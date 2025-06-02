const std = @import("std");
const builtin = @import("builtin");
const native_os = builtin.os.tag;
const SIG = std.posix.SIG;

const znit_version = "0.1.0";

var debug_allocator: std.heap.DebugAllocator(.{}) = .init;

var parent_death_signal: u6 = 0;
var kill_process_group: u6 = 0;
const ts = std.posix.timespec{ .sec = 1, .nsec = 0 };
const STATUS_MAX = 255;
const STATUS_MIN = 0;

const SignalConfiguration = struct {
    sig_mask: *std.posix.sigset_t,
    sig_ttin_action: *std.posix.Sigaction,
    sig_ttou_action: *std.posix.Sigaction,
};

pub fn main() void {
    const child_pid: std.posix.pid_t = 0;

    // These are passed to function to get an exit code back.
    const child_exitcode: i32 = -1; // This isn't a valid exit code, and lets us tell whether the child has exited.

    // Memory allocation setup
    const gpa, const is_debug = gpa: {
        if (native_os == .wasi) break :gpa .{ std.heap.wasm_allocator, false };
        break :gpa switch (builtin.mode) {
            .Debug, .ReleaseSafe => .{ debug_allocator.allocator(), true },
            .ReleaseFast, .ReleaseSmall => .{ std.heap.smp_allocator, false },
        };
    };
    defer if (is_debug) {
        if (gpa.deinit() == .leak) {
            std.log.err("Memory leak detected", .{});
            std.process.exit(1);
        }
    };

    // Read arguments
    const args = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, args);

    const child_args = parseArgs(args) catch |err| {
        if (err == error.Version) {
            std.process.exit(0);
        } else if (err == error.Usage) {
            std.process.exit(0);
        }
        std.log.err("Error parsing arguments: {s}", .{@errorName(err)});
        std.process.exit(1);
    };

    var parent_sigset: std.posix.sigset_t = undefined;
    var child_sigset: std.posix.sigset_t = undefined;
    var sig_ttin_action = std.posix.Sigaction{
        .handler = .{ .handler = SIG.IGN },
        .mask = std.posix.empty_sigset,
        .flags = 0,
    };
    var sig_ttout_action = std.posix.Sigaction{
        .handler = .{ .handler = SIG.IGN },
        .mask = std.posix.empty_sigset,
        .flags = 0,
    };

    var child_sigconf = SignalConfiguration{
        .sig_mask = &child_sigset,
        .sig_ttin_action = &sig_ttin_action,
        .sig_ttou_action = &sig_ttout_action,
    };

    try configureSignals(&parent_sigset, &child_sigconf);

    // Trigger signal on this process when the parent process exits.
    if (parent_death_signal != 0) {
        std.posix.prctl(std.posix.PR.SET_PDEATHSIG, parent_death_signal) catch |err| {
            std.log.err("Failed to set up parent death signal: {s}", .{@errorName(err)});
            std.process.exit(1);
        };
    }

    // Are we going to reap zombies properly? If not, warn.
    checkReaper();

    const ret_code = spawn(&child_sigconf, child_args, child_pid);
    if (ret_code != 0) std.process.exit(ret_code);

    while (true) {
        // Wait for one signal, and forward it
        waitAndForwardSignal(&parent_sigset, child_pid) catch return 1;

        // reap them zombies
        reapZombies(child_pid, &child_exitcode) catch return 1;

        if (child_exitcode != -1) {
            std.log.info("Exiting: child has exited", .{});
            return child_exitcode;
        }
    }
}

fn parseArgs(args: [][:0]u8) ![][:0]u8 {
    const program_name = args[0];

    // We handle --version if it's the *only* argument provided.
    if (args.len == 2 and std.mem.eql(u8, args[1], "--version")) {
        std.debug.print("{s}\n", .{znit_version});
        return error.Version;
    }

    for (args) |arg| {
        if (std.mem.eql(u8, arg, "-h")) {
            try printUsage(program_name, std.io.getStdErr().writer());
            return error.Usage;
        }
    }

    if (args.len == 1) {
        // user forgot to provide args
        try printUsage(program_name, std.io.getStdErr().writer());
        return error.Usage;
    }

    return args[1..];
}

fn printUsage(program_name: []const u8, writer: anytype) !void {
    const basename = std.fs.path.basename(program_name);

    try writer.print("{s} ({s})\n", .{ basename, znit_version });
    try writer.print(
        \\Usage: {s} PROGRAM [ARGS] | --version
        \\
        \\Execute a program under the supervision of a valid init process ({s})
        \\
        \\Command line options:
        \\
        \\  --version: Show version and exit.
        \\  -h: Show this help message and exit.
        \\
    , .{ basename, basename });
}

fn configureSignals(parent_sigset: *std.posix.sigset_t, sigconf: *SignalConfiguration) !void {
    // block all signals that are meant to be collected by the main loop
    std.c.sigfillset(parent_sigset);

    // these shouldn't be collected by the main loop
    const signals_for_znit = [_]u6{
        SIG.FPE,
        SIG.ILL,
        SIG.SEGV,
        SIG.BUS,
        SIG.ABRT,
        SIG.TRAP,
        SIG.SYS,
        SIG.TTIN,
        SIG.TTOU,
    };
    for (signals_for_znit) |signal| {
        std.os.linux.sigdelset(parent_sigset, signal);
    }

    std.posix.sigprocmask(SIG.SETMASK, parent_sigset, sigconf.sig_mask);

    // Handle SIGTTIN and SIGTTOU separately. Since znit makes the child process group
    // the foreground process group, there's a chance znit can end up not controlling the tty.
    // If TOSTOP is set on the tty, this could block znit on writing debug messages. We don't
    // want that. Ignore those signals.
    var ignore_action = std.posix.Sigaction{};
    ignore_action.handler.handler = SIG.IGN;
    ignore_action.mask = std.posix.empty_sigset;

    std.posix.sigaction(SIG.TTIN, &ignore_action, sigconf.sig_ttin_action);
    std.posix.sigaction(SIG.TTOU, &ignore_action, sigconf.sig_ttou_action);
}

fn checkReaper() !void {
    if (std.os.linux.getpid() == 1) return;

    std.log.warn("znit is not running as PID 1. Zombie processes will not be re-parented to znit, so zombie reaping won't work. To fix the problem, run znit as PID 1.", .{});
}

fn spawn(sigconf: *SignalConfiguration, child_args: [][]u8, child_pid: *std.posix.pid_t) !i32 {
    const pid = std.posix.fork() catch |err| {
        std.log.err("fork failed: {s}", .{@errorName(err)});
        return 1;
    };

    if (pid == 0) {
        // Put the child in a process group and make it the foreground process if there is a tty.
        isolateChild() catch return 1;

        // Restore all signal handlers to the way they were before we touched them.
        restoreSignals(sigconf) catch return 1;

        std.posix.execvpeZ(child_args[0], child_args, null) catch |err| {
            std.log.err("exec {s} failed: {s}", .{ child_args[0], @errorName(err) });
            const status = switch (err) {
                error.AccessDenied => 126,
                error.FileNotFound => 127,
                else => 1,
            };
            return status;
        };
    } else {
        // parent
        std.log.info("Spawned child process '{s}' with pid '{d}'", .{ child_args[0], pid });
        child_pid.* = pid;
        return 0;
    }
}

fn isolateChild() !void {
    // Put the child into a new process group.
    std.posix.setpgid(0, 0) catch |err| {
        std.log.err("setpgid failed: {s}", .{@errorName(err)});
        return error.SetpgidFailed;
    };

    // If there is a tty, allocate it to this new process group. We
    // can do this in the child process because we're blocking
    // SIGTTIN / SIGTTOU.

    // Doing it in the child process avoids a race condition scenario
    // if znit is calling znit (in which case the grandparent may make the
    // parent the foreground process group, and the actual child ends up...
    // in the background!)
    std.posix.tcsetpgrp(std.posix.STDIN_FILENO, std.posix.tcgetpgrp()) catch |err| {
        if (err == error.NotATerminal) {
            std.log.debug("tcsetpgrp failed: no tty (ok to proceed)", .{});
        } else {
            std.log.err("tcsetpgrp failed: {s}", .{@errorName(err)});
            return error.TcsetpgrpFailed;
        }
    };
}

fn restoreSignals(sigconf: *SignalConfiguration) !void {
    std.posix.sigprocmask(SIG.SETMASK, sigconf.sig_mask, null) catch |err| {
        std.log.err("Restoring child signal mask failed: '{s}'", .{@errorName(err)});
        return error.RestoreSignalsFailed;
    };

    std.posix.sigaction(SIG.TTIN, sigconf.sig_ttin_action, null) catch |err| {
        std.log.err("Restoring SIGTTIN handler failed: '{s}'", .{@errorName(err)});
        return error.RestoreSignalsFailed;
    };

    std.posix.sigaction(SIG.TTOU, sigconf.sig_ttou_action, null) catch |err| {
        std.log.err("Restoring SIGTTOU handler failed: '{s}'", .{@errorName(err)});
        return error.RestoreSignalsFailed;
    };
}

fn waitAndForwardSignal(parent_sigset: *std.posix.sigset_t, child_pid: std.posix.pid_t) !void {
    var sig: std.os.linux.siginfo_t = .{};
    sigtimedwait(parent_sigset, &sig, ts) catch return 1;

    // There is a signal to handle here
    switch (sig.signo) {
        SIG.CHLD => {
            // Special-cased, as we don't forward SIGCHLD. Instead, we'll
            // fallthrough to reaping processes.
            std.log.debug("Received SIGCHLD", .{});
            return;
        },
        else => {
            std.log.debug("Passing signal: '{s}'", .{@tagName(sig.signo)});
            // Forward anything else
            std.posix.kill(if (kill_process_group != 0) -child_pid else child_pid, sig.signo) catch |err| {
                if (err == error.ProcessNotFound) {
                    std.log.warn("Child was dead when forwarding signal", .{});
                } else {
                    std.log.err("Unexpected error when forwarding signal: '{s}'", .{@errorName(err)});
                    return err;
                }
            };
        },
    }
}

// ?TODO: Upstream to zig std lib
fn sigtimedwait(set: *std.os.linux.sigset_t, info: *std.os.linux.siginfo_t, timeout: std.posix.timespec) !void {
    switch (std.posix.errno(std.os.linux.syscall3(
        std.os.linux.SYS.rt_sigtimedwait,
        @intFromPtr(set),
        @intFromPtr(info),
        @intFromPtr(timeout),
    ))) {
        .SUCCESS => return,
        .AGAIN, .INTR => return,
        else => |err| return std.posix.unexpectedErrno(err),
    }
}

fn reapZombies(child_pid: std.posix.pid_t, exitcode: *i32) !void {
    while (true) {
        const pid_result = std.posix.waitpid(-1, std.os.linux.W.NOHANG);
        const current_pid = pid_result.pid;
        const current_status = pid_result.status;

        switch (current_pid) {
            0 => {
                std.log.debug("No child to reap", .{});
            },
            else => {
                // A child was reaped. Check whether it's the main one. If it is, then
                // set the exit_code, which will cause us to exit once we've reaped everyone else.
                std.log.debug("Reaped child with pid: '{d}'", .{current_pid});
                if (current_pid == child_pid) {
                    if (std.os.linux.W.IFEXITED(current_status)) {
                        // Our process exited normally.
                        std.log.info("Main child exited normally (with status '{d}')", .{std.os.linux.W.EXITSTATUS(current_status)});
                        exitcode.* = std.os.linux.W.EXITSTATUS(current_status);
                    } else if (std.os.linux.W.IFSIGNALED(current_status)) {
                        // Our process was terminated. Emulate what sh / bash
                        // would do, which is to return 128 + signal number.
                        std.log.info("Main child exited with signal (with signal '{s}')", .{@tagName(std.os.linux.W.TERMSIG(current_status))});
                        exitcode.* = 128 + std.os.linux.W.TERMSIG(current_status);
                    } else {
                        std.log.err("Main child exited for unknown reason", .{});
                        return error.UnknownExitStatus;
                    }

                    // Be safe, ensure the status code is indeed between 0 and 255.
                    exitcode.* = exitcode.* % (STATUS_MAX - STATUS_MIN + 1);
                }

                continue;
            },
        }

        break;
    }
}

fn int32BitfieldCheckBounds(F: []const u32, i: usize) void {
    // i is unsigned (>= 0), so only need to check i/32 < F.len
    std.debug.assert(F.len > i / 32);
}

fn int32BitfieldTest(F: []const u32, i: usize) bool {
    return (F[i / 32] & (u32(1) << (i % 32))) != 0;
}
