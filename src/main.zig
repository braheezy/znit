const std = @import("std");
const builtin = @import("builtin");
const native_os = builtin.os.tag;
const SIG = std.posix.SIG;

const znit_version = "0.1.0";

var debug_allocator: std.heap.DebugAllocator(.{}) = .init;

var parent_death_signal: u6 = 0;
var kill_process_group: bool = false;
var warn_on_reap: bool = false;
var subreaper: bool = false;
const ts = std.posix.timespec{ .sec = 1, .nsec = 0 };
const STATUS_MAX = 255;
const STATUS_MIN = 0;
var expect_status = [_]u32{0} ** ((STATUS_MAX - STATUS_MIN + 1) / 32);
const signals = std.StaticStringMap(u6).initComptime(.{
    .{ "SIGHUP", std.posix.SIG.HUP },
    .{ "SIGINT", std.posix.SIG.INT },
    .{ "SIGQUIT", std.posix.SIG.QUIT },
    .{ "SIGILL", std.posix.SIG.ILL },
    .{ "SIGTRAP", std.posix.SIG.TRAP },
    .{ "SIGABRT", std.posix.SIG.ABRT },
    .{ "SIGBUS", std.posix.SIG.BUS },
    .{ "SIGFPE", std.posix.SIG.FPE },
    .{ "SIGKILL", std.posix.SIG.KILL },
    .{ "SIGUSR1", std.posix.SIG.USR1 },
    .{ "SIGSEGV", std.posix.SIG.SEGV },
    .{ "SIGUSR2", std.posix.SIG.USR2 },
    .{ "SIGPIPE", std.posix.SIG.PIPE },
    .{ "SIGALRM", std.posix.SIG.ALRM },
    .{ "SIGTERM", std.posix.SIG.TERM },
    .{ "SIGCHLD", std.posix.SIG.CHLD },
    .{ "SIGCONT", std.posix.SIG.CONT },
    .{ "SIGSTOP", std.posix.SIG.STOP },
    .{ "SIGTSTP", std.posix.SIG.TSTP },
    .{ "SIGTTIN", std.posix.SIG.TTIN },
    .{ "SIGTTOU", std.posix.SIG.TTOU },
    .{ "SIGURG", std.posix.SIG.URG },
    .{ "SIGXCPU", std.posix.SIG.XCPU },
    .{ "SIGXFSZ", std.posix.SIG.XFSZ },
    .{ "SIGVTALRM", std.posix.SIG.VTALRM },
    .{ "SIGPROF", std.posix.SIG.PROF },
    .{ "SIGWINCH", std.posix.SIG.WINCH },
    .{ "SIGSYS", std.posix.SIG.SYS },
});

const SignalConfiguration = struct {
    sig_mask: *std.posix.sigset_t,
    sig_ttin_action: *std.posix.Sigaction,
    sig_ttou_action: *std.posix.Sigaction,
};

pub fn main() void {
    var child_pid: std.posix.pid_t = 0;

    // These are passed to function to get an exit code back.
    var child_exitcode: ?u32 = null; // This isn't a valid exit code, and lets us tell whether the child has exited.

    // Memory allocation setup
    const gpa, const is_debug = gpa: {
        if (native_os == .wasi) break :gpa .{ std.heap.wasm_allocator, false };
        break :gpa switch (builtin.mode) {
            .Debug, .ReleaseSafe => .{ debug_allocator.allocator(), true },
            .ReleaseFast, .ReleaseSmall => .{ std.heap.smp_allocator, false },
        };
    };
    defer if (is_debug) {
        if (debug_allocator.deinit() == .leak) {
            std.log.err("Memory leak detected", .{});
            std.process.exit(1);
        }
    };

    // Read arguments
    const args = std.process.argsAlloc(gpa) catch |err| {
        std.log.err("Failed to allocate memory for arguments: {s}", .{@errorName(err)});
        std.process.exit(1);
    };
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

    configureSignals(&parent_sigset, &child_sigconf) catch |err| {
        std.log.err("Failed to configure signals: {s}", .{@errorName(err)});
        std.process.exit(1);
    };

    // Trigger signal on this process when the parent process exits.
    if (parent_death_signal != 0) {
        _ = std.posix.prctl(std.posix.PR.SET_PDEATHSIG, .{parent_death_signal}) catch |err| {
            std.log.err("Failed to set up parent death signal: {any}", .{err});
            std.process.exit(1);
        };
    }

    if (subreaper) {
        registerSubreaper() catch {
            std.process.exit(1);
        };
    }

    // Are we going to reap zombies properly? If not, warn.
    checkReaper() catch |err| {
        std.log.err("Failed to check reaper: {s}", .{@errorName(err)});
        std.process.exit(1);
    };

    const ret_code = spawn(&child_sigconf, child_args, &child_pid);
    if (ret_code != 0) std.process.exit(ret_code);

    while (true) {
        std.log.debug("=== MAIN LOOP ITERATION ===", .{});
        // Wait for one signal, and forward it
        waitAndForwardSignal(&parent_sigset, child_pid) catch std.process.exit(1);

        // reap them zombies
        child_exitcode = reapZombies(child_pid) catch std.process.exit(1);
        std.log.debug("=== MAIN LOOP: child_exitcode after reapZombies = {?d} ===", .{child_exitcode});

        if (child_exitcode != null) {
            std.log.info("Exiting: child has exited", .{});
            std.process.exit(@intCast(child_exitcode.?));
        }
    }
}

fn parseArgs(args: [][:0]u8) ![][:0]u8 {
    const program_name = args[0];

    // Find where the actual command arguments start
    // Docker ENTRYPOINT may insert '--' as arg[1], so we need to handle:
    // Case 1: [program] [--version]                    -> args.len == 2
    // Case 2: [program] [--] [program] [--version]     -> args.len == 4, check args[3]
    // Case 3: [program] [--] [command] [args...]       -> normal execution
    // Case 4: [program] [-h]                           -> args.len == 2
    // Case 5: [program] [--] [program] [-h]            -> args.len == 4, check args[3]

    var start_idx: usize = 1;
    var has_separator = false;

    // Check if we have -- as the first argument (Docker ENTRYPOINT case)
    if (args.len > 1 and std.mem.eql(u8, args[1], "--")) {
        has_separator = true;
        start_idx = 2;
    }

    // Handle --version flag
    if ((args.len == 2 and std.mem.eql(u8, args[1], "--version")) or
        (args.len == 4 and has_separator and std.mem.eql(u8, args[3], "--version")))
    {
        std.debug.print("{s}\n", .{znit_version});
        return error.Version;
    }

    // Handle -h flag
    if ((args.len == 2 and std.mem.eql(u8, args[1], "-h")) or
        (args.len == 4 and has_separator and std.mem.eql(u8, args[3], "-h")))
    {
        try printUsage(program_name, std.io.getStdErr().writer());
        return error.Usage;
    }

    // Check for other flags in any position
    for (args[start_idx..]) |arg| {
        if (std.mem.eql(u8, arg, "-h")) {
            try printUsage(program_name, std.io.getStdErr().writer());
            return error.Usage;
        } else if (std.mem.eql(u8, arg, "-e")) {
            addExpectStatus(arg) catch {
                std.log.err("Not a valid option for -e: {s}", .{arg});
                return error.InvalidOption;
            };
        } else if (std.mem.eql(u8, arg, "-p")) {
            setPDeathSig(arg) catch {
                std.log.err("Not a valid option for -p: {s}", .{arg});
                return error.InvalidOption;
            };
        } else if (std.mem.eql(u8, arg, "-g")) {
            kill_process_group = true;
        } else if (std.mem.eql(u8, arg, "-w")) {
            warn_on_reap = true;
        } else if (std.mem.eql(u8, arg, "-s")) {
            subreaper = true;
        }
    }

    // If we only have the program name (and optionally --), show usage
    if (args.len <= start_idx) {
        try printUsage(program_name, std.io.getStdErr().writer());
        return error.Usage;
    }

    return args[start_idx..];
}

fn addExpectStatus(arg: []const u8) !void {
    const status = try std.fmt.parseInt(u8, arg, 10);

    if (status < STATUS_MIN or status > STATUS_MAX) {
        return error.InvalidStatus;
    }

    checkBitfieldBounds(&expect_status, status);
    int32BitfieldSet(&expect_status, status);
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
        \\  -e EXIT_CODE: Remap EXIT_CODE (from 0 to 255) to 0 (can be repeated).
        \\  -p SIGNAL: Trigger SIGNAL when parent dies, e.g. "-p SIGKILL".
        \\  -g: Kill the process group instead of the process.
        \\  -w: Print a warning when processes are getting reaped.
        \\  -s: Register as a process subreaper (requires Linux >= 3.4).
        \\
    , .{ basename, basename });
}

fn setPDeathSig(arg: []const u8) !void {
    if (signals.get(arg)) |signal| {
        parent_death_signal = signal;
        return;
    }
    return error.InvalidSignal;
}

fn configureSignals(parent_sigset: *std.posix.sigset_t, sigconf: *SignalConfiguration) !void {
    // block all signals that are meant to be collected by the main loop
    parent_sigset.* = sigfillset();

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
    var ignore_action = std.posix.Sigaction{
        .handler = .{ .handler = SIG.IGN },
        .mask = std.posix.empty_sigset,
        .flags = 0,
    };

    std.posix.sigaction(SIG.TTIN, &ignore_action, sigconf.sig_ttin_action);
    std.posix.sigaction(SIG.TTOU, &ignore_action, sigconf.sig_ttou_action);
}

fn checkReaper() !void {
    if (std.os.linux.getpid() == 1) return;

    if (subreaper) {
        const bit = std.posix.prctl(std.posix.PR.GET_CHILD_SUBREAPER, .{1}) catch |err| {
            std.log.err("Failed to read child subreaper attribute: {s}", .{@errorName(err)});
            return err;
        };
        if (bit == 1) return;
    }

    std.log.warn(
        \\znit is not running as PID 1{s}. Zombie processes will not be re-parented to znit, so zombie reaping won't work.
        \\To fix the problem,{s} run znit as PID 1.
    , .{
        if (subreaper) " and isn't registered as a child subreaper" else "",
        if (subreaper) "use the -s option or " else "",
    });
}

fn registerSubreaper() !void {
    if (subreaper) {
        _ = std.posix.prctl(std.posix.PR.SET_CHILD_SUBREAPER, .{1}) catch |err| {
            std.log.err("Failed to register as child subreaper: {s}", .{@errorName(err)});
            return err;
        };
        std.log.debug("Registered as child subreaper", .{});
    }
}

fn spawn(sigconf: *SignalConfiguration, child_args: [][:0]u8, child_pid: *std.posix.pid_t) u8 {
    const pid = std.posix.fork() catch |err| {
        std.log.err("fork failed: {s}", .{@errorName(err)});
        return 1;
    };

    if (pid == 0) {
        // Put the child in a process group and make it the foreground process if there is a tty.
        isolateChild() catch return 1;

        // Restore all signal handlers to the way they were before we touched them.
        restoreSignals(sigconf) catch return 1;

        var env = [_:null]?[*:0]u8{};
        var args = [_:null]?[*:0]const u8{ "echo", "machin", "test" };

        // Use execvpeZ to search PATH - this function returns noreturn on success, error on failure
        std.debug.print("execvpeZ: {s}\n", .{
            child_args,
        });
        const exec_err = std.posix.execvpeZ(child_args[0], args[0..args.len], env[0..env.len]);

        std.log.err("execvpeZ failed: {s}", .{@errorName(exec_err)});
        const status: u8 = switch (exec_err) {
            error.AccessDenied => 126,
            error.FileNotFound => 127,
            else => 1,
        };
        std.process.exit(status);
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
    const pgrp = getpgrp() catch |err| {
        std.log.err("getpgrp failed: {s}", .{@errorName(err)});
        return err;
    };
    std.posix.tcsetpgrp(std.posix.STDIN_FILENO, pgrp) catch |err| {
        if (err == error.NotATerminal) {
            std.log.debug("tcsetpgrp failed: no tty (ok to proceed)", .{});
        } else {
            std.log.err("tcsetpgrp failed: {s}", .{@errorName(err)});
            return err;
        }
    };
}

fn restoreSignals(sigconf: *SignalConfiguration) !void {
    std.posix.sigprocmask(SIG.SETMASK, sigconf.sig_mask, null);

    std.posix.sigaction(SIG.TTIN, sigconf.sig_ttin_action, null);

    std.posix.sigaction(SIG.TTOU, sigconf.sig_ttou_action, null);
}

fn waitAndForwardSignal(parent_sigset: *std.posix.sigset_t, child_pid: std.posix.pid_t) !void {
    var sig: std.os.linux.siginfo_t = undefined;
    try sigtimedwait(parent_sigset, &sig, ts);

    // There is a signal to handle here
    switch (sig.signo) {
        SIG.CHLD => {
            // Special-cased, as we don't forward SIGCHLD. Instead, we'll
            // fallthrough to reaping processes.
            std.log.debug("Received SIGCHLD", .{});
            return;
        },
        else => {
            std.log.debug("Passing signal: '{d}'", .{sig.signo});
            // Forward anything else
            std.posix.kill(if (kill_process_group) -child_pid else child_pid, @intCast(sig.signo)) catch |err| {
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
    // Linux kernel expects sigsetsize to be 8 (64 bits / 8 bits per byte)
    // This is the size of the kernel's sigset_t, not necessarily the libc one
    const sigsetsize = 8;

    switch (std.posix.errno(std.os.linux.syscall4(
        std.os.linux.SYS.rt_sigtimedwait,
        @intFromPtr(set),
        @intFromPtr(info),
        @intFromPtr(&timeout),
        sigsetsize,
    ))) {
        .SUCCESS => return,
        .AGAIN, .INTR => return, // Timeout or interrupted
        .INVAL => {
            std.log.err("sigtimedwait: Invalid argument (signal set size={}, timeout={}.{} sec)", .{ sigsetsize, timeout.sec, timeout.nsec });
            return error.InvalidArgument;
        },
        else => |err| {
            std.log.err("sigtimedwait failed with errno: {d}", .{@intFromEnum(err)});
            return std.posix.unexpectedErrno(err);
        },
    }
}

// ?TODO: Upstream to zig std lib
// Get the process group ID of the calling process
fn getpgrp() !std.posix.pid_t {
    const result = std.os.linux.syscall1(std.os.linux.SYS.getpgid, 0);
    switch (std.posix.errno(result)) {
        .SUCCESS => return @intCast(result),
        else => |err| {
            std.log.err("getpgrp failed with errno: {d}", .{@intFromEnum(err)});
            return std.posix.unexpectedErrno(err);
        },
    }
}

// Safe wrapper around waitpid that handles ECHILD properly
fn safe_waitpid(wpid: std.posix.pid_t, options: u32) ?std.posix.WaitPidResult {
    std.log.debug("safe_waitpid: Called with wpid={d}, options={d}", .{ wpid, options });

    // Manual waitpid implementation that handles ECHILD by returning null
    var status: if (builtin.link_libc) c_int else u32 = undefined;
    while (true) {
        const rc = std.posix.system.waitpid(wpid, &status, @intCast(options));
        switch (std.posix.errno(rc)) {
            .SUCCESS => {
                std.log.debug("safe_waitpid: SUCCESS, pid={d}, status={d}", .{ rc, status });
                return .{
                    .pid = @intCast(rc),
                    .status = @bitCast(status),
                };
            },
            .INTR => {
                std.log.debug("safe_waitpid: EINTR, continuing", .{});
                continue;
            },
            .CHILD => {
                std.log.debug("safe_waitpid: ECHILD, no children to wait for", .{});
                return null;
            },
            .INVAL => unreachable, // Invalid flags.
            else => |err| {
                std.log.err("safe_waitpid: Unexpected error: {d}", .{@intFromEnum(err)});
                return null;
            },
        }
    }
}

fn reapZombies(child_pid: std.posix.pid_t) !?u32 {
    std.log.debug("reapZombies: Starting zombie reaping for child_pid={d}", .{child_pid});
    var exitcode: ?u32 = null;
    while (true) {
        std.log.debug("reapZombies: Calling safe_waitpid", .{});
        // Use our safe waitpid wrapper
        const result = safe_waitpid(-1, std.os.linux.W.NOHANG) orelse {
            std.log.debug("No more children to reap", .{});
            break;
        };

        std.log.debug("reapZombies: safe_waitpid returned, extracting pid and status", .{});
        const current_pid = result.pid;
        const status = result.status;
        std.log.debug("reapZombies: current_pid={d}, status={d}", .{ current_pid, status });

        switch (current_pid) {
            0 => {
                std.log.debug("No child to reap", .{});
                break;
            },
            else => {
                // A child was reaped. Check whether it's the main one. If it is, then
                // set the exit_code, which will cause us to exit once we've reaped everyone else.
                std.log.debug("Reaped child with pid: '{d}'", .{current_pid});
                if (current_pid == child_pid) {
                    std.log.debug("reapZombies: This is the main child, checking exit status", .{});
                    if (std.os.linux.W.IFEXITED(status)) {
                        // Our process exited normally.
                        std.log.info("Main child exited normally (with status '{d}')", .{std.os.linux.W.EXITSTATUS(status)});
                        exitcode = std.os.linux.W.EXITSTATUS(status);
                    } else if (std.os.linux.W.IFSIGNALED(status)) {
                        // Our process was terminated. Emulate what sh / bash
                        // would do, which is to return 128 + signal number.
                        std.log.info("Main child exited with signal (with signal '{d}')", .{std.os.linux.W.TERMSIG(status)});
                        exitcode = 128 + std.os.linux.W.TERMSIG(status);
                    } else {
                        std.log.err("Main child exited for unknown reason", .{});
                        return error.UnknownExitStatus;
                    }

                    // Be safe, ensure the status code is indeed between 0 and 255.
                    exitcode = exitcode.? % (STATUS_MAX - STATUS_MIN + 1);

                    // If this exitcode was remapped, then set it to 0.
                    checkBitfieldBounds(&expect_status, exitcode.?);
                    if (int32BitfieldTest(&expect_status, exitcode.?)) {
                        exitcode = 0;
                    }
                } else if (warn_on_reap) {
                    std.log.warn("Reaped zombie process with pid={d}", .{current_pid});
                }

                // Check if other childs have been reaped.
                continue;
            },
        }
    }
    std.log.debug("reapZombies: Finished, returning exitcode={?d}", .{exitcode});
    return exitcode;
}

fn int32BitfieldTest(F: []const u32, i: usize) bool {
    return (F[i / 32] & (@as(u32, @intCast(1)) << @intCast(i % 32))) != 0;
}

inline fn checkBitfieldBounds(F: []u32, i: isize) void {
    std.debug.assert(i >= 0);
    const idx = @as(usize, @intCast(i)) / 32;
    std.debug.assert(idx < F.len);
}
/// Set bit `i` in a 32-bit–chunked bitfield `F`
inline fn int32BitfieldSet(F: []u32, i: usize) void {
    // chunk index = i / 32  (use >> 5)
    // bit mask    = 1 << (i % 32)  (use & 31)
    F[i >> 5] |= @as(u32, @intCast(1)) << @intCast(i & 31);
}

const SigsetElement = u32;
const sigset_len = @typeInfo(std.os.linux.sigset_t).array.len;
pub fn sigfillset() std.os.linux.sigset_t {
    return [_]SigsetElement{~@as(SigsetElement, 0)} ** sigset_len;
}
