const std = @import("std");
const builtin = @import("builtin");
const native_os = builtin.os.tag;
const SIG = std.posix.SIG;

const znit_version = "0.1.0";

var debug_allocator: std.heap.DebugAllocator(.{}) = .init;

var parent_death_signal: u6 = 0;

const SignalConfiguration = struct {
    sig_mask: *std.posix.sigset_t,
    sig_ttin_action: *std.posix.Sigaction,
    sig_ttou_action: *std.posix.Sigaction,
};

pub fn main() !void {
    // const child_pid: std.posix.pid_t = 0;

    // // These are passed to function to get an exit code back.
    // var child_exitcode: i32 = -1; // This isn't a valid exit code, and lets us tell whether the child has exited.

    // Memory allocation setup
    const gpa, const is_debug = gpa: {
        if (native_os == .wasi) break :gpa .{ std.heap.wasm_allocator, false };
        break :gpa switch (builtin.mode) {
            .Debug, .ReleaseSafe => .{ debug_allocator.allocator(), true },
            .ReleaseFast, .ReleaseSmall => .{ std.heap.smp_allocator, false },
        };
    };
    defer if (is_debug) {
        _ = debug_allocator.deinit();
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
        return err;
    };

    std.debug.print("child_args: {s}\n", .{child_args});

    // TODO: Configure signals
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
        try std.posix.prctl(std.posix.PR.SET_PDEATHSIG, parent_death_signal);
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
