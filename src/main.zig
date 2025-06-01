const std = @import("std");
const builtin = @import("builtin");
const native_os = builtin.os.tag;

const znit_version = "0.1.0";

var debug_allocator: std.heap.DebugAllocator(.{}) = .init;

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

    const child_args = parse_args(args) catch |err| {
        if (err == error.Version) {
            std.process.exit(0);
        } else if (err == error.Usage) {
            std.process.exit(0);
        }
        return err;
    };

    std.debug.print("child_args: {s}\n", .{child_args});

    // TODO: Configure signals
}

fn parse_args(args: [][:0]u8) ![][:0]u8 {
    const program_name = args[0];

    // We handle --version if it's the *only* argument provided.
    if (args.len == 2 and std.mem.eql(u8, args[1], "--version")) {
        std.debug.print("{s}\n", .{znit_version});
        return error.Version;
    }

    for (args) |arg| {
        if (std.mem.eql(u8, arg, "-h")) {
            try print_usage(program_name, std.io.getStdErr().writer());
            return error.Usage;
        }
    }

    if (args.len == 1) {
        // user forgot to provide args
        try print_usage(program_name, std.io.getStdErr().writer());
        return error.Usage;
    }

    return args[1..];
}

fn print_usage(program_name: []const u8, writer: anytype) !void {
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
