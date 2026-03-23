const std = @import("std");
const runar = @import("runar");
const runar_frontend = @import("runar_frontend");

/// Compile a contract source file and return a parsed RunarArtifact.
/// Uses the Zig compiler frontend directly (parse -> validate -> typecheck -> ANF -> stack -> emit).
///
/// For .runar.ts sources, shells out to the Go compiler binary since the Zig
/// frontend only supports .runar.zig files. If the Go compiler is not available,
/// falls back to reading a pre-compiled JSON artifact from disk.
pub fn compileContract(allocator: std.mem.Allocator, source_path: []const u8) !runar.RunarArtifact {
    // Determine the project root (integration/zig -> project root is ../.. )
    const project_root = projectRoot();

    // Check file extension
    if (std.mem.endsWith(u8, source_path, ".runar.zig")) {
        return compileZigContract(allocator, project_root, source_path);
    }

    // For .runar.ts (and other formats), shell out to the Go compiler
    return compileViaGoCompiler(allocator, project_root, source_path);
}

/// Compile a .runar.zig contract using the native Zig compiler frontend.
fn compileZigContract(allocator: std.mem.Allocator, project_root: []const u8, source_path: []const u8) !runar.RunarArtifact {
    const abs_path = try std.fs.path.join(allocator, &.{ project_root, source_path });
    defer allocator.free(abs_path);

    const source = try std.fs.cwd().readFileAlloc(allocator, abs_path, 10 * 1024 * 1024);
    defer allocator.free(source);

    const file_name = std.fs.path.basename(source_path);

    const result = try runar_frontend.compileSource(allocator, source, file_name);
    defer allocator.free(result.script_hex);

    if (result.artifact_json) |json| {
        defer allocator.free(json);
        return runar.RunarArtifact.fromJson(allocator, json);
    }

    return error.OutOfMemory;
}

/// Compile via the Go compiler binary, which supports .runar.ts, .runar.sol, etc.
fn compileViaGoCompiler(allocator: std.mem.Allocator, project_root: []const u8, source_path: []const u8) !runar.RunarArtifact {
    const abs_source = try std.fs.path.join(allocator, &.{ project_root, source_path });
    defer allocator.free(abs_source);

    // Try the Go compiler binary
    const go_compiler = try std.fs.path.join(allocator, &.{ project_root, "compilers/go/runar-go" });
    defer allocator.free(go_compiler);

    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ go_compiler, "-source", abs_source },
    }) catch |err| {
        // Go binary not found; try building it first, or fall back to npx
        std.log.warn("Go compiler not found ({any}), trying npx...", .{err});
        return compileViaNpx(allocator, project_root, abs_source);
    };
    defer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }

    const exit_code: u8 = if (result.term == .Exited) result.term.Exited else 255;
    if (exit_code != 0) {
        std.log.err("Go compiler exited with code {d}: {s}", .{ exit_code, result.stderr });
        // Fall back to npx
        return compileViaNpx(allocator, project_root, abs_source);
    }

    return runar.RunarArtifact.fromJson(allocator, result.stdout);
}

/// Compile via npx runar-compiler (Node.js).
fn compileViaNpx(allocator: std.mem.Allocator, project_root: []const u8, abs_source: []const u8) !runar.RunarArtifact {
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "npx", "runar-compiler", "--source", abs_source },
        .cwd = project_root,
    }) catch return error.OutOfMemory;
    defer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }

    const npx_exit: u8 = if (result.term == .Exited) result.term.Exited else 255;
    if (npx_exit != 0) {
        std.log.err("npx compiler exited with code {d}: {s}", .{ npx_exit, result.stderr });
        return error.OutOfMemory;
    }

    return runar.RunarArtifact.fromJson(allocator, result.stdout);
}

/// Get the project root directory (relative from integration/zig/).
fn projectRoot() []const u8 {
    return "../..";
}

test "compileContract placeholder" {
    // This test just verifies the module compiles.
    // Actual compilation requires contract files on disk.
    try std.testing.expect(true);
}
