const std = @import("std");
const types = @import("ir/types.zig");
const json_parser = @import("ir/json.zig");
const stack_lower = @import("passes/stack_lower.zig");
const peephole = @import("passes/peephole.zig");
const emit = @import("codegen/emit.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        printUsage();
        std.process.exit(1);
    }

    const command = args[1];

    if (std.mem.eql(u8, command, "compile-ir")) {
        if (args.len < 3) {
            std.debug.print("Usage: runar-zig compile-ir <anf-ir.json>\n", .{});
            std.process.exit(1);
        }
        compileFromIR(allocator, args[2]) catch |err| {
            std.debug.print("error: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
    } else if (std.mem.eql(u8, command, "compile")) {
        if (args.len < 3) {
            std.debug.print("Usage: runar-zig compile <source-file>\n", .{});
            std.process.exit(1);
        }
        compileFromSource(allocator, args[2]) catch |err| {
            std.debug.print("error: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
    } else if (std.mem.eql(u8, command, "--help") or std.mem.eql(u8, command, "-h")) {
        printUsage();
    } else {
        std.debug.print("Unknown command: {s}\n", .{command});
        printUsage();
        std.process.exit(1);
    }
}

fn printUsage() void {
    std.debug.print(
        \\Usage: runar-zig <command> [options]
        \\
        \\Commands:
        \\  compile <file>       Full pipeline: source -> Bitcoin Script artifact
        \\  compile-ir <file>    IR consumer: ANF IR JSON -> Bitcoin Script
        \\  --help, -h           Show this help
        \\
        \\Supported formats:
        \\  .runar.zig    Zig contracts
        \\  .runar.ts     TypeScript contracts
        \\  .json         ANF IR JSON (IR consumer mode)
        \\
    , .{});
}

/// Phase 1: Compile from ANF IR JSON (passes 5-6 only)
fn compileFromIR(allocator: std.mem.Allocator, path: []const u8) !void {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const source = try file.readToEndAlloc(allocator, 10 * 1024 * 1024);
    defer allocator.free(source);

    // Parse ANF IR JSON
    const program = try json_parser.parseANFProgram(allocator, source);
    defer program.deinit(allocator);

    // Pass 5: Stack lower
    const stack_program = try stack_lower.lower(allocator, program);
    defer stack_program.deinit(allocator);

    // Pass 6: Emit
    const artifact = try emit.emitArtifact(allocator, stack_program, program);
    defer allocator.free(artifact);

    const stdout = std.fs.File.stdout();
    try stdout.writeAll(artifact);
    try stdout.writeAll("\n");
}

/// Full pipeline: source -> parse -> validate -> typecheck -> ANF -> stack -> emit
fn compileFromSource(allocator: std.mem.Allocator, path: []const u8) !void {
    _ = allocator;
    std.debug.print("Compiling: {s}\n", .{path});
    std.debug.print("Full source compilation not yet implemented. Use compile-ir for Phase 1.\n", .{});
}

test {
    _ = @import("ir/types.zig");
    _ = @import("ir/json.zig");
    _ = @import("codegen/opcodes.zig");
    _ = @import("codegen/emit.zig");
    _ = @import("passes/stack_lower.zig");
    _ = @import("passes/peephole.zig");
    _ = @import("passes/parse_zig.zig");
    _ = @import("passes/parse_ts.zig");
    _ = @import("passes/validate.zig");
    _ = @import("passes/typecheck.zig");
    _ = @import("passes/anf_lower.zig");
    _ = @import("passes/constant_fold.zig");
    _ = @import("passes/ec_optimizer.zig");
}
