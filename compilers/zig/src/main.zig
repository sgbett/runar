const std = @import("std");
const types = @import("ir/types.zig");
const json_parser = @import("ir/json.zig");
const parse_zig = @import("passes/parse_zig.zig");
const parse_ts = @import("passes/parse_ts.zig");
const validate_pass = @import("passes/validate.zig");
const typecheck_pass = @import("passes/typecheck.zig");
const anf_lower = @import("passes/anf_lower.zig");
const constant_fold = @import("passes/constant_fold.zig");
const ec_optimizer = @import("passes/ec_optimizer.zig");
const stack_lower = @import("passes/stack_lower.zig");
const peephole = @import("passes/peephole.zig");
const emit = @import("codegen/emit.zig");

const CompileOptions = struct {
    emit_ir: bool = false,
    hex_only: bool = false,
    disable_constant_folding: bool = false,
};

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

    const first = args[1];

    // Subcommand form
    if (std.mem.eql(u8, first, "compile-ir")) {
        if (args.len < 3) {
            std.debug.print("error: missing file argument\n", .{});
            std.process.exit(1);
        }
        compileFromIR(allocator, args[2], .{}) catch |err| {
            std.debug.print("error: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
        return;
    }
    if (std.mem.eql(u8, first, "compile")) {
        if (args.len < 3) {
            std.debug.print("error: missing file argument\n", .{});
            std.process.exit(1);
        }
        var opts = CompileOptions{};
        var i: usize = 3;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--emit-ir")) opts.emit_ir = true
            else if (std.mem.eql(u8, args[i], "--hex")) opts.hex_only = true
            else if (std.mem.eql(u8, args[i], "--disable-constant-folding")) opts.disable_constant_folding = true;
        }
        compileFromSource(allocator, args[2], opts) catch |err| {
            std.debug.print("error: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
        return;
    }
    if (std.mem.eql(u8, first, "--help") or std.mem.eql(u8, first, "-h")) {
        printUsage();
        return;
    }

    // Flag form: --source <file> [--emit-ir] [--hex] [--disable-constant-folding]
    if (std.mem.eql(u8, first, "--source")) {
        if (args.len < 3) {
            std.debug.print("error: --source requires a file path\n", .{});
            std.process.exit(1);
        }
        const file_path = args[2];
        var opts = CompileOptions{};
        var i: usize = 3;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--emit-ir")) opts.emit_ir = true
            else if (std.mem.eql(u8, args[i], "--hex")) opts.hex_only = true
            else if (std.mem.eql(u8, args[i], "--disable-constant-folding")) opts.disable_constant_folding = true;
        }
        const format = detectFormat(file_path);
        const result = if (format == .anf_json)
            compileFromIR(allocator, file_path, opts)
        else
            compileFromSource(allocator, file_path, opts);
        result catch |err| {
            std.debug.print("error: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
        return;
    }

    std.debug.print("Unknown command: {s}\n", .{first});
    printUsage();
    std.process.exit(1);
}

const FileFormat = enum { runar_zig, runar_ts, anf_json, unknown };

fn detectFormat(path: []const u8) FileFormat {
    if (std.mem.endsWith(u8, path, ".runar.zig")) return .runar_zig;
    if (std.mem.endsWith(u8, path, ".runar.ts")) return .runar_ts;
    if (std.mem.endsWith(u8, path, ".json")) return .anf_json;
    return .unknown;
}

fn printUsage() void {
    std.debug.print(
        \\Usage: runar-zig <command> [options]
        \\
        \\Commands:
        \\  compile <file> [flags]    Full pipeline: source -> Bitcoin Script
        \\  compile-ir <file>         IR consumer: ANF IR JSON -> Bitcoin Script
        \\  --source <file> [flags]   Flag mode (conformance runner compatible)
        \\  --help, -h                Show this help
        \\
        \\Flags:
        \\  --emit-ir                 Output canonical ANF IR JSON (stop after pass 4)
        \\  --hex                     Output script hex only (no artifact JSON)
        \\  --disable-constant-folding  Skip constant folding pass
        \\
        \\Formats: .runar.zig, .runar.ts, .json
        \\
    , .{});
}

/// Compile from ANF IR JSON (passes 5-6 only)
fn compileFromIR(allocator: std.mem.Allocator, path: []const u8, opts: CompileOptions) !void {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const source = try file.readToEndAlloc(allocator, 10 * 1024 * 1024);
    defer allocator.free(source);

    const program = try json_parser.parseANFProgram(allocator, source);
    defer program.deinit(allocator);

    if (opts.emit_ir) {
        const canonical = try json_parser.serializeCanonicalJSON(allocator, program);
        defer allocator.free(canonical);
        const stdout = std.fs.File.stdout();
        try stdout.writeAll(canonical);
        return;
    }

    const stack_program = try stack_lower.lower(allocator, program);
    defer stack_program.deinit(allocator);

    if (opts.hex_only) {
        const stdout = std.fs.File.stdout();
        for (stack_program.methods) |method| {
            const hex = try emit.emitMethodScript(allocator, method.instructions);
            defer allocator.free(hex);
            try stdout.writeAll(hex);
            try stdout.writeAll("\n");
        }
        return;
    }

    const artifact = try emit.emitArtifact(allocator, stack_program, program);
    defer allocator.free(artifact);
    const stdout = std.fs.File.stdout();
    try stdout.writeAll(artifact);
    try stdout.writeAll("\n");
}

/// Full pipeline: source -> parse -> validate -> typecheck -> ANF -> stack -> emit
fn compileFromSource(allocator: std.mem.Allocator, path: []const u8, opts: CompileOptions) !void {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const source = try file.readToEndAlloc(allocator, 1 * 1024 * 1024);
    defer allocator.free(source);

    const format = detectFormat(path);

    // Pass 1: Parse (dispatch by format, extract contract or fail)
    const contract: types.ContractNode = switch (format) {
        .runar_zig => blk: {
            const r = parse_zig.parseZig(allocator, source, path);
            if (r.errors.len > 0) {
                for (r.errors) |err| std.debug.print("  parse error: {s}\n", .{err});
                return error.ParseFailed;
            }
            break :blk r.contract orelse return error.ParseFailed;
        },
        .runar_ts => blk: {
            const r = parse_ts.parseTs(allocator, source, path);
            if (r.errors.len > 0) {
                for (r.errors) |err| std.debug.print("  parse error: {s}\n", .{err});
                return error.ParseFailed;
            }
            break :blk r.contract orelse return error.ParseFailed;
        },
        else => {
            std.debug.print("error: unsupported format for {s}\n", .{path});
            return error.UnsupportedFormat;
        },
    };

    // Pass 2: Validate
    const val_result = try validate_pass.validate(allocator, contract);
    if (val_result.errors.len > 0) {
        for (val_result.errors) |diag| std.debug.print("  validation error: {s}\n", .{diag.message});
        return error.ValidationFailed;
    }
    for (val_result.warnings) |diag| std.debug.print("  warning: {s}\n", .{diag.message});

    // Pass 3: Typecheck
    const tc_result = try typecheck_pass.typeCheck(allocator, contract);
    if (tc_result.errors.len > 0) {
        for (tc_result.errors) |err| std.debug.print("  type error: {s}\n", .{err});
        return error.TypeCheckFailed;
    }

    // Pass 4: ANF Lower
    var program = try anf_lower.lowerToANF(allocator, contract);

    // Pass 4.25: Constant Fold
    if (!opts.disable_constant_folding) {
        program = try constant_fold.foldConstants(allocator, program);
    }

    // Pass 4.5: EC Optimize
    program = try ec_optimizer.optimize(allocator, program);

    // --emit-ir: output canonical ANF IR JSON and stop
    if (opts.emit_ir) {
        const canonical = try json_parser.serializeCanonicalJSON(allocator, program);
        defer allocator.free(canonical);
        const stdout = std.fs.File.stdout();
        try stdout.writeAll(canonical);
        return;
    }

    // Pass 5: Stack Lower
    const stack_program = try stack_lower.lower(allocator, program);
    defer stack_program.deinit(allocator);

    // --hex: output hex script only
    if (opts.hex_only) {
        const stdout = std.fs.File.stdout();
        for (stack_program.methods) |method| {
            const hex = try emit.emitMethodScript(allocator, method.instructions);
            defer allocator.free(hex);
            try stdout.writeAll(hex);
            try stdout.writeAll("\n");
        }
        return;
    }

    // Pass 6: Emit full artifact
    const artifact = try emit.emitArtifact(allocator, stack_program, program);
    defer allocator.free(artifact);

    const stdout = std.fs.File.stdout();
    try stdout.writeAll(artifact);
    try stdout.writeAll("\n");

    std.debug.print("Compiled: {s}\n", .{path});
}

const UnsupportedFormat = error{UnsupportedFormat};
const ParseFailed = error{ParseFailed};
const ValidationFailed = error{ValidationFailed};
const TypeCheckFailed = error{TypeCheckFailed};

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
    _ = @import("tests/e2e.zig");
}
