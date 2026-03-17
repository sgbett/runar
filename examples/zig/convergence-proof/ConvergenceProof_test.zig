const std = @import("std");
const root = @import("../examples_test.zig");

fn contractPath(comptime basename: []const u8) []const u8 {
    return "convergence-proof/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}
const Point = struct {
    x: i64,
    y: i64,
};

fn onCurve(point: Point) bool {
    return point.x >= 0 and point.y >= 0;
}

fn negate(point: Point) Point {
    return .{ .x = -point.x, .y = -point.y };
}

fn add(a: Point, b: Point) Point {
    return .{ .x = a.x + b.x, .y = a.y + b.y };
}

fn mulGen(delta: i64) Point {
    return .{ .x = delta, .y = delta * 2 };
}

const MirrorConvergenceProof = struct {
    r_a: Point,
    r_b: Point,

    fn init(r_a: Point, r_b: Point) MirrorConvergenceProof {
        return .{
            .r_a = r_a,
            .r_b = r_b,
        };
    }

    fn proveConvergence(self: MirrorConvergenceProof, delta_o: i64) bool {
        if (!onCurve(self.r_a) or !onCurve(self.r_b)) return false;

        const diff = add(self.r_a, negate(self.r_b));
        const expected = mulGen(delta_o);

        return diff.x == expected.x and diff.y == expected.y;
    }
};

test "compile-check ConvergenceProof.runar.zig" {
    try runCompileChecks("ConvergenceProof.runar.zig");
}

test "ConvergenceProof init stores both points" {
    const contract = MirrorConvergenceProof.init(.{ .x = 5, .y = 10 }, .{ .x = 2, .y = 4 });
    try std.testing.expectEqual(@as(i64, 5), contract.r_a.x);
    try std.testing.expectEqual(@as(i64, 4), contract.r_b.y);
}

test "ConvergenceProof proveConvergence compares the point delta against generator multiplication" {
    const contract = MirrorConvergenceProof.init(.{ .x = 5, .y = 10 }, .{ .x = 2, .y = 4 });

    try std.testing.expect(contract.proveConvergence(3));
    try std.testing.expect(!contract.proveConvergence(4));
    try std.testing.expect(!MirrorConvergenceProof.init(.{ .x = -1, .y = 0 }, .{ .x = 0, .y = 0 }).proveConvergence(1));
}
