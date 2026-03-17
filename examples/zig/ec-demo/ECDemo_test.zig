const std = @import("std");
const root = @import("../examples_test.zig");

fn contractPath(comptime basename: []const u8) []const u8 {
    return "ec-demo/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}
const Point = struct {
    x: i64,
    y: i64,
};

fn makePoint(x: i64, y: i64) Point {
    return .{ .x = x, .y = y };
}

fn onCurve(point: Point) bool {
    return point.x >= 0 and point.y >= 0;
}

fn addPoints(a: Point, b: Point) Point {
    return .{ .x = a.x + b.x, .y = a.y + b.y };
}

fn mulPoint(point: Point, scalar: i64) Point {
    return .{ .x = point.x * scalar, .y = point.y * scalar };
}

fn mulGen(scalar: i64) Point {
    return .{ .x = scalar, .y = scalar * 2 };
}

fn negate(point: Point) Point {
    return .{ .x = point.x, .y = -point.y };
}

fn modReduce(value: i64, modulus: i64) i64 {
    const remainder = @mod(value, modulus);
    return remainder;
}

const MirrorECDemo = struct {
    pt: Point,

    fn init(pt: Point) MirrorECDemo {
        return .{ .pt = pt };
    }
};

test "compile-check ECDemo.runar.zig" {
    try runCompileChecks("ECDemo.runar.zig");
}

test "ECDemo init stores the point" {
    const point = makePoint(3, 5);
    const contract = MirrorECDemo.init(point);
    try std.testing.expectEqual(point.x, contract.pt.x);
    try std.testing.expectEqual(point.y, contract.pt.y);
}

test "ECDemo point helpers preserve core arithmetic" {
    const point = makePoint(3, 5);
    const other = makePoint(4, 7);

    try std.testing.expect(onCurve(point));
    try std.testing.expectEqualDeep(makePoint(7, 12), addPoints(point, other));
    try std.testing.expectEqualDeep(makePoint(6, 10), mulPoint(point, 2));
    try std.testing.expectEqualDeep(makePoint(9, 18), mulGen(9));
    try std.testing.expectEqualDeep(point, negate(negate(point)));
    try std.testing.expectEqual(@as(i64, 2), modReduce(17, 5));
}
