const std = @import("std");
const root = @import("../examples_test.zig");

fn contractPath(comptime basename: []const u8) []const u8 {
    return "schnorr-zkp/" ++ basename;
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

fn challenge(r_point: Point, pub_key: Point) i64 {
    return (r_point.x - pub_key.x) + 1;
}

fn mulGen(scalar: i64) Point {
    return .{ .x = scalar, .y = scalar };
}

fn mul(point: Point, scalar: i64) Point {
    return .{ .x = point.x * scalar, .y = point.y * scalar };
}

fn add(a: Point, b: Point) Point {
    return .{ .x = a.x + b.x, .y = a.y + b.y };
}

const MirrorSchnorrZKP = struct {
    pub_key: Point,

    fn init(pub_key: Point) MirrorSchnorrZKP {
        return .{ .pub_key = pub_key };
    }

    fn verify(self: MirrorSchnorrZKP, r_point: Point, s: i64) bool {
        if (!onCurve(r_point)) return false;

        const e = challenge(r_point, self.pub_key);
        const s_g = mulGen(s);
        const e_p = mul(self.pub_key, e);
        const rhs = add(r_point, e_p);

        return s_g.x == rhs.x and s_g.y == rhs.y;
    }
};

test "compile-check SchnorrZKP.runar.zig" {
    try runCompileChecks("SchnorrZKP.runar.zig");
}

test "SchnorrZKP init stores pubKey" {
    const pub_key = Point{ .x = 1, .y = 1 };
    const contract = MirrorSchnorrZKP.init(pub_key);
    try std.testing.expectEqual(pub_key.x, contract.pub_key.x);
    try std.testing.expectEqual(pub_key.y, contract.pub_key.y);
}

test "SchnorrZKP verify mirrors the proof equality flow" {
    const contract = MirrorSchnorrZKP.init(.{ .x = 1, .y = 1 });

    try std.testing.expect(contract.verify(.{ .x = 1, .y = 1 }, 2));
    try std.testing.expect(!contract.verify(.{ .x = 1, .y = 2 }, 2));
    try std.testing.expect(!contract.verify(.{ .x = -1, .y = 1 }, 2));
}
