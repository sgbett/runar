const std = @import("std");

const root = @import("../examples_test.zig");

const contract_source = @embedFile("MathDemo.runar.zig");

fn percentOf(amount: i64, fee_bps: i64) i64 {
    return @divTrunc(amount * fee_bps, 10_000);
}

fn clampValueScalar(value: i64, lo: i64, hi: i64) i64 {
    if (value < lo) return lo;
    if (value > hi) return hi;
    return value;
}

fn signum(value: i64) i64 {
    if (value > 0) return 1;
    if (value < 0) return -1;
    return 0;
}

fn intPow(base: i64, exp: i64) !i64 {
    if (exp < 0) return error.NegativeExponent;
    var result: i64 = 1;
    var i: i64 = 0;
    while (i < exp) : (i += 1) result *= base;
    return result;
}

fn intSqrt(value: i64) !i64 {
    if (value < 0) return error.NegativeSqrt;
    var approx: i64 = 0;
    while ((approx + 1) * (approx + 1) <= value) : (approx += 1) {}
    return approx;
}

fn gcd(a: i64, b: i64) i64 {
    var x = if (a < 0) -a else a;
    var y = if (b < 0) -b else b;
    while (y != 0) {
        const tmp = @mod(x, y);
        x = y;
        y = tmp;
    }
    return x;
}

fn mulDiv(value: i64, numerator: i64, denominator: i64) !i64 {
    if (denominator == 0) return error.DivisionByZero;
    return @divTrunc(value * numerator, denominator);
}

fn floorLog2(value: i64) !i64 {
    if (value <= 0) return error.NonPositive;
    var current = value;
    var result: i64 = 0;
    while (current > 1) : (current = @divTrunc(current, 2)) result += 1;
    return result;
}

const MathDemoMirror = struct {
    value: i64,

    fn divideBy(self: *MathDemoMirror, divisor: i64) !void {
        if (divisor == 0) return error.DivisionByZero;
        self.value = @divTrunc(self.value, divisor);
    }

    fn withdrawWithFee(self: *MathDemoMirror, amount: i64, fee_bps: i64) !void {
        const fee = percentOf(amount, fee_bps);
        const total = amount + fee;
        if (total > self.value) return error.InsufficientValue;
        self.value -= total;
    }

    fn clampValue(self: *MathDemoMirror, lo: i64, hi: i64) void {
        self.value = clampValueScalar(self.value, lo, hi);
    }

    fn normalize(self: *MathDemoMirror) void {
        self.value = signum(self.value);
    }

    fn exponentiate(self: *MathDemoMirror, exp: i64) !void {
        self.value = try intPow(self.value, exp);
    }

    fn squareRoot(self: *MathDemoMirror) !void {
        self.value = try intSqrt(self.value);
    }

    fn reduceGcd(self: *MathDemoMirror, other: i64) void {
        self.value = gcd(self.value, other);
    }

    fn scaleByRatio(self: *MathDemoMirror, numerator: i64, denominator: i64) !void {
        self.value = try mulDiv(self.value, numerator, denominator);
    }

    fn computeLog2(self: *MathDemoMirror) !void {
        self.value = try floorLog2(self.value);
    }
};

test "compile-check MathDemo.runar.zig" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "MathDemo.runar.zig", .data = contract_source });

    const path = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..], "MathDemo.runar.zig" });
    defer allocator.free(path);
    try root.runar.compileCheckFile(allocator, path);
    try root.runar.compileCheckSource(allocator, contract_source, "MathDemo.runar.zig");
}

test "math demo mirror handles division fee clamp and sign" {
    var demo = MathDemoMirror{ .value = 1000 };
    try demo.divideBy(4);
    try std.testing.expectEqual(@as(i64, 250), demo.value);

    try demo.withdrawWithFee(100, 500);
    try std.testing.expectEqual(@as(i64, 145), demo.value);

    demo.clampValue(-10, 120);
    try std.testing.expectEqual(@as(i64, 120), demo.value);

    demo.normalize();
    try std.testing.expectEqual(@as(i64, 1), demo.value);
}

test "math demo mirror covers pow sqrt gcd ratio and log2" {
    var demo = MathDemoMirror{ .value = 3 };
    try demo.exponentiate(4);
    try std.testing.expectEqual(@as(i64, 81), demo.value);

    try demo.squareRoot();
    try std.testing.expectEqual(@as(i64, 9), demo.value);

    demo.reduceGcd(6);
    try std.testing.expectEqual(@as(i64, 3), demo.value);

    try demo.scaleByRatio(10, 3);
    try std.testing.expectEqual(@as(i64, 10), demo.value);

    try demo.computeLog2();
    try std.testing.expectEqual(@as(i64, 3), demo.value);
}
