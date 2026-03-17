const std = @import("std");

const root = @import("../examples_test.zig");

const contract_source = @embedFile("FunctionPatterns.runar.zig");

fn percentOf(amount: i64, fee_bps: i64) i64 {
    return @divTrunc(amount * fee_bps, 10_000);
}

fn mulDiv(value: i64, numerator: i64, denominator: i64) !i64 {
    if (denominator == 0) return error.DivisionByZero;
    return @divTrunc(value * numerator, denominator);
}

fn clampValue(value: i64, lo: i64, hi: i64) i64 {
    if (value < lo) return lo;
    if (value > hi) return hi;
    return value;
}

fn roundDown(value: i64, step: i64) !i64 {
    if (step <= 0) return error.InvalidStep;
    const remainder = @mod(value, step);
    return value - remainder;
}

const FunctionPatternsMirror = struct {
    balance: i64,

    fn deposit(self: *FunctionPatternsMirror, authorized: bool, amount: i64) !void {
        if (!authorized) return error.Unauthorized;
        if (amount <= 0) return error.InvalidAmount;
        self.balance += amount;
    }

    fn withdraw(self: *FunctionPatternsMirror, authorized: bool, amount: i64, fee_bps: i64) !void {
        if (!authorized) return error.Unauthorized;
        if (amount <= 0) return error.InvalidAmount;

        const fee = percentOf(amount, fee_bps);
        const total = amount + fee;
        if (total > self.balance) return error.InsufficientBalance;
        self.balance -= total;
    }

    fn scale(self: *FunctionPatternsMirror, authorized: bool, numerator: i64, denominator: i64) !void {
        if (!authorized) return error.Unauthorized;
        self.balance = try mulDiv(self.balance, numerator, denominator);
    }

    fn normalize(self: *FunctionPatternsMirror, authorized: bool, lo: i64, hi: i64, step: i64) !void {
        if (!authorized) return error.Unauthorized;
        const clamped = clampValue(self.balance, lo, hi);
        self.balance = try roundDown(clamped, step);
    }
};

test "compile-check FunctionPatterns.runar.zig" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "FunctionPatterns.runar.zig", .data = contract_source });

    const path = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..], "FunctionPatterns.runar.zig" });
    defer allocator.free(path);
    try root.runar.compileCheckFile(allocator, path);
    try root.runar.compileCheckSource(allocator, contract_source, "FunctionPatterns.runar.zig");
}

test "function patterns mirror applies deposit and withdraw fee flow" {
    var contract = FunctionPatternsMirror{ .balance = 1000 };

    try contract.deposit(true, 250);
    try std.testing.expectEqual(@as(i64, 1250), contract.balance);

    try contract.withdraw(true, 400, 250);
    try std.testing.expectEqual(@as(i64, 840), contract.balance);
}

test "function patterns mirror scales and normalizes balance" {
    var contract = FunctionPatternsMirror{ .balance = 137 };

    try contract.scale(true, 3, 2);
    try std.testing.expectEqual(@as(i64, 205), contract.balance);

    try contract.normalize(true, 0, 200, 16);
    try std.testing.expectEqual(@as(i64, 192), contract.balance);
}
