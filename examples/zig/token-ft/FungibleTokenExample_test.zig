const std = @import("std");

const root = @import("../examples_test.zig");

const contract_source = @embedFile("FungibleTokenExample.runar.zig");

const TokenOutput = struct {
    owner: i64,
    balance: i64,
    merge_balance: i64,
    satoshis: i64,
};

const TransferPlan = struct {
    count: usize,
    outputs: [2]TokenOutput,
};

const MergePlan = struct {
    owner: i64,
    balance: i64,
    merge_balance: i64,
    satoshis: i64,
};

const FungibleTokenMirror = struct {
    owner: i64,
    balance: i64,
    merge_balance: i64,

    fn totalBalance(self: *const FungibleTokenMirror) i64 {
        return self.balance + self.merge_balance;
    }

    fn transfer(self: *const FungibleTokenMirror, to: i64, amount: i64, output_satoshis: i64) !TransferPlan {
        if (output_satoshis < 1) return error.InvalidSatoshis;
        const total_balance = self.totalBalance();
        if (amount <= 0) return error.InvalidAmount;
        if (amount > total_balance) return error.InsufficientBalance;

        var plan = TransferPlan{
            .count = 1,
            .outputs = undefined,
        };
        plan.outputs[0] = .{
            .owner = to,
            .balance = amount,
            .merge_balance = 0,
            .satoshis = output_satoshis,
        };
        if (amount < total_balance) {
            plan.count = 2;
            plan.outputs[1] = .{
                .owner = self.owner,
                .balance = total_balance - amount,
                .merge_balance = 0,
                .satoshis = output_satoshis,
            };
        }
        return plan;
    }

    fn send(self: *const FungibleTokenMirror, to: i64, output_satoshis: i64) !TokenOutput {
        if (output_satoshis < 1) return error.InvalidSatoshis;
        return .{
            .owner = to,
            .balance = self.totalBalance(),
            .merge_balance = 0,
            .satoshis = output_satoshis,
        };
    }

    fn merge(self: *const FungibleTokenMirror, other_balance: i64, my_is_first: bool, output_satoshis: i64) !MergePlan {
        if (output_satoshis < 1) return error.InvalidSatoshis;
        if (other_balance < 0) return error.InvalidMergeBalance;
        const my_balance = self.totalBalance();
        return .{
            .owner = self.owner,
            .balance = if (my_is_first) my_balance else other_balance,
            .merge_balance = if (my_is_first) other_balance else my_balance,
            .satoshis = output_satoshis,
        };
    }
};

test "compile-check FungibleTokenExample.runar.zig" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "FungibleTokenExample.runar.zig", .data = contract_source });

    const path = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..], "FungibleTokenExample.runar.zig" });
    defer allocator.free(path);
    try root.runar.compileCheckFile(allocator, path);
    try root.runar.compileCheckSource(allocator, contract_source, "FungibleTokenExample.runar.zig");
}

test "fungible token mirror transfer creates recipient and change outputs" {
    const token = FungibleTokenMirror{
        .owner = 1,
        .balance = 40,
        .merge_balance = 10,
    };

    const plan = try token.transfer(2, 30, 1);
    try std.testing.expectEqual(@as(usize, 2), plan.count);
    try std.testing.expectEqual(@as(i64, 2), plan.outputs[0].owner);
    try std.testing.expectEqual(@as(i64, 30), plan.outputs[0].balance);
    try std.testing.expectEqual(@as(i64, 1), plan.outputs[1].owner);
    try std.testing.expectEqual(@as(i64, 20), plan.outputs[1].balance);
}

test "fungible token mirror merge preserves first-input ordering" {
    const token = FungibleTokenMirror{
        .owner = 7,
        .balance = 25,
        .merge_balance = 5,
    };

    const first = try token.merge(12, true, 1);
    try std.testing.expectEqual(@as(i64, 30), first.balance);
    try std.testing.expectEqual(@as(i64, 12), first.merge_balance);

    const second = try token.merge(12, false, 1);
    try std.testing.expectEqual(@as(i64, 12), second.balance);
    try std.testing.expectEqual(@as(i64, 30), second.merge_balance);
}
