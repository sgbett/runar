const std = @import("std");

const root = @import("../examples_test.zig");
const runar = @import("runar");
const OraclePriceFeed = @import("OraclePriceFeed.runar.zig").OraclePriceFeed;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "oracle-price/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

fn findRabinPadding(message: []const u8, modulus: []const u8) ![]const u8 {
    var pad_value: u16 = 0;
    while (pad_value <= std.math.maxInt(u8)) : (pad_value += 1) {
        const candidate = [_]u8{@truncate(pad_value)};
        if (runar.verifyRabinSig(message, &[_]u8{0x00}, &candidate, modulus)) {
            return std.testing.allocator.dupe(u8, &candidate);
        }
    }
    return error.PaddingNotFound;
}

test "compile-check OraclePriceFeed.runar.zig" {
    try runCompileChecks("OraclePriceFeed.runar.zig");
}

test "OraclePriceFeed init stores oracle and receiver" {
    const oracle_pub_key = [_]u8{0xfb};
    const contract = OraclePriceFeed.init(&oracle_pub_key, runar.ALICE.pubKey);
    try std.testing.expectEqualSlices(u8, &oracle_pub_key, contract.oraclePubKey);
    try std.testing.expectEqualSlices(u8, runar.ALICE.pubKey, contract.receiver);
}

test "OraclePriceFeed settle accepts a real oracle proof above the threshold" {
    const oracle_pub_key = [_]u8{0xfb};
    const contract = OraclePriceFeed.init(&oracle_pub_key, runar.ALICE.pubKey);
    const price: i64 = 60_000;
    const msg = runar.num2bin(price, 8);
    const padding = try findRabinPadding(msg, &oracle_pub_key);
    defer std.testing.allocator.free(padding);

    contract.settle(price, &[_]u8{0x00}, padding, runar.signTestMessage(runar.ALICE));
}

test "OraclePriceFeed rejects invalid oracle proofs, thresholds, and receiver signatures" {
    try root.expectAssertFailure("oracle-price-wrong-rabin-proof");
    try root.expectAssertFailure("oracle-price-below-threshold");
    try root.expectAssertFailure("oracle-price-wrong-receiver-sig");
}
