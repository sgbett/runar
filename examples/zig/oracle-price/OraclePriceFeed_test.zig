const std = @import("std");
const root = @import("../examples_test.zig");

fn contractPath(comptime basename: []const u8) []const u8 {
    return "oracle-price/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

fn num2bin8(value: u64) [8]u8 {
    var out = [_]u8{0} ** 8;
    var current = value;
    var index: usize = 0;
    while (index < out.len) : (index += 1) {
        out[index] = @truncate(current & 0xff);
        current >>= 8;
    }
    return out;
}

const MirrorOraclePriceFeed = struct {
    oracle_pub_key: []const u8,
    receiver: []const u8,

    fn init(oracle_pub_key: []const u8, receiver: []const u8) MirrorOraclePriceFeed {
        return .{
            .oracle_pub_key = oracle_pub_key,
            .receiver = receiver,
        };
    }

    fn settle(
        self: MirrorOraclePriceFeed,
        price: u64,
        rabin_sig_ok: bool,
        sig_ok: bool,
        expected_msg: [8]u8,
    ) bool {
        _ = self;
        const msg = num2bin8(price);
        return rabin_sig_ok and
            sig_ok and
            price > 50_000 and
            std.mem.eql(u8, msg[0..], expected_msg[0..]);
    }
};

test "compile-check OraclePriceFeed.runar.zig" {
    try runCompileChecks("OraclePriceFeed.runar.zig");
}

test "OraclePriceFeed init stores oracle and receiver" {
    const contract = MirrorOraclePriceFeed.init("oracle", "receiver");
    try std.testing.expectEqualStrings("oracle", contract.oracle_pub_key);
    try std.testing.expectEqualStrings("receiver", contract.receiver);
}

test "OraclePriceFeed settle requires an encoded oracle message, threshold, and receiver signature" {
    const contract = MirrorOraclePriceFeed.init("oracle", "receiver");
    const expected_msg = num2bin8(60_000);

    try std.testing.expect(contract.settle(60_000, true, true, expected_msg));
    try std.testing.expect(!contract.settle(49_999, true, true, num2bin8(49_999)));
    try std.testing.expect(!contract.settle(60_000, false, true, expected_msg));
}
