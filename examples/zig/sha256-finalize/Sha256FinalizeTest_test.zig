const std = @import("std");
const root = @import("../examples_test.zig");

fn contractPath(comptime basename: []const u8) []const u8 {
    return "sha256-finalize/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

fn sha256Digest(message: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(message, &digest, .{});
    return digest;
}

const MirrorSha256FinalizeTest = struct {
    expected: [32]u8,

    fn init(expected: [32]u8) MirrorSha256FinalizeTest {
        return .{ .expected = expected };
    }

    fn verify(self: MirrorSha256FinalizeTest, finalized: [32]u8, remaining: []const u8, msg_bit_len: i64) bool {
        return msg_bit_len == @as(i64, @intCast(remaining.len * 8)) and
            std.mem.eql(u8, self.expected[0..], finalized[0..]);
    }
};

test "compile-check Sha256FinalizeTest.runar.zig" {
    try runCompileChecks("Sha256FinalizeTest.runar.zig");
}

test "Sha256FinalizeTest stores expected digest" {
    const expected = sha256Digest("abc");
    const contract = MirrorSha256FinalizeTest.init(expected);
    try std.testing.expectEqualSlices(u8, expected[0..], contract.expected[0..]);
}

test "Sha256FinalizeTest verify checks digest bytes and message bit length" {
    const remaining = "abc";
    const expected = sha256Digest(remaining);
    const contract = MirrorSha256FinalizeTest.init(expected);

    try std.testing.expect(contract.verify(expected, remaining, 24));
    try std.testing.expect(!contract.verify(expected, remaining, 23));
    try std.testing.expect(!contract.verify(sha256Digest("abcd"), remaining, 24));
}
