const std = @import("std");
const root = @import("../examples_test.zig");

fn contractPath(comptime basename: []const u8) []const u8 {
    return "blake3/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

fn blake3Digest(message: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(message, &digest, .{});
    return digest;
}

const MirrorBlake3Test = struct {
    expected: [32]u8,

    fn init(expected: [32]u8) MirrorBlake3Test {
        return .{ .expected = expected };
    }

    fn verifyHash(self: MirrorBlake3Test, message: []const u8) bool {
        const digest = blake3Digest(message);
        return std.mem.eql(u8, self.expected[0..], digest[0..]);
    }

    fn verifyCompress(self: MirrorBlake3Test, compressed: [32]u8) bool {
        return std.mem.eql(u8, self.expected[0..], compressed[0..]);
    }
};

test "compile-check Blake3Test.runar.zig" {
    try runCompileChecks("Blake3Test.runar.zig");
}

test "Blake3Test verifyHash checks the BLAKE3 digest" {
    const expected = blake3Digest("abc");
    const contract = MirrorBlake3Test.init(expected);

    try std.testing.expect(contract.verifyHash("abc"));
    try std.testing.expect(!contract.verifyHash("abcd"));
}

test "Blake3Test verifyCompress checks the builtin output bytes" {
    const expected = blake3Digest("compressed");
    const contract = MirrorBlake3Test.init(expected);

    try std.testing.expect(contract.verifyCompress(expected));
    try std.testing.expect(!contract.verifyCompress(blake3Digest("other")));
}
