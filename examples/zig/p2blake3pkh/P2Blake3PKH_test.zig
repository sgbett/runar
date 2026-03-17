const std = @import("std");
const root = @import("../examples_test.zig");

fn contractPath(comptime basename: []const u8) []const u8 {
    return "p2blake3pkh/" ++ basename;
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

const MirrorP2Blake3PKH = struct {
    pub_key_hash: [32]u8,

    fn init(pub_key_hash: [32]u8) MirrorP2Blake3PKH {
        return .{ .pub_key_hash = pub_key_hash };
    }

    fn unlock(self: MirrorP2Blake3PKH, sig_ok: bool, pub_key: []const u8) bool {
        const actual = blake3Digest(pub_key);
        return std.mem.eql(u8, self.pub_key_hash[0..], actual[0..]) and sig_ok;
    }
};

test "compile-check P2Blake3PKH.runar.zig" {
    try runCompileChecks("P2Blake3PKH.runar.zig");
}

test "P2Blake3PKH init stores pubKeyHash" {
    const expected = blake3Digest("alice");
    const contract = MirrorP2Blake3PKH.init(expected);
    try std.testing.expectEqualSlices(u8, expected[0..], contract.pub_key_hash[0..]);
}

test "P2Blake3PKH unlock requires hash match and signature" {
    const pub_key = "alice";
    const contract = MirrorP2Blake3PKH.init(blake3Digest(pub_key));

    try std.testing.expect(contract.unlock(true, pub_key));
    try std.testing.expect(!contract.unlock(false, pub_key));
    try std.testing.expect(!contract.unlock(true, "mallory"));
}
