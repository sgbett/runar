const std = @import("std");
const root = @import("../examples_test.zig");

fn contractPath(comptime basename: []const u8) []const u8 {
    return "p2pkh/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}
test "compile-check P2PKH.runar.zig" {
    try runCompileChecks("P2PKH.runar.zig");
}

fn sha256First20(bytes: []const u8) [20]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});

    var out: [20]u8 = undefined;
    @memcpy(out[0..], digest[0..20]);
    return out;
}

const MirrorP2PKH = struct {
    pub_key_hash: [20]u8,

    fn init(pub_key_hash: [20]u8) MirrorP2PKH {
        return .{ .pub_key_hash = pub_key_hash };
    }

    fn unlock(self: MirrorP2PKH, sig_ok: bool, pub_key: []const u8) bool {
        const actual = sha256First20(pub_key);
        return std.mem.eql(u8, self.pub_key_hash[0..], actual[0..]) and sig_ok;
    }
};

test "P2PKH init stores pubKeyHash" {
    const expected = sha256First20("alice");
    const contract = MirrorP2PKH.init(expected);
    try std.testing.expectEqualSlices(u8, expected[0..], contract.pub_key_hash[0..]);
}

test "P2PKH unlock requires hash match and signature" {
    const pub_key = "alice";
    const contract = MirrorP2PKH.init(sha256First20(pub_key));

    try std.testing.expect(contract.unlock(true, pub_key));
    try std.testing.expect(!contract.unlock(false, pub_key));
    try std.testing.expect(!contract.unlock(true, "mallory"));
}
