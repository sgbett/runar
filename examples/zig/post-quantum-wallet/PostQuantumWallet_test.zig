const std = @import("std");
const root = @import("../examples_test.zig");

fn contractPath(comptime basename: []const u8) []const u8 {
    return "post-quantum-wallet/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}
fn sha256First20(bytes: []const u8) [20]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});

    var out: [20]u8 = undefined;
    @memcpy(out[0..], digest[0..20]);
    return out;
}

const MirrorPostQuantumWallet = struct {
    ecdsa_pub_key_hash: [20]u8,
    wots_pub_key_hash: [20]u8,

    fn init(ecdsa_pub_key_hash: [20]u8, wots_pub_key_hash: [20]u8) MirrorPostQuantumWallet {
        return .{
            .ecdsa_pub_key_hash = ecdsa_pub_key_hash,
            .wots_pub_key_hash = wots_pub_key_hash,
        };
    }

    fn spend(
        self: MirrorPostQuantumWallet,
        wots_sig_ok: bool,
        sig_ok: bool,
        pub_key: []const u8,
        wots_pub_key: []const u8,
    ) bool {
        const ecdsa_hash = sha256First20(pub_key);
        const wots_hash = sha256First20(wots_pub_key);
        return std.mem.eql(u8, self.ecdsa_pub_key_hash[0..], ecdsa_hash[0..]) and
            sig_ok and
            std.mem.eql(u8, self.wots_pub_key_hash[0..], wots_hash[0..]) and
            wots_sig_ok;
    }
};

test "compile-check PostQuantumWallet.runar.zig" {
    try runCompileChecks("PostQuantumWallet.runar.zig");
}

test "PostQuantumWallet init stores both authorization hashes" {
    const ecdsa_hash = sha256First20("ecdsa-pub-key");
    const wots_hash = sha256First20("wots-pub-key");
    const contract = MirrorPostQuantumWallet.init(ecdsa_hash, wots_hash);

    try std.testing.expectEqualSlices(u8, ecdsa_hash[0..], contract.ecdsa_pub_key_hash[0..]);
    try std.testing.expectEqualSlices(u8, wots_hash[0..], contract.wots_pub_key_hash[0..]);
}

test "PostQuantumWallet spend requires both signature systems" {
    const contract = MirrorPostQuantumWallet.init(
        sha256First20("ecdsa-pub-key"),
        sha256First20("wots-pub-key"),
    );

    try std.testing.expect(contract.spend(true, true, "ecdsa-pub-key", "wots-pub-key"));
    try std.testing.expect(!contract.spend(false, true, "ecdsa-pub-key", "wots-pub-key"));
    try std.testing.expect(!contract.spend(true, true, "ecdsa-pub-key", "other-wots-key"));
}
