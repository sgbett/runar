const std = @import("std");
const root = @import("../examples_test.zig");

fn contractPath(comptime basename: []const u8) []const u8 {
    return "sphincs-wallet/" ++ basename;
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

const MirrorSPHINCSWallet = struct {
    ecdsa_pub_key_hash: [20]u8,
    slhdsa_pub_key_hash: [20]u8,

    fn init(ecdsa_pub_key_hash: [20]u8, slhdsa_pub_key_hash: [20]u8) MirrorSPHINCSWallet {
        return .{
            .ecdsa_pub_key_hash = ecdsa_pub_key_hash,
            .slhdsa_pub_key_hash = slhdsa_pub_key_hash,
        };
    }

    fn spend(
        self: MirrorSPHINCSWallet,
        slhdsa_sig_ok: bool,
        sig_ok: bool,
        pub_key: []const u8,
        slhdsa_pub_key: []const u8,
    ) bool {
        const ecdsa_hash = sha256First20(pub_key);
        const slhdsa_hash = sha256First20(slhdsa_pub_key);
        return std.mem.eql(u8, self.ecdsa_pub_key_hash[0..], ecdsa_hash[0..]) and
            sig_ok and
            std.mem.eql(u8, self.slhdsa_pub_key_hash[0..], slhdsa_hash[0..]) and
            slhdsa_sig_ok;
    }
};

test "compile-check SPHINCSWallet.runar.zig" {
    try runCompileChecks("SPHINCSWallet.runar.zig");
}

test "SPHINCSWallet init stores both authorization hashes" {
    const ecdsa_hash = sha256First20("ecdsa-pub-key");
    const slhdsa_hash = sha256First20("slhdsa-pub-key");
    const contract = MirrorSPHINCSWallet.init(ecdsa_hash, slhdsa_hash);

    try std.testing.expectEqualSlices(u8, ecdsa_hash[0..], contract.ecdsa_pub_key_hash[0..]);
    try std.testing.expectEqualSlices(u8, slhdsa_hash[0..], contract.slhdsa_pub_key_hash[0..]);
}

test "SPHINCSWallet spend requires both signature systems" {
    const contract = MirrorSPHINCSWallet.init(
        sha256First20("ecdsa-pub-key"),
        sha256First20("slhdsa-pub-key"),
    );

    try std.testing.expect(contract.spend(true, true, "ecdsa-pub-key", "slhdsa-pub-key"));
    try std.testing.expect(!contract.spend(false, true, "ecdsa-pub-key", "slhdsa-pub-key"));
    try std.testing.expect(!contract.spend(true, true, "ecdsa-pub-key", "other-slhdsa-key"));
}
