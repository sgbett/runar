const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const fixtures = @import("fixtures.zig");
const SPHINCSWallet = @import("SPHINCSWallet.runar.zig").SPHINCSWallet;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "sphincs-wallet/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check SPHINCSWallet.runar.zig" {
    try runCompileChecks("SPHINCSWallet.runar.zig");
}

test "SPHINCSWallet init stores both authorization hashes" {
    const ecdsa_hash = runar.hash160(runar.ALICE.pubKey);
    const slhdsa_hash = runar.hash160(&fixtures.slhdsa_pub_key);
    const contract = SPHINCSWallet.init(ecdsa_hash, slhdsa_hash);

    try std.testing.expectEqualSlices(u8, ecdsa_hash, contract.ecdsaPubKeyHash);
    try std.testing.expectEqualSlices(u8, slhdsa_hash, contract.slhdsaPubKeyHash);
    try std.testing.expectEqualSlices(u8, &fixtures.slhdsa_pub_key_hash, contract.slhdsaPubKeyHash);
}

test "SPHINCSWallet rejects invalid authorization paths through the real contract" {
    try root.expectAssertFailure("sphincs-wallet-wrong-ecdsa-pubkey");
    try root.expectAssertFailure("sphincs-wallet-wrong-ecdsa-sig");
    try root.expectAssertFailure("sphincs-wallet-wrong-slhdsa-key");
    try root.expectAssertFailure("sphincs-wallet-invalid-slhdsa-proof");
}
