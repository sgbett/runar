const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const PostQuantumWallet = @import("PostQuantumWallet.runar.zig").PostQuantumWallet;

const Sha256 = std.crypto.hash.sha2.Sha256;
const wots_n = 32;
const wots_w = 16;
const wots_len1 = 64;
const wots_len2 = 3;
const wots_len = wots_len1 + wots_len2;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "post-quantum-wallet/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

fn wotsF(pub_seed: []const u8, chain_idx: usize, step_idx: usize, msg: []const u8) [32]u8 {
    var input: [wots_n + 2 + wots_n]u8 = undefined;
    @memcpy(input[0..wots_n], pub_seed);
    input[wots_n] = @truncate(chain_idx);
    input[wots_n + 1] = @truncate(step_idx);
    @memcpy(input[wots_n + 2 ..], msg);

    var out: [32]u8 = undefined;
    Sha256.hash(&input, &out, .{});
    return out;
}

fn wotsChain(x: []const u8, start_step: usize, steps: usize, pub_seed: []const u8, chain_idx: usize) [32]u8 {
    var current: [32]u8 = undefined;
    @memcpy(&current, x[0..wots_n]);
    var j = start_step;
    while (j < start_step + steps) : (j += 1) {
        current = wotsF(pub_seed, chain_idx, j, &current);
    }
    return current;
}

fn wotsAllDigits(msg_hash: *const [32]u8) [wots_len]usize {
    var digits: [wots_len]usize = undefined;
    var checksum: usize = 0;
    for (msg_hash, 0..) |byte, index| {
        const high = (byte >> 4) & 0x0f;
        const low = byte & 0x0f;
        digits[index * 2] = high;
        digits[index * 2 + 1] = low;
        checksum += (wots_w - 1) - high;
        checksum += (wots_w - 1) - low;
    }
    var remaining = checksum;
    var i: usize = wots_len;
    while (i > wots_len1) {
        i -= 1;
        digits[i] = remaining % wots_w;
        remaining /= wots_w;
    }
    return digits;
}

fn wotsSecretKeyElement(seed: []const u8, index: usize) [32]u8 {
    var input: [wots_n + 4]u8 = undefined;
    @memcpy(input[0..wots_n], seed);
    std.mem.writeInt(u32, input[wots_n .. wots_n + 4], @intCast(index), .big);

    var out: [32]u8 = undefined;
    Sha256.hash(&input, &out, .{});
    return out;
}

fn wotsPublicKeyFromSeed(seed: []const u8, pub_seed: []const u8) [64]u8 {
    var endpoints: [wots_len * wots_n]u8 = undefined;
    for (0..wots_len) |i| {
        const sk_element = wotsSecretKeyElement(seed, i);
        const endpoint = wotsChain(&sk_element, 0, wots_w - 1, pub_seed, i);
        @memcpy(endpoints[i * wots_n ..][0..wots_n], &endpoint);
    }

    var root_hash: [32]u8 = undefined;
    Sha256.hash(&endpoints, &root_hash, .{});

    var out: [64]u8 = undefined;
    @memcpy(out[0..32], pub_seed);
    @memcpy(out[32..64], &root_hash);
    return out;
}

fn wotsSignDeterministic(message: []const u8, seed: []const u8, pub_seed: []const u8) [wots_len * wots_n]u8 {
    var msg_hash: [32]u8 = undefined;
    Sha256.hash(message, &msg_hash, .{});
    const digits = wotsAllDigits(&msg_hash);

    var sig: [wots_len * wots_n]u8 = undefined;
    for (0..wots_len) |i| {
        const sk_element = wotsSecretKeyElement(seed, i);
        const element = wotsChain(&sk_element, 0, digits[i], pub_seed, i);
        @memcpy(sig[i * wots_n ..][0..wots_n], &element);
    }
    return sig;
}

test "compile-check PostQuantumWallet.runar.zig" {
    try runCompileChecks("PostQuantumWallet.runar.zig");
}

test "PostQuantumWallet init stores both authorization hashes" {
    const ecdsa_hash = runar.hash160(runar.ALICE.pubKey);
    const wots_pub_key = "wots-pub-key";
    const wots_hash = runar.hash160(wots_pub_key);
    const contract = PostQuantumWallet.init(ecdsa_hash, wots_hash);

    try std.testing.expectEqualSlices(u8, ecdsa_hash, contract.ecdsaPubKeyHash);
    try std.testing.expectEqualSlices(u8, wots_hash, contract.wotsPubKeyHash);
}

test "PostQuantumWallet spend accepts real ECDSA and WOTS authorization" {
    const ecdsa_sig = runar.signTestMessage(runar.ALICE);
    const seed = [_]u8{0x42} ** 32;
    const pub_seed = [_]u8{0x13} ** 32;
    const wots_pub_key = wotsPublicKeyFromSeed(&seed, &pub_seed);
    const wots_sig = wotsSignDeterministic(ecdsa_sig, &seed, &pub_seed);

    const contract = PostQuantumWallet.init(
        runar.hash160(runar.ALICE.pubKey),
        runar.hash160(&wots_pub_key),
    );

    contract.spend(&wots_sig, &wots_pub_key, ecdsa_sig, runar.ALICE.pubKey);
}

test "PostQuantumWallet rejects invalid authorization paths through the real contract" {
    try root.expectAssertFailure("post-quantum-wallet-wrong-ecdsa-pubkey");
    try root.expectAssertFailure("post-quantum-wallet-wrong-ecdsa-sig");
    try root.expectAssertFailure("post-quantum-wallet-wrong-wots-key");
    try root.expectAssertFailure("post-quantum-wallet-invalid-wots-proof");
}
