const std = @import("std");
const runar = @import("runar");
const bsvz = @import("bsvz");
const helpers = @import("helpers.zig");
const compile = @import("compile.zig");

// ---------------------------------------------------------------------------
// Helpers — hex-encoded values for the SDK (on-chain convention)
// ---------------------------------------------------------------------------

const BB_PRIME: i64 = 2013265921;

fn bbMulField(a: i64, b: i64) i64 {
    return @rem(a * b, BB_PRIME);
}

fn hexSha256(allocator: std.mem.Allocator, hex_data: []const u8) ![]u8 {
    // Decode hex to bytes
    const byte_len = hex_data.len / 2;
    const data = try allocator.alloc(u8, byte_len);
    defer allocator.free(data);
    for (0..byte_len) |i| {
        data[i] = std.fmt.parseUnsigned(u8, hex_data[i * 2 .. i * 2 + 2], 16) catch 0;
    }

    // SHA-256
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &hash, .{});

    // Encode to hex
    const result = try allocator.alloc(u8, 64);
    const hex_chars = "0123456789abcdef";
    for (0..32) |i| {
        result[i * 2] = hex_chars[hash[i] >> 4];
        result[i * 2 + 1] = hex_chars[hash[i] & 0x0f];
    }
    return result;
}

fn hexHash256(allocator: std.mem.Allocator, hex_data: []const u8) ![]u8 {
    const first = try hexSha256(allocator, hex_data);
    defer allocator.free(first);
    return hexSha256(allocator, first);
}

fn hexStateRoot(allocator: std.mem.Allocator, n: usize) ![]u8 {
    const input = try std.fmt.allocPrint(allocator, "{x:0>2}", .{n});
    defer allocator.free(input);
    return hexSha256(allocator, input);
}

fn hexZeros32(allocator: std.mem.Allocator) ![]u8 {
    const result = try allocator.alloc(u8, 64);
    @memset(result, '0');
    return result;
}

const MerkleTree = struct {
    root: []const u8,
    layers: [][]const []const u8,
    leaves: []const []const u8,
    allocator: std.mem.Allocator,

    fn deinit(self: *MerkleTree) void {
        for (self.layers) |layer| {
            for (layer) |item| self.allocator.free(item);
            self.allocator.free(layer);
        }
        self.allocator.free(self.layers);
        for (self.leaves) |leaf| self.allocator.free(leaf);
        self.allocator.free(self.leaves);
    }
};

fn buildMerkleTree(allocator: std.mem.Allocator) !MerkleTree {
    // Build 16 leaves
    var leaves = try allocator.alloc([]const u8, 16);
    for (0..16) |i| {
        const input = try std.fmt.allocPrint(allocator, "{x:0>2}", .{i});
        defer allocator.free(input);
        leaves[i] = try hexSha256(allocator, input);
    }

    var layers: std.ArrayListUnmanaged([]const []const u8) = .empty;

    // Clone first layer
    var first_layer = try allocator.alloc([]const u8, leaves.len);
    for (leaves, 0..) |leaf, i| first_layer[i] = try allocator.dupe(u8, leaf);
    try layers.append(allocator, first_layer);

    var level = first_layer;
    while (level.len > 1) {
        var next_layer = try allocator.alloc([]const u8, level.len / 2);
        for (0..level.len / 2) |i| {
            const combined = try std.fmt.allocPrint(allocator, "{s}{s}", .{ level[i * 2], level[i * 2 + 1] });
            defer allocator.free(combined);
            next_layer[i] = try hexSha256(allocator, combined);
        }
        try layers.append(allocator, next_layer);
        level = next_layer;
    }

    return .{
        .root = level[0],
        .layers = try layers.toOwnedSlice(allocator),
        .leaves = leaves,
        .allocator = allocator,
    };
}

fn getProof(allocator: std.mem.Allocator, tree: *const MerkleTree, index: usize) !struct { leaf: []u8, proof: []u8 } {
    var siblings: std.ArrayListUnmanaged([]const u8) = .empty;
    defer siblings.deinit(allocator);

    var idx = index;
    for (0..tree.layers.len - 1) |d| {
        try siblings.append(allocator, tree.layers[d][idx ^ 1]);
        idx >>= 1;
    }

    var proof_len: usize = 0;
    for (siblings.items) |s| proof_len += s.len;

    var proof = try allocator.alloc(u8, proof_len);
    var offset: usize = 0;
    for (siblings.items) |s| {
        @memcpy(proof[offset .. offset + s.len], s);
        offset += s.len;
    }

    const leaf = try allocator.dupe(u8, tree.leaves[index]);

    return .{ .leaf = leaf, .proof = proof };
}

const SC_LEAF_IDX: usize = 3;

test "StateCovenant_Deploy" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/ts/state-covenant/StateCovenant.runar.ts") catch |err| {
        std.log.warn("Could not compile StateCovenant contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var tree = try buildMerkleTree(allocator);
    defer tree.deinit();

    const zeros = try hexZeros32(allocator);
    defer allocator.free(zeros);

    const root_dup = try allocator.dupe(u8, tree.root);

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = zeros },
        .{ .int = 0 },
        .{ .bytes = root_dup },
    });
    defer contract.deinit();

    var wallet = try helpers.newWallet(allocator);
    defer wallet.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &wallet, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try wallet.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 10000 });
    defer allocator.free(deploy_txid);
    std.log.info("StateCovenant deployed: {s}", .{deploy_txid});
    try std.testing.expectEqual(@as(usize, 64), deploy_txid.len);
}
