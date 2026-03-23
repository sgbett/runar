const std = @import("std");
const bsvz = @import("bsvz");
const types = @import("sdk_types.zig");
const state_mod = @import("sdk_state.zig");
const deploy_mod = @import("sdk_deploy.zig");

// ---------------------------------------------------------------------------
// Transaction construction for method invocation
// ---------------------------------------------------------------------------

pub const CallBuildOptions = struct {
    contract_outputs: []const types.ContractOutput = &.{},
};

pub const CallResult = struct {
    tx_hex: []u8,
    input_count: usize,
    change_amount: i64,

    pub fn deinit(self: *CallResult, allocator: std.mem.Allocator) void {
        allocator.free(self.tx_hex);
        self.* = .{ .tx_hex = &.{}, .input_count = 0, .change_amount = 0 };
    }
};

/// BuildCallTransaction builds a Transaction that spends a contract UTXO.
///
/// Input 0: the current contract UTXO with the given unlocking script.
/// Additional inputs: funding UTXOs if provided.
/// Output 0 (optional): new contract UTXO with updated locking script.
/// Last output (optional): change.
pub fn buildCallTransaction(
    allocator: std.mem.Allocator,
    current_utxo: types.UTXO,
    unlocking_script_hex: []const u8,
    new_locking_script_hex: []const u8,
    new_satoshis: i64,
    change_address: ?[]const u8,
    additional_utxos: []const types.UTXO,
    fee_rate_in: i64,
    opts: ?*const CallBuildOptions,
) !CallResult {
    // Determine contract outputs
    var contract_outputs: std.ArrayListUnmanaged(types.ContractOutput) = .empty;
    defer contract_outputs.deinit(allocator);

    if (opts != null and opts.?.contract_outputs.len > 0) {
        try contract_outputs.appendSlice(allocator, opts.?.contract_outputs);
    } else if (new_locking_script_hex.len > 0) {
        const sats = if (new_satoshis > 0) new_satoshis else current_utxo.satoshis;
        try contract_outputs.append(allocator, .{ .script = new_locking_script_hex, .satoshis = sats });
    }

    // Calculate total inputs
    var total_input: i64 = current_utxo.satoshis;
    for (additional_utxos) |u| total_input += u.satoshis;

    var contract_output_sats: i64 = 0;
    for (contract_outputs.items) |co| contract_output_sats += co.satoshis;

    // Estimate fee
    const input0_script_len = unlocking_script_hex.len / 2;
    const input0_size = 32 + 4 + varIntByteSize(input0_script_len) + input0_script_len + 4;
    const p2pkh_inputs_size = additional_utxos.len * 148;
    const inputs_size = input0_size + p2pkh_inputs_size;

    var outputs_size: usize = 0;
    for (contract_outputs.items) |co| {
        const script_len = co.script.len / 2;
        outputs_size += 8 + varIntByteSize(script_len) + script_len;
    }
    if (change_address != null) {
        outputs_size += 34; // P2PKH change
    }
    const estimated_size: i64 = @intCast(10 + inputs_size + outputs_size);
    const rate: i64 = if (fee_rate_in > 0) fee_rate_in else 100;
    const fee = @divTrunc(estimated_size * rate + 999, 1000);

    const change = total_input - contract_output_sats - fee;

    // Build transaction using bsvz Builder
    var builder = bsvz.transaction.Builder.init(allocator);
    defer builder.deinit();

    // Input 0: contract UTXO with unlocking script
    {
        const txid_chain = bsvz.primitives.chainhash.Hash.fromHex(current_utxo.txid) catch return error.OutOfMemory;
        const txid_hash = bsvz.crypto.Hash256{ .bytes = txid_chain.bytes };
        const unlock_bytes = try bsvz.primitives.hex.decode(allocator, unlocking_script_hex);
        defer allocator.free(unlock_bytes);
        const utxo_script_bytes = try bsvz.primitives.hex.decode(allocator, current_utxo.script);
        defer allocator.free(utxo_script_bytes);

        try builder.addInput(.{
            .previous_outpoint = .{
                .txid = txid_hash,
                .index = @intCast(current_utxo.output_index),
            },
            .unlocking_script = bsvz.script.Script.init(unlock_bytes),
            .sequence = 0xffffffff,
            .source_output = .{
                .satoshis = current_utxo.satoshis,
                .locking_script = bsvz.script.Script.init(utxo_script_bytes),
            },
        });
    }

    // P2PKH funding inputs (unsigned — empty script)
    for (additional_utxos) |utxo| {
        const txid_chain = bsvz.primitives.chainhash.Hash.fromHex(utxo.txid) catch return error.OutOfMemory;
        const txid_hash = bsvz.crypto.Hash256{ .bytes = txid_chain.bytes };
        const utxo_script_bytes = try bsvz.primitives.hex.decode(allocator, utxo.script);
        defer allocator.free(utxo_script_bytes);

        try builder.addInput(.{
            .previous_outpoint = .{
                .txid = txid_hash,
                .index = @intCast(utxo.output_index),
            },
            .unlocking_script = .empty(),
            .sequence = 0xffffffff,
            .source_output = .{
                .satoshis = utxo.satoshis,
                .locking_script = bsvz.script.Script.init(utxo_script_bytes),
            },
        });
    }

    // Contract outputs
    for (contract_outputs.items) |co| {
        const co_bytes = try bsvz.primitives.hex.decode(allocator, co.script);
        defer allocator.free(co_bytes);
        try builder.addOutput(.{
            .satoshis = co.satoshis,
            .locking_script = bsvz.script.Script.init(co_bytes),
        });
    }

    // Change output
    if (change > 0) {
        if (change_address) |addr| {
            try builder.payToAddress(addr, change);
        }
    }

    // Build and serialize
    var tx = try builder.build();
    defer tx.deinit(allocator);

    const serialized = try tx.serialize(allocator);
    defer allocator.free(serialized);

    const hex_buf = try allocator.alloc(u8, serialized.len * 2);
    _ = try bsvz.primitives.hex.encodeLower(serialized, hex_buf);

    return .{
        .tx_hex = hex_buf,
        .input_count = 1 + additional_utxos.len,
        .change_amount = if (change > 0) change else 0,
    };
}

fn varIntByteSize(n: usize) usize {
    if (n < 0xfd) return 1;
    if (n <= 0xffff) return 3;
    if (n <= 0xffffffff) return 5;
    return 9;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "buildCallTransaction with stateless contract" {
    const allocator = std.testing.allocator;

    const contract_utxo = types.UTXO{
        .txid = "aa" ** 32,
        .output_index = 0,
        .satoshis = 1000,
        .script = "5100", // OP_1 OP_0
    };

    // Simple unlocking script: OP_1
    var result = try buildCallTransaction(
        allocator,
        contract_utxo,
        "51", // unlocking script: OP_1
        "", // no new locking script (stateless)
        0,
        null,
        &.{}, // no additional utxos
        100,
        null,
    );
    defer result.deinit(allocator);

    try std.testing.expect(result.tx_hex.len > 0);
    try std.testing.expectEqual(@as(usize, 1), result.input_count);
}
