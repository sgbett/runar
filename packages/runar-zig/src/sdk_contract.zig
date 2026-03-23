const std = @import("std");
const bsvz = @import("bsvz");
const types = @import("sdk_types.zig");
const state_mod = @import("sdk_state.zig");
const provider_mod = @import("sdk_provider.zig");
const signer_mod = @import("sdk_signer.zig");
const deploy_mod = @import("sdk_deploy.zig");
const call_mod = @import("sdk_call.zig");

// ---------------------------------------------------------------------------
// RunarContract — main contract runtime wrapper
// ---------------------------------------------------------------------------

pub const ContractError = error{
    NotDeployed,
    MethodNotFound,
    ArgCountMismatch,
    NoProviderOrSigner,
    DeployFailed,
    CallFailed,
    OutOfMemory,
    InsufficientFunds,
};

/// RunarContract is a runtime wrapper for a compiled Runar contract. It handles
/// deployment, method invocation, state tracking, and script construction.
pub const RunarContract = struct {
    allocator: std.mem.Allocator,
    artifact: *types.RunarArtifact,
    constructor_args: []types.StateValue,
    state: []types.StateValue,
    code_script: ?[]u8 = null,
    current_utxo: ?types.UTXO = null,
    provider: ?provider_mod.Provider = null,
    signer: ?signer_mod.Signer = null,

    /// Create a new contract instance from a compiled artifact and constructor arguments.
    pub fn init(
        allocator: std.mem.Allocator,
        artifact: *types.RunarArtifact,
        constructor_args: []const types.StateValue,
    ) !RunarContract {
        const expected = artifact.abi.constructor.params.len;
        if (constructor_args.len != expected) return ContractError.ArgCountMismatch;

        // Clone constructor args
        var args = try allocator.alloc(types.StateValue, constructor_args.len);
        for (constructor_args, 0..) |arg, i| {
            args[i] = try arg.clone(allocator);
        }

        // Initialize state from constructor args for stateful contracts
        var state_vals: []types.StateValue = &.{};
        if (artifact.state_fields.len > 0) {
            state_vals = try allocator.alloc(types.StateValue, artifact.state_fields.len);
            for (artifact.state_fields, 0..) |field, i| {
                if (field.initial_value) |init_val| {
                    // Parse initial value string based on type
                    state_vals[i] = parseInitialValue(allocator, init_val, field.type_name) catch .{ .int = 0 };
                } else if (field.index >= 0 and @as(usize, @intCast(field.index)) < constructor_args.len) {
                    state_vals[i] = try constructor_args[@intCast(field.index)].clone(allocator);
                } else {
                    state_vals[i] = .{ .int = 0 };
                }
            }
        }

        return .{
            .allocator = allocator,
            .artifact = artifact,
            .constructor_args = args,
            .state = state_vals,
        };
    }

    pub fn deinit(self: *RunarContract) void {
        for (self.constructor_args) |*arg| arg.deinit(self.allocator);
        if (self.constructor_args.len > 0) self.allocator.free(self.constructor_args);
        for (self.state) |*s| s.deinit(self.allocator);
        if (self.state.len > 0) self.allocator.free(self.state);
        if (self.code_script) |cs| self.allocator.free(cs);
        if (self.current_utxo) |*u| {
            var mu = u.*;
            mu.deinit(self.allocator);
        }
        self.* = .{
            .allocator = self.allocator,
            .artifact = self.artifact,
            .constructor_args = &.{},
            .state = &.{},
        };
    }

    /// Connect stores a provider and signer on this contract.
    pub fn connect(self: *RunarContract, provider: provider_mod.Provider, signer_val: signer_mod.Signer) void {
        self.provider = provider;
        self.signer = signer_val;
    }

    /// Deploy the contract by creating a UTXO with the locking script.
    pub fn deploy(
        self: *RunarContract,
        provider: ?provider_mod.Provider,
        signer_val: ?signer_mod.Signer,
        options: types.DeployOptions,
    ) ![]u8 {
        const prov = provider orelse self.provider orelse return ContractError.NoProviderOrSigner;
        const sign = signer_val orelse self.signer orelse return ContractError.NoProviderOrSigner;

        const address = try sign.getAddress(self.allocator);
        defer self.allocator.free(address);

        const change_address = options.change_address orelse address;

        const locking_script = try self.getLockingScript();
        defer self.allocator.free(locking_script);

        // Fetch fee rate and funding UTXOs
        const fee_rate = prov.getFeeRate() catch 100;
        const all_utxos = prov.getUtxos(self.allocator, address) catch return ContractError.DeployFailed;
        defer {
            for (all_utxos) |*u| u.deinit(self.allocator);
            self.allocator.free(all_utxos);
        }

        if (all_utxos.len == 0) return ContractError.InsufficientFunds;

        const selected = try deploy_mod.selectUtxos(self.allocator, all_utxos, options.satoshis, locking_script.len / 2, fee_rate);
        defer {
            for (selected) |*u| u.deinit(self.allocator);
            self.allocator.free(selected);
        }

        // Build the deploy transaction
        var deploy_result = deploy_mod.buildDeployTransaction(
            self.allocator,
            locking_script,
            selected,
            options.satoshis,
            change_address,
            fee_rate,
        ) catch return ContractError.DeployFailed;
        defer deploy_result.deinit(self.allocator);

        // Sign all P2PKH inputs
        var signed_tx = try self.allocator.dupe(u8, deploy_result.tx_hex);
        errdefer self.allocator.free(signed_tx);

        for (selected, 0..) |utxo, i| {
            const sig = try sign.sign(self.allocator, signed_tx, i, utxo.script, utxo.satoshis, null);
            defer self.allocator.free(sig);
            const pub_key = try sign.getPublicKey(self.allocator);
            defer self.allocator.free(pub_key);

            // Build P2PKH unlocking script hex: push(sig) + push(pubkey)
            const sig_push = try state_mod.encodePushData(self.allocator, sig);
            defer self.allocator.free(sig_push);
            const pk_push = try state_mod.encodePushData(self.allocator, pub_key);
            defer self.allocator.free(pk_push);

            const unlock = try std.mem.concat(self.allocator, u8, &[_][]const u8{ sig_push, pk_push });
            defer self.allocator.free(unlock);

            const new_tx = try insertUnlockingScript(self.allocator, signed_tx, i, unlock);
            self.allocator.free(signed_tx);
            signed_tx = new_tx;
        }

        // Broadcast
        const txid = prov.broadcast(self.allocator, signed_tx) catch return ContractError.DeployFailed;
        errdefer self.allocator.free(txid);

        // Track the deployed UTXO
        if (self.current_utxo) |*old| {
            var mu = old.*;
            mu.deinit(self.allocator);
        }
        self.current_utxo = .{
            .txid = try self.allocator.dupe(u8, txid),
            .output_index = 0,
            .satoshis = options.satoshis,
            .script = try self.allocator.dupe(u8, locking_script),
        };

        self.allocator.free(signed_tx);
        return txid;
    }

    /// GetLockingScript returns the full locking script hex for the contract.
    /// For stateful contracts this includes the code followed by OP_RETURN and
    /// the serialized state fields.
    pub fn getLockingScript(self: *const RunarContract) ![]u8 {
        const code = if (self.code_script) |cs|
            try self.allocator.dupe(u8, cs)
        else
            try self.buildCodeScript();
        errdefer self.allocator.free(code);

        if (self.artifact.state_fields.len > 0 and self.state.len > 0) {
            const state_hex = try state_mod.serializeState(
                self.allocator,
                self.artifact.state_fields,
                self.state,
            );
            defer self.allocator.free(state_hex);

            if (state_hex.len > 0) {
                const result = try std.mem.concat(self.allocator, u8, &[_][]const u8{ code, "6a", state_hex });
                self.allocator.free(code);
                return result;
            }
        }

        return code;
    }

    /// BuildUnlockingScript builds the unlocking script hex for a method call.
    pub fn buildUnlockingScript(
        self: *const RunarContract,
        method_name: []const u8,
        args: []const types.StateValue,
    ) ![]u8 {
        var script: std.ArrayListUnmanaged(u8) = .empty;
        errdefer script.deinit(self.allocator);

        // Push each argument
        for (args) |arg| {
            const encoded = try state_mod.encodeArg(self.allocator, arg);
            defer self.allocator.free(encoded);
            try script.appendSlice(self.allocator, encoded);
        }

        // Method selector if multiple public methods
        const public_methods = try self.getPublicMethods();
        defer self.allocator.free(public_methods);

        if (public_methods.len > 1) {
            var method_index: ?usize = null;
            for (public_methods, 0..) |m, i| {
                if (std.mem.eql(u8, m.name, method_name)) {
                    method_index = i;
                    break;
                }
            }
            if (method_index) |idx| {
                const selector = try state_mod.encodeScriptNumber(self.allocator, @intCast(idx));
                defer self.allocator.free(selector);
                try script.appendSlice(self.allocator, selector);
            }
        }

        return script.toOwnedSlice(self.allocator);
    }

    /// Get a copy of the current state values.
    pub fn getState(self: *const RunarContract) ![]types.StateValue {
        var result = try self.allocator.alloc(types.StateValue, self.state.len);
        for (self.state, 0..) |s, i| {
            result[i] = try s.clone(self.allocator);
        }
        return result;
    }

    /// Set state values directly.
    pub fn setState(self: *RunarContract, new_state: []const types.StateValue) !void {
        for (self.state) |*s| s.deinit(self.allocator);
        if (self.state.len > 0) self.allocator.free(self.state);
        var vals = try self.allocator.alloc(types.StateValue, new_state.len);
        for (new_state, 0..) |s, i| {
            vals[i] = try s.clone(self.allocator);
        }
        self.state = vals;
    }

    /// Get the current UTXO (null if not deployed or spent).
    pub fn getCurrentUtxo(self: *const RunarContract) ?types.UTXO {
        return self.current_utxo;
    }

    /// Set the current UTXO.
    pub fn setCurrentUtxo(self: *RunarContract, utxo: ?types.UTXO) !void {
        if (self.current_utxo) |*old| {
            var mu = old.*;
            mu.deinit(self.allocator);
        }
        if (utxo) |u| {
            self.current_utxo = .{
                .txid = try self.allocator.dupe(u8, u.txid),
                .output_index = u.output_index,
                .satoshis = u.satoshis,
                .script = try self.allocator.dupe(u8, u.script),
            };
        } else {
            self.current_utxo = null;
        }
    }

    // ---------------------------------------------------------------------------
    // Private helpers
    // ---------------------------------------------------------------------------

    fn buildCodeScript(self: *const RunarContract) ![]u8 {
        var script = try self.allocator.dupe(u8, self.artifact.script);

        if (self.artifact.constructor_slots.len > 0) {
            // Sort by byteOffset descending so splicing doesn't shift later offsets
            const indices = try self.allocator.alloc(usize, self.artifact.constructor_slots.len);
            defer self.allocator.free(indices);
            for (0..self.artifact.constructor_slots.len) |i| indices[i] = i;
            const slots = self.artifact.constructor_slots;
            std.mem.sort(usize, indices, slots, struct {
                fn lessThan(ctx: []const types.ConstructorSlot, a: usize, b: usize) bool {
                    return ctx[a].byte_offset > ctx[b].byte_offset;
                }
            }.lessThan);

            for (indices) |idx| {
                const slot = slots[idx];
                const param_idx: usize = @intCast(slot.param_index);
                if (param_idx >= self.constructor_args.len) continue;

                const encoded = try state_mod.encodeArg(self.allocator, self.constructor_args[param_idx]);
                defer self.allocator.free(encoded);

                const hex_offset: usize = @intCast(slot.byte_offset * 2);
                // Replace the 1-byte OP_0 placeholder (2 hex chars) with encoded arg
                if (hex_offset + 2 <= script.len) {
                    var new_script = try self.allocator.alloc(u8, script.len - 2 + encoded.len);
                    @memcpy(new_script[0..hex_offset], script[0..hex_offset]);
                    @memcpy(new_script[hex_offset .. hex_offset + encoded.len], encoded);
                    @memcpy(new_script[hex_offset + encoded.len ..], script[hex_offset + 2 ..]);
                    self.allocator.free(script);
                    script = new_script;
                }
            }
        } else if (self.artifact.state_fields.len == 0) {
            // Backward compatibility: old stateless artifacts without constructorSlots
            for (self.constructor_args) |arg| {
                const encoded = try state_mod.encodeArg(self.allocator, arg);
                defer self.allocator.free(encoded);
                const new_script = try std.mem.concat(self.allocator, u8, &[_][]const u8{ script, encoded });
                self.allocator.free(script);
                script = new_script;
            }
        }

        return script;
    }

    fn getPublicMethods(self: *const RunarContract) ![]types.ABIMethod {
        var result: std.ArrayListUnmanaged(types.ABIMethod) = .empty;
        for (self.artifact.abi.methods) |m| {
            if (m.is_public) try result.append(self.allocator, m);
        }
        return result.toOwnedSlice(self.allocator);
    }

    fn findMethod(self: *const RunarContract, name: []const u8) ?*types.ABIMethod {
        for (self.artifact.abi.methods) |*m| {
            if (m.is_public and std.mem.eql(u8, m.name, name)) return m;
        }
        return null;
    }

    /// adjustCodeSepOffset adjusts a code separator byte offset from the base
    /// (template) script to the constructor-arg-substituted script.
    pub fn adjustCodeSepOffset(self: *const RunarContract, base_offset: i32) !i32 {
        if (self.artifact.constructor_slots.len == 0) return base_offset;
        var shift: i32 = 0;
        for (self.artifact.constructor_slots) |slot| {
            if (slot.byte_offset < base_offset) {
                const param_idx: usize = @intCast(slot.param_index);
                if (param_idx < self.constructor_args.len) {
                    const encoded = try state_mod.encodeArg(self.allocator, self.constructor_args[param_idx]);
                    defer self.allocator.free(encoded);
                    shift += @as(i32, @intCast(encoded.len / 2)) - 1;
                }
            }
        }
        return base_offset + shift;
    }

    /// getCodeSepIndex returns the adjusted code separator byte offset for a
    /// given method index, or null if no OP_CODESEPARATOR is present.
    pub fn getCodeSepIndex(self: *const RunarContract, method_index: usize) !?i32 {
        if (self.artifact.code_separator_indices.len > 0 and method_index < self.artifact.code_separator_indices.len) {
            return try self.adjustCodeSepOffset(self.artifact.code_separator_indices[method_index]);
        }
        if (self.artifact.code_separator_index) |idx| {
            return try self.adjustCodeSepOffset(idx);
        }
        return null;
    }

    /// getCodePartHex returns the code portion of the locking script (without state).
    pub fn getCodePartHex(self: *const RunarContract) ![]u8 {
        if (self.code_script) |cs| return self.allocator.dupe(u8, cs);
        return self.buildCodeScript();
    }
};

// ---------------------------------------------------------------------------
// Helper: parse initial value string to StateValue
// ---------------------------------------------------------------------------

fn parseInitialValue(allocator: std.mem.Allocator, init_str: []const u8, type_name: []const u8) !types.StateValue {
    if (std.mem.eql(u8, type_name, "int") or std.mem.eql(u8, type_name, "bigint")) {
        // Handle BigInt strings with "n" suffix
        var s = init_str;
        if (std.mem.endsWith(u8, s, "n")) {
            s = s[0 .. s.len - 1];
        }
        const n = std.fmt.parseInt(i64, s, 10) catch return .{ .int = 0 };
        return .{ .int = n };
    } else if (std.mem.eql(u8, type_name, "bool")) {
        return .{ .boolean = std.mem.eql(u8, init_str, "true") };
    } else {
        return .{ .bytes = try allocator.dupe(u8, init_str) };
    }
}

// ---------------------------------------------------------------------------
// Helper: insert unlocking script into raw tx hex at given input index
// ---------------------------------------------------------------------------

pub fn insertUnlockingScript(allocator: std.mem.Allocator, tx_hex: []const u8, input_index: usize, unlock_script_hex: []const u8) ![]u8 {
    var pos: usize = 0;

    // Skip version (4 bytes = 8 hex chars)
    pos += 8;

    // Read input count
    const ic = readVarIntHex(tx_hex, pos);
    const input_count = ic.value;
    pos += ic.hex_len;

    if (input_index >= input_count) return error.OutOfMemory; // index out of range

    var i: usize = 0;
    while (i < input_count) : (i += 1) {
        // Skip prevTxid (32 bytes = 64 hex chars)
        pos += 64;
        // Skip prevOutputIndex (4 bytes = 8 hex chars)
        pos += 8;

        // Read scriptSig length
        const sl = readVarIntHex(tx_hex, pos);
        const script_len = sl.value;
        const sl_hex_len = sl.hex_len;

        if (i == input_index) {
            // Build replacement
            const new_script_byte_len = unlock_script_hex.len / 2;
            const new_varint = try writeVarIntHex(allocator, new_script_byte_len);
            defer allocator.free(new_varint);

            const before = tx_hex[0..pos];
            const after = tx_hex[pos + sl_hex_len + script_len * 2 ..];
            return std.mem.concat(allocator, u8, &[_][]const u8{ before, new_varint, unlock_script_hex, after });
        }

        // Skip this input's scriptSig + sequence (4 bytes = 8 hex chars)
        pos += sl_hex_len + script_len * 2 + 8;
    }

    return error.OutOfMemory; // should not reach here
}

const VarIntResult = struct {
    value: usize,
    hex_len: usize,
};

fn readVarIntHex(hex: []const u8, pos: usize) VarIntResult {
    const first = hexByteAt(hex, pos);
    if (first < 0xfd) return .{ .value = first, .hex_len = 2 };
    if (first == 0xfd) {
        const lo = hexByteAt(hex, pos + 2);
        const hi = hexByteAt(hex, pos + 4);
        return .{ .value = lo | (hi << 8), .hex_len = 6 };
    }
    if (first == 0xfe) {
        const b0 = hexByteAt(hex, pos + 2);
        const b1 = hexByteAt(hex, pos + 4);
        const b2 = hexByteAt(hex, pos + 6);
        const b3 = hexByteAt(hex, pos + 8);
        return .{ .value = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24), .hex_len = 10 };
    }
    // 0xff — 8-byte varint; low 4 bytes only
    const b0 = hexByteAt(hex, pos + 2);
    const b1 = hexByteAt(hex, pos + 4);
    const b2 = hexByteAt(hex, pos + 6);
    const b3 = hexByteAt(hex, pos + 8);
    return .{ .value = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24), .hex_len = 18 };
}

fn writeVarIntHex(allocator: std.mem.Allocator, n: usize) ![]u8 {
    if (n < 0xfd) {
        var buf: [2]u8 = undefined;
        _ = std.fmt.bufPrint(&buf, "{x:0>2}", .{n}) catch unreachable;
        return allocator.dupe(u8, &buf);
    }
    if (n <= 0xffff) {
        var buf: [6]u8 = undefined;
        const lo = n & 0xff;
        const hi = (n >> 8) & 0xff;
        _ = std.fmt.bufPrint(&buf, "fd{x:0>2}{x:0>2}", .{ lo, hi }) catch unreachable;
        return allocator.dupe(u8, &buf);
    }
    if (n <= 0xffffffff) {
        var buf: [10]u8 = undefined;
        const b0 = n & 0xff;
        const b1 = (n >> 8) & 0xff;
        const b2 = (n >> 16) & 0xff;
        const b3 = (n >> 24) & 0xff;
        _ = std.fmt.bufPrint(&buf, "fe{x:0>2}{x:0>2}{x:0>2}{x:0>2}", .{ b0, b1, b2, b3 }) catch unreachable;
        return allocator.dupe(u8, &buf);
    }
    return error.OutOfMemory;
}

fn hexByteAt(hex: []const u8, pos: usize) usize {
    if (pos + 2 > hex.len) return 0;
    const high = hexNibble(hex[pos]);
    const low = hexNibble(hex[pos + 1]);
    return (@as(usize, high) << 4) | @as(usize, low);
}

fn hexNibble(c: u8) u4 {
    return switch (c) {
        '0'...'9' => @intCast(c - '0'),
        'a'...'f' => @intCast(c - 'a' + 10),
        'A'...'F' => @intCast(c - 'A' + 10),
        else => 0,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "RunarContract.init and getLockingScript for stateless contract" {
    const allocator = std.testing.allocator;
    const json =
        \\{"contractName":"P2PKH","version":"1","compilerVersion":"1.0","script":"76a914","asm":"OP_DUP OP_HASH160",
        \\"abi":{"constructor":{"params":[{"name":"pubKeyHash","type":"Addr"}]},"methods":[{"name":"unlock","params":[],"isPublic":true}]},
        \\"stateFields":[],"constructorSlots":[],"buildTimestamp":"2024-01-01"}
    ;
    var artifact = try types.RunarArtifact.fromJson(allocator, json);
    defer artifact.deinit();

    var contract = try RunarContract.init(allocator, &artifact, &[_]types.StateValue{.{ .bytes = "aabbccdd" }});
    defer contract.deinit();

    const ls = try contract.getLockingScript();
    defer allocator.free(ls);
    // Stateless with no constructor slots appends args: "76a914" + push("aabbccdd") = "76a914" + "04aabbccdd"
    try std.testing.expect(std.mem.startsWith(u8, ls, "76a914"));
}

test "RunarContract.init and getLockingScript for stateful contract" {
    const allocator = std.testing.allocator;
    const json =
        \\{"contractName":"Counter","version":"1","compilerVersion":"1.0","script":"005100","asm":"OP_0 OP_1 OP_0",
        \\"abi":{"constructor":{"params":[{"name":"count","type":"int"}]},"methods":[{"name":"increment","params":[],"isPublic":true}]},
        \\"stateFields":[{"name":"count","type":"int","index":0}],
        \\"constructorSlots":[{"paramIndex":0,"byteOffset":0}],
        \\"codeSeparatorIndex":2,"buildTimestamp":"2024-01-01"}
    ;
    var artifact = try types.RunarArtifact.fromJson(allocator, json);
    defer artifact.deinit();

    var contract = try RunarContract.init(allocator, &artifact, &[_]types.StateValue{.{ .int = 0 }});
    defer contract.deinit();

    const ls = try contract.getLockingScript();
    defer allocator.free(ls);
    // Should contain OP_RETURN (6a) separator
    try std.testing.expect(std.mem.indexOf(u8, ls, "6a") != null);
}

test "RunarContract.buildUnlockingScript basic" {
    const allocator = std.testing.allocator;
    const json =
        \\{"contractName":"Test","version":"1","compilerVersion":"1.0","script":"5100","asm":"OP_1 OP_0",
        \\"abi":{"constructor":{"params":[]},"methods":[{"name":"unlock","params":[{"name":"x","type":"int"}],"isPublic":true}]},
        \\"stateFields":[],"constructorSlots":[],"buildTimestamp":"2024-01-01"}
    ;
    var artifact = try types.RunarArtifact.fromJson(allocator, json);
    defer artifact.deinit();

    var contract = try RunarContract.init(allocator, &artifact, &.{});
    defer contract.deinit();

    const unlock = try contract.buildUnlockingScript("unlock", &[_]types.StateValue{.{ .int = 42 }});
    defer allocator.free(unlock);
    try std.testing.expect(unlock.len > 0);
}

test "insertUnlockingScript replaces empty scriptSig" {
    const allocator = std.testing.allocator;
    // Minimal tx: version + 1 input (with 0-length scriptSig) + 0 outputs + locktime
    const tx = "01000000" ++ // version
        "01" ++ // 1 input
        "aa" ** 32 ++ // txid
        "00000000" ++ // vout
        "00" ++ // scriptSig length = 0
        "ffffffff" ++ // sequence
        "00" ++ // 0 outputs
        "00000000"; // locktime

    const result = try insertUnlockingScript(allocator, tx, 0, "51");
    defer allocator.free(result);

    // Should contain "0151" (varint 1 + OP_1)
    try std.testing.expect(std.mem.indexOf(u8, result, "0151") != null);
}
