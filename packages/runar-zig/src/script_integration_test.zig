const std = @import("std");
const builtins = @import("builtins.zig");
const test_keys = @import("test_keys.zig");
const frontend = @import("runar_frontend");
const bsvz = @import("bsvz");

// Integration tests: compile Runar contracts through the Zig compiler
// frontend, then verify Bitcoin Script output in bsvz's script engine.

test "bsvz engine executes arithmetic script (2 + 3 = 5)" {
    const allocator = std.testing.allocator;
    const script_bytes = [_]u8{ 0x52, 0x53, 0x93, 0x55, 0x9c };
    const script = bsvz.script.Script.init(&script_bytes);
    var result = try bsvz.script.engine.executeScript(.{ .allocator = allocator }, script);
    defer result.deinit(allocator);
    try std.testing.expect(result.success);
}

test "bsvz engine rejects failing arithmetic (2 + 3 != 6)" {
    const allocator = std.testing.allocator;
    const script_bytes = [_]u8{ 0x52, 0x53, 0x93, 0x56, 0x9c };
    const script = bsvz.script.Script.init(&script_bytes);
    var result = try bsvz.script.engine.executeScript(.{ .allocator = allocator }, script);
    defer result.deinit(allocator);
    try std.testing.expect(!result.success);
}

test "bsvz engine handles OP_IF branching" {
    const allocator = std.testing.allocator;
    const script_bytes = [_]u8{ 0x51, 0x63, 0x52, 0x67, 0x53, 0x68, 0x52, 0x9c };
    const script = bsvz.script.Script.init(&script_bytes);
    var result = try bsvz.script.engine.executeScript(.{ .allocator = allocator }, script);
    defer result.deinit(allocator);
    try std.testing.expect(result.success);
}

test "bsvz engine verifies OP_HASH160" {
    const allocator = std.testing.allocator;
    const msg = "hello";
    const expected_hash = builtins.hash160(msg);

    var script_buf: [256]u8 = undefined;
    var pos: usize = 0;
    script_buf[pos] = @intCast(msg.len);
    pos += 1;
    @memcpy(script_buf[pos..][0..msg.len], msg);
    pos += msg.len;
    script_buf[pos] = 0xa9;
    pos += 1;
    script_buf[pos] = @intCast(expected_hash.len);
    pos += 1;
    @memcpy(script_buf[pos..][0..expected_hash.len], expected_hash);
    pos += expected_hash.len;
    script_buf[pos] = 0x87;
    pos += 1;

    const script = bsvz.script.Script.init(script_buf[0..pos]);
    var result = try bsvz.script.engine.executeScript(.{ .allocator = allocator }, script);
    defer result.deinit(allocator);
    try std.testing.expect(result.success);
}

// ---------------------------------------------------------------------------
// End-to-end: .runar.zig → frontend parse/validate/typecheck → bsvz verify
// ---------------------------------------------------------------------------

test "end-to-end: Arithmetic contract passes frontend pipeline" {
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const work = arena.allocator();

    const source =
        \\const runar = @import("runar");
        \\
        \\pub const Arithmetic = struct {
        \\    pub const Contract = runar.SmartContract;
        \\
        \\    target: i64,
        \\
        \\    pub fn init(target: i64) Arithmetic {
        \\        return .{ .target = target };
        \\    }
        \\
        \\    pub fn verify(self: *const Arithmetic, a: i64, b: i64) void {
        \\        const sum = a + b;
        \\        const diff = a - b;
        \\        const prod = a * b;
        \\        const result = sum + diff + prod;
        \\        runar.assert(result == self.target);
        \\    }
        \\};
    ;

    const parse_result = frontend.parseZig(work, source, "Arithmetic.runar.zig");
    try std.testing.expectEqual(@as(usize, 0), parse_result.errors.len);
    try std.testing.expect(parse_result.contract != null);

    const contract = parse_result.contract.?;
    const val_result = try frontend.validateContract(work, contract);
    try std.testing.expectEqual(@as(usize, 0), val_result.errors.len);

    const tc_result = try frontend.typeCheck(work, contract);
    try std.testing.expectEqual(@as(usize, 0), tc_result.errors.len);
}

test "end-to-end: P2PKH hash check runs in bsvz engine" {
    // Construct the hash-check portion of what Runar compiles for P2PKH:
    // <pubkey> OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_1
    //
    // This is the non-CHECKSIG part of the P2PKH locking script. CHECKSIG
    // requires a full transaction context (sighash), so we verify the hash
    // check independently. This proves bsvz can execute the stack operations
    // and hash opcodes that Runar contracts compile to.
    const allocator = std.testing.allocator;

    const alice_pubkey = test_keys.ALICE.pubKey;
    const pkh = builtins.hash160(alice_pubkey);

    var script_buf: [256]u8 = undefined;
    var pos: usize = 0;

    // Push pubkey
    script_buf[pos] = @intCast(alice_pubkey.len);
    pos += 1;
    @memcpy(script_buf[pos..][0..alice_pubkey.len], alice_pubkey);
    pos += alice_pubkey.len;

    // OP_DUP OP_HASH160 <20-byte pkh> OP_EQUALVERIFY OP_1
    script_buf[pos] = 0x76;
    pos += 1;
    script_buf[pos] = 0xa9;
    pos += 1;
    script_buf[pos] = 0x14;
    pos += 1;
    @memcpy(script_buf[pos..][0..pkh.len], pkh);
    pos += pkh.len;
    script_buf[pos] = 0x88;
    pos += 1;
    script_buf[pos] = 0x51; // OP_1 — truthy top after EQUALVERIFY consumes
    pos += 1;

    const script = bsvz.script.Script.init(script_buf[0..pos]);
    var result = try bsvz.script.engine.executeScript(.{ .allocator = allocator }, script);
    defer result.deinit(allocator);

    try std.testing.expect(result.success);
}

test "end-to-end: P2PKH hash check rejects wrong pubkey" {
    const allocator = std.testing.allocator;

    const alice_pubkey = test_keys.ALICE.pubKey;
    const pkh = builtins.hash160(alice_pubkey);

    // Use BOB's pubkey but ALICE's hash — should fail EQUALVERIFY
    const bob_pubkey = test_keys.BOB.pubKey;

    var script_buf: [256]u8 = undefined;
    var pos: usize = 0;

    script_buf[pos] = @intCast(bob_pubkey.len);
    pos += 1;
    @memcpy(script_buf[pos..][0..bob_pubkey.len], bob_pubkey);
    pos += bob_pubkey.len;

    script_buf[pos] = 0x76;
    pos += 1;
    script_buf[pos] = 0xa9;
    pos += 1;
    script_buf[pos] = 0x14;
    pos += 1;
    @memcpy(script_buf[pos..][0..pkh.len], pkh);
    pos += pkh.len;
    script_buf[pos] = 0x88;
    pos += 1;
    script_buf[pos] = 0x51;
    pos += 1;

    const script = bsvz.script.Script.init(script_buf[0..pos]);
    const result = bsvz.script.engine.executeScript(.{ .allocator = allocator }, script);
    try std.testing.expectError(error.VerifyFailed, result);
}
