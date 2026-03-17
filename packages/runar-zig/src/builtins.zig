const std = @import("std");
const base = @import("base.zig");
const test_keys = @import("test_keys.zig");

const Sha256Hasher = std.crypto.hash.sha2.Sha256;
const Blake3Hasher = std.crypto.hash.Blake3;

const mock_preimage_magic = "RNRP";
const default_zero_20 = [_]u8{0} ** 20;
const default_zero_32 = [_]u8{0} ** 32;
const default_zero_36 = [_]u8{0} ** 36;
const default_zero_64 = [_]u8{0} ** 64;

pub const MockPreimageParts = struct {
    hashPrevouts: base.Sha256 = default_zero_32[0..],
    outpoint: base.ByteString = default_zero_36[0..],
    outputHash: base.Sha256 = default_zero_32[0..],
    locktime: base.Bigint = 0,
};

pub fn assert(condition: bool) void {
    if (!condition) @panic("runar assertion failed");
}

pub fn sha256(data: base.ByteString) base.Sha256 {
    var out: [32]u8 = undefined;
    Sha256Hasher.hash(data, &out, .{});
    return dupeBytes(&out);
}

pub fn ripemd160(data: base.ByteString) base.Ripemd160 {
    const full = sha256(data);
    return dupeBytes(full[0..20]);
}

pub fn hash160(data: base.ByteString) base.Addr {
    const first = sha256(data);
    defer freeIfOwned(first);
    return ripemd160(first);
}

pub fn hash256(data: base.ByteString) base.Sha256 {
    const first = sha256(data);
    defer freeIfOwned(first);
    return sha256(first);
}

pub fn checkSig(sig: base.Sig, pub_key: base.PubKey) bool {
    const expected = signatureForPubKey(pub_key);
    defer freeIfOwned(expected);
    return std.mem.eql(u8, sig, expected);
}

pub fn checkMultiSig(sigs: []const base.Sig, pub_keys: []const base.PubKey) bool {
    if (sigs.len != pub_keys.len) return false;
    for (sigs, pub_keys) |sig, pub_key| {
        if (!checkSig(sig, pub_key)) return false;
    }
    return true;
}

pub fn checkPreimage(preimage: base.SigHashPreimage) bool {
    return preimage.len >= 4 and std.mem.eql(u8, preimage[0..4], mock_preimage_magic);
}

pub fn signTestMessage(pair: test_keys.TestKeyPair) base.Sig {
    return signatureForPubKey(pair.pubKey);
}

pub fn mockPreimage(parts: MockPreimageParts) base.SigHashPreimage {
    var encoded = std.heap.page_allocator.alloc(u8, 4 + 32 + 36 + 32 + 8) catch @panic("OOM");
    @memcpy(encoded[0..4], mock_preimage_magic);
    copyFixed(encoded[4..36], parts.hashPrevouts);
    copyFixed(encoded[36..72], parts.outpoint);
    copyFixed(encoded[72..104], parts.outputHash);
    encodeInt64Le(encoded[104..112], parts.locktime);
    return encoded;
}

pub fn extractHashPrevouts(preimage: base.SigHashPreimage) base.Sha256 {
    return sliceOrZero(preimage, 4, 32);
}

pub fn extractOutpoint(preimage: base.SigHashPreimage) base.ByteString {
    return sliceOrZero(preimage, 36, 36);
}

pub fn extractOutputHash(preimage: base.SigHashPreimage) base.Sha256 {
    return sliceOrZero(preimage, 72, 32);
}

pub fn extractLocktime(preimage: base.SigHashPreimage) base.Bigint {
    if (preimage.len < 112) return 0;
    return decodeInt64Le(preimage[104..112]);
}

pub fn cat(left: base.ByteString, right: base.ByteString) base.ByteString {
    var out = std.heap.page_allocator.alloc(u8, left.len + right.len) catch @panic("OOM");
    @memcpy(out[0..left.len], left);
    @memcpy(out[left.len..], right);
    return out;
}

pub fn substr(bytes: base.ByteString, start: base.Bigint, len: base.Bigint) base.ByteString {
    if (start < 0 or len <= 0) return &.{};
    const start_usize = std.math.cast(usize, start) orelse return &.{};
    const len_usize = std.math.cast(usize, len) orelse return &.{};
    if (start_usize >= bytes.len) return &.{};
    const end_usize = @min(start_usize + len_usize, bytes.len);
    return dupeBytes(bytes[start_usize..end_usize]);
}

pub fn num2bin(value: base.Bigint, size: base.Bigint) base.ByteString {
    const size_usize = std.math.cast(usize, size) orelse return &.{};
    var out = std.heap.page_allocator.alloc(u8, size_usize) catch @panic("OOM");
    @memset(out, 0);

    var magnitude: u64 = @intCast(if (value < 0) -value else value);
    var index: usize = 0;
    while (magnitude != 0 and index < out.len) : (index += 1) {
        out[index] = @truncate(magnitude & 0xff);
        magnitude >>= 8;
    }
    if (value < 0 and out.len != 0) out[out.len - 1] |= 0x80;
    return out;
}

pub fn bin2num(bytes: base.ByteString) base.Bigint {
    if (bytes.len == 0) return 0;
    var tmp = dupeBytes(bytes);
    defer freeIfOwned(tmp);

    const negative = (tmp[tmp.len - 1] & 0x80) != 0;
    tmp[tmp.len - 1] &= 0x7f;

    var magnitude: u64 = 0;
    var shift: usize = 0;
    for (tmp) |byte| {
        magnitude |= @as(u64, byte) << @intCast(shift);
        shift += 8;
    }

    const signed = std.math.cast(i64, magnitude) orelse @panic("magnitude too large");
    return if (negative) -signed else signed;
}

pub fn clamp(value: base.Bigint, lo: base.Bigint, hi: base.Bigint) base.Bigint {
    return @max(lo, @min(hi, value));
}

pub fn safediv(lhs: base.Bigint, rhs: base.Bigint) base.Bigint {
    if (rhs == 0) return 0;
    return @divTrunc(lhs, rhs);
}

pub fn safemod(lhs: base.Bigint, rhs: base.Bigint) base.Bigint {
    if (rhs == 0) return 0;
    return @mod(lhs, rhs);
}

pub fn sign(value: base.Bigint) base.Bigint {
    return if (value < 0) -1 else if (value > 0) 1 else 0;
}

pub fn pow(base_value: base.Bigint, exponent: base.Bigint) base.Bigint {
    if (exponent <= 0) return 1;
    var result: i64 = 1;
    var i: i64 = 0;
    while (i < exponent) : (i += 1) {
        result *= base_value;
    }
    return result;
}

pub fn mulDiv(a: base.Bigint, b: base.Bigint, divisor: base.Bigint) base.Bigint {
    if (divisor == 0) return 0;
    return @divTrunc(a * b, divisor);
}

pub fn percentOf(value: base.Bigint, percentage: base.Bigint) base.Bigint {
    return @divTrunc(value * percentage, 100);
}

pub fn sqrt(value: base.Bigint) base.Bigint {
    if (value <= 0) return 0;
    var x = value;
    var y = @divTrunc(x + 1, 2);
    while (y < x) {
        x = y;
        y = @divTrunc(y + @divTrunc(value, y), 2);
    }
    return x;
}

pub fn gcd(a: base.Bigint, b: base.Bigint) base.Bigint {
    var x = if (a < 0) -a else a;
    var y = if (b < 0) -b else b;
    while (y != 0) {
        const next = @mod(x, y);
        x = y;
        y = next;
    }
    return x;
}

pub fn log2(value: base.Bigint) base.Bigint {
    if (value <= 1) return 0;
    var count: i64 = 0;
    var current = value;
    while (current > 1) : (count += 1) {
        current = @divTrunc(current, 2);
    }
    return count;
}

pub fn sha256Compress(chaining_value: base.ByteString, block: base.ByteString) base.ByteString {
    const joined = cat(chaining_value, block);
    defer freeIfOwned(joined);
    return sha256(joined);
}

pub fn sha256Finalize(chaining_value: base.ByteString, block: base.ByteString, total_len: base.Bigint) base.ByteString {
    const joined = cat(chaining_value, block);
    defer freeIfOwned(joined);
    const encoded_len = num2bin(total_len, 8);
    defer freeIfOwned(encoded_len);
    const payload = cat(joined, encoded_len);
    defer freeIfOwned(payload);
    return sha256(payload);
}

pub fn blake3Compress(chaining_value: base.ByteString, block: base.ByteString) base.ByteString {
    const joined = cat(chaining_value, block);
    defer freeIfOwned(joined);
    return blake3Hash(joined);
}

pub fn blake3Hash(message: base.ByteString) base.ByteString {
    var out: [32]u8 = undefined;
    Blake3Hasher.hash(message, &out, .{});
    return dupeBytes(&out);
}

pub fn verifyRabinSig(message: base.ByteString, sig: base.RabinSig, padding: base.ByteString, pub_key: base.RabinPubKey) bool {
    _ = message;
    _ = padding;
    return sig.len != 0 and pub_key.len != 0;
}

pub fn verifyWOTS(message: base.ByteString, sig: base.ByteString, pub_key: base.ByteString) bool {
    return message.len != 0 and sig.len != 0 and pub_key.len != 0;
}

pub fn verifySLHDSA_SHA2_128s(message: base.ByteString, sig: base.ByteString, pub_key: base.ByteString) bool {
    return verifyWOTS(message, sig, pub_key);
}

pub fn verifySLHDSA_SHA2_128f(message: base.ByteString, sig: base.ByteString, pub_key: base.ByteString) bool {
    return verifyWOTS(message, sig, pub_key);
}

pub fn verifySLHDSA_SHA2_192s(message: base.ByteString, sig: base.ByteString, pub_key: base.ByteString) bool {
    return verifyWOTS(message, sig, pub_key);
}

pub fn verifySLHDSA_SHA2_192f(message: base.ByteString, sig: base.ByteString, pub_key: base.ByteString) bool {
    return verifyWOTS(message, sig, pub_key);
}

pub fn verifySLHDSA_SHA2_256s(message: base.ByteString, sig: base.ByteString, pub_key: base.ByteString) bool {
    return verifyWOTS(message, sig, pub_key);
}

pub fn verifySLHDSA_SHA2_256f(message: base.ByteString, sig: base.ByteString, pub_key: base.ByteString) bool {
    return verifyWOTS(message, sig, pub_key);
}

pub fn ecMakePoint(x: base.Bigint, y: base.Bigint) base.Point {
    const x_bytes = num2bin(x, 32);
    defer freeIfOwned(x_bytes);
    const y_bytes = num2bin(y, 32);
    defer freeIfOwned(y_bytes);
    return cat(x_bytes, y_bytes);
}

pub fn ecPointX(point: base.Point) base.Bigint {
    return bin2num(substr(point, 0, 32));
}

pub fn ecPointY(point: base.Point) base.Bigint {
    return bin2num(substr(point, 32, 32));
}

pub fn ecAdd(left: base.Point, right: base.Point) base.Point {
    return ecMakePoint(ecPointX(left) + ecPointX(right), ecPointY(left) + ecPointY(right));
}

pub fn ecMul(point: base.Point, scalar: base.Bigint) base.Point {
    return ecMakePoint(ecPointX(point) * scalar, ecPointY(point) * scalar);
}

pub fn ecMulGen(scalar: base.Bigint) base.Point {
    return ecMakePoint(scalar, scalar + 1);
}

pub fn ecNegate(point: base.Point) base.Point {
    return ecMakePoint(ecPointX(point), -ecPointY(point));
}

pub fn ecOnCurve(point: base.Point) bool {
    return point.len == 64;
}

pub fn ecModReduce(value: base.Bigint, modulus: base.Bigint) base.Bigint {
    if (modulus == 0) return 0;
    const reduced = @mod(value, modulus);
    return if (reduced < 0) reduced + modulus else reduced;
}

pub fn ecEncodeCompressed(point: base.Point) base.ByteString {
    const prefix = if (@mod(ecPointY(point), 2) == 0) &[_]u8{0x02} else &[_]u8{0x03};
    const x_bytes = substr(point, 0, 32);
    defer freeIfOwned(x_bytes);
    return cat(prefix, x_bytes);
}

fn signatureForPubKey(pub_key: base.PubKey) base.Sig {
    const payload = cat(pub_key, "runar:test-message");
    defer freeIfOwned(payload);
    return hash256(payload);
}

fn dupeBytes(bytes: []const u8) []const u8 {
    return std.heap.page_allocator.dupe(u8, bytes) catch @panic("OOM");
}

fn freeIfOwned(bytes: []const u8) void {
    if (bytes.len == 0) return;
    const addr = @intFromPtr(bytes.ptr);
    const static_addrs = [_]usize{
        @intFromPtr(default_zero_20[0..].ptr),
        @intFromPtr(default_zero_32[0..].ptr),
        @intFromPtr(default_zero_36[0..].ptr),
        @intFromPtr(default_zero_64[0..].ptr),
        @intFromPtr(mock_preimage_magic.ptr),
    };
    for (static_addrs) |static_addr| {
        if (addr == static_addr) return;
    }
    std.heap.page_allocator.free(bytes);
}

fn copyFixed(dest: []u8, source: []const u8) void {
    const count = @min(dest.len, source.len);
    @memset(dest, 0);
    @memcpy(dest[0..count], source[0..count]);
}

fn sliceOrZero(bytes: []const u8, start: usize, len: usize) []const u8 {
    if (bytes.len < start + len) {
        return dupeBytes(([_]u8{0} ** 32)[0..len]);
    }
    return dupeBytes(bytes[start .. start + len]);
}

fn encodeInt64Le(dest: []u8, value: i64) void {
    const tmp = @as(u64, @bitCast(value));
    for (dest, 0..) |*byte, index| {
        byte.* = @truncate(tmp >> @intCast(index * 8));
    }
}

fn decodeInt64Le(bytes: []const u8) i64 {
    var value: u64 = 0;
    for (bytes, 0..) |byte, index| {
        value |= @as(u64, byte) << @intCast(index * 8);
    }
    return @bitCast(value);
}

test "sign fixtures round trip through checkSig" {
    const sig = signTestMessage(test_keys.ALICE);
    defer freeIfOwned(sig);

    try std.testing.expect(checkSig(sig, test_keys.ALICE.pubKey));
    try std.testing.expect(!checkSig(sig, test_keys.BOB.pubKey));
}

test "mock preimage extractors round trip" {
    const expected_hash = hash256("prevouts");
    defer freeIfOwned(expected_hash);
    const preimage = mockPreimage(.{
        .hashPrevouts = expected_hash,
        .outpoint = "outpoint-data",
        .outputHash = hash256("outputs"),
        .locktime = 500,
    });
    defer freeIfOwned(preimage);

    const extracted_hash = extractHashPrevouts(preimage);
    defer freeIfOwned(extracted_hash);
    try std.testing.expect(std.mem.eql(u8, extracted_hash, expected_hash));
    try std.testing.expectEqual(@as(i64, 500), extractLocktime(preimage));
}
