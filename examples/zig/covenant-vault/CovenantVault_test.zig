const std = @import("std");

const root = @import("../examples_test.zig");

const contract_source = @embedFile("CovenantVault.runar.zig");

fn encodeAmountLE(amount: i64) [8]u8 {
    var value: u64 = @intCast(amount);
    var out = [_]u8{0} ** 8;
    for (0..out.len) |i| {
        out[i] = @intCast(value & 0xff);
        value >>= 8;
    }
    return out;
}

const CovenantVaultMirror = struct {
    recipient: [20]u8,
    min_amount: i64,

    fn buildExpectedOutput(self: *const CovenantVaultMirror) [34]u8 {
        var out = [_]u8{0} ** 34;
        const amount = encodeAmountLE(self.min_amount);

        @memcpy(out[0..8], amount[0..]);
        out[8] = 0x19;
        out[9] = 0x76;
        out[10] = 0xa9;
        out[11] = 0x14;
        @memcpy(out[12..32], self.recipient[0..]);
        out[32] = 0x88;
        out[33] = 0xac;
        return out;
    }
};

test "compile-check CovenantVault.runar.zig" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "CovenantVault.runar.zig", .data = contract_source });

    const path = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..], "CovenantVault.runar.zig" });
    defer allocator.free(path);
    try root.runar.compileCheckFile(allocator, path);
    try root.runar.compileCheckSource(allocator, contract_source, "CovenantVault.runar.zig");
}

test "covenant vault mirror builds expected p2pkh output bytes" {
    const recipient = [_]u8{
        0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14,
    };
    const vault = CovenantVaultMirror{
        .recipient = recipient,
        .min_amount = 5000,
    };

    const output = vault.buildExpectedOutput();
    try std.testing.expectEqual(@as(usize, 34), output.len);
    try std.testing.expectEqual(@as(u8, 0x19), output[8]);
    try std.testing.expectEqual(@as(u8, 0x76), output[9]);
    try std.testing.expectEqual(@as(u8, 0xa9), output[10]);
    try std.testing.expectEqual(@as(u8, 0x14), output[11]);
    try std.testing.expectEqualSlices(u8, recipient[0..], output[12..32]);
    try std.testing.expectEqual(@as(u8, 0x88), output[32]);
    try std.testing.expectEqual(@as(u8, 0xac), output[33]);
}
