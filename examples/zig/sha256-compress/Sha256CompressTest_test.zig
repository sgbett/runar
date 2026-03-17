const std = @import("std");
const root = @import("../examples_test.zig");

fn contractPath(comptime basename: []const u8) []const u8 {
    return "sha256-compress/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}
const MirrorSha256CompressTest = struct {
    expected: []const u8,

    fn init(expected: []const u8) MirrorSha256CompressTest {
        return .{ .expected = expected };
    }

    fn verify(self: MirrorSha256CompressTest, compressed: []const u8) bool {
        return std.mem.eql(u8, self.expected, compressed);
    }
};

test "compile-check Sha256CompressTest.runar.zig" {
    try runCompileChecks("Sha256CompressTest.runar.zig");
}

test "Sha256CompressTest stores expected compressed state" {
    const expected = "compressed-state";
    const contract = MirrorSha256CompressTest.init(expected);
    try std.testing.expectEqualStrings(expected, contract.expected);
}

test "Sha256CompressTest verify compares builtin output to expected bytes" {
    const expected = "compressed-state";
    const contract = MirrorSha256CompressTest.init(expected);

    try std.testing.expect(contract.verify(expected));
    try std.testing.expect(!contract.verify("different-state"));
}
