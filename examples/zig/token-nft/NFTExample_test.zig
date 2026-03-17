const std = @import("std");

const root = @import("../examples_test.zig");

const contract_source = @embedFile("NFTExample.runar.zig");

const NFTMirror = struct {
    owner: i64,

    fn transfer(self: *NFTMirror, authorized: bool, new_owner: i64, output_satoshis: i64) !void {
        if (!authorized) return error.Unauthorized;
        if (output_satoshis < 1) return error.InvalidSatoshis;
        self.owner = new_owner;
    }

    fn burn(self: *const NFTMirror, authorized: bool) !void {
        _ = self;
        if (!authorized) return error.Unauthorized;
    }
};

test "compile-check NFTExample.runar.zig" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "NFTExample.runar.zig", .data = contract_source });

    const path = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..], "NFTExample.runar.zig" });
    defer allocator.free(path);
    try root.runar.compileCheckFile(allocator, path);
    try root.runar.compileCheckSource(allocator, contract_source, "NFTExample.runar.zig");
}

test "nft mirror transfer changes owner when authorized" {
    var nft = NFTMirror{ .owner = 1 };
    try nft.transfer(true, 2, 1);
    try std.testing.expectEqual(@as(i64, 2), nft.owner);
}

test "nft mirror enforces authorization for transfer and burn" {
    var nft = NFTMirror{ .owner = 1 };
    try std.testing.expectError(error.Unauthorized, nft.transfer(false, 2, 1));
    try std.testing.expectError(error.Unauthorized, nft.burn(false));
}
