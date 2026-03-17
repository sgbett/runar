const std = @import("std");
const root = @import("../examples_test.zig");

fn contractPath(comptime basename: []const u8) []const u8 {
    return "escrow/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}
const MirrorEscrow = struct {
    buyer: []const u8,
    seller: []const u8,
    arbiter: []const u8,

    fn init(buyer: []const u8, seller: []const u8, arbiter: []const u8) MirrorEscrow {
        return .{
            .buyer = buyer,
            .seller = seller,
            .arbiter = arbiter,
        };
    }

    fn release(self: MirrorEscrow, seller_sig_ok: bool, arbiter_sig_ok: bool) bool {
        _ = self;
        return seller_sig_ok and arbiter_sig_ok;
    }

    fn refund(self: MirrorEscrow, buyer_sig_ok: bool, arbiter_sig_ok: bool) bool {
        _ = self;
        return buyer_sig_ok and arbiter_sig_ok;
    }
};

test "compile-check Escrow.runar.zig" {
    try runCompileChecks("Escrow.runar.zig");
}

test "Escrow init stores all parties" {
    const contract = MirrorEscrow.init("buyer", "seller", "arbiter");
    try std.testing.expectEqualStrings("buyer", contract.buyer);
    try std.testing.expectEqualStrings("seller", contract.seller);
    try std.testing.expectEqualStrings("arbiter", contract.arbiter);
}

test "Escrow release and refund require both signatures" {
    const contract = MirrorEscrow.init("buyer", "seller", "arbiter");

    try std.testing.expect(contract.release(true, true));
    try std.testing.expect(!contract.release(true, false));
    try std.testing.expect(contract.refund(true, true));
    try std.testing.expect(!contract.refund(false, true));
}
