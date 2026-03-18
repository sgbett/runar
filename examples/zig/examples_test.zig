const std = @import("std");
const runtime = @import("runar");

const assert_probe_path = "zig-out/bin/assert_probe";

pub const runar = struct {
    pub fn compileCheckSource(
        allocator: std.mem.Allocator,
        source: []const u8,
        file_name: []const u8,
    ) !void {
        const result = try runtime.compileCheckSource(allocator, source, file_name);
        defer result.deinit(allocator);
        if (!result.ok()) {
            for (result.messages) |message| {
                std.debug.print("compile-check {s}: {s}\n", .{ file_name, message });
            }
            return error.CompileCheckFailed;
        }
    }

    pub fn compileCheckFile(
        allocator: std.mem.Allocator,
        file_path: []const u8,
    ) !void {
        const result = try runtime.compileCheckFile(allocator, file_path);
        defer result.deinit(allocator);
        if (!result.ok()) {
            for (result.messages) |message| {
                std.debug.print("compile-check {s}: {s}\n", .{ file_path, message });
            }
            return error.CompileCheckFailed;
        }
    }

    pub fn expectAssertFailure(
        allocator: std.mem.Allocator,
        probe_case: []const u8,
    ) !void {
        const result = try std.process.Child.run(.{
            .allocator = allocator,
            .argv = &.{ assert_probe_path, probe_case },
            .max_output_bytes = 64 * 1024,
        });
        defer {
            allocator.free(result.stdout);
            allocator.free(result.stderr);
        }

        switch (result.term) {
            .Exited => |code| try std.testing.expect(code != 0),
            .Signal => {},
            else => return error.TestUnexpectedResult,
        }

        const saw_assert_panic =
            std.mem.indexOf(u8, result.stdout, "runar assertion failed") != null or
            std.mem.indexOf(u8, result.stderr, "runar assertion failed") != null;
        try std.testing.expect(saw_assert_panic);
    }
};

pub fn expectAssertFailure(probe_case: []const u8) !void {
    try runar.expectAssertFailure(std.testing.allocator, probe_case);
}

test {
    _ = @import("./auction/Auction_test.zig");
    _ = @import("./blake3/Blake3Test_test.zig");
    _ = @import("./convergence-proof/ConvergenceProof_test.zig");
    _ = @import("./covenant-vault/CovenantVault_test.zig");
    _ = @import("./ec-demo/ECDemo_test.zig");
    _ = @import("./escrow/Escrow_test.zig");
    _ = @import("./function-patterns/FunctionPatterns_test.zig");
    _ = @import("./math-demo/MathDemo_test.zig");
    _ = @import("./oracle-price/OraclePriceFeed_test.zig");
    _ = @import("./p2blake3pkh/P2Blake3PKH_test.zig");
    _ = @import("./p2pkh/P2PKH_test.zig");
    _ = @import("./post-quantum-wallet/PostQuantumWallet_test.zig");
    _ = @import("./property-initializers/BoundedCounter_test.zig");
    _ = @import("./schnorr-zkp/SchnorrZKP_test.zig");
    _ = @import("./sha256-compress/Sha256CompressTest_test.zig");
    _ = @import("./sha256-finalize/Sha256FinalizeTest_test.zig");
    _ = @import("./sphincs-wallet/SPHINCSWallet_test.zig");
    _ = @import("./stateful-counter/Counter_test.zig");
    _ = @import("./tic-tac-toe/TicTacToe_test.zig");
    _ = @import("./token-ft/FungibleTokenExample_test.zig");
    _ = @import("./token-nft/NFTExample_test.zig");
}
