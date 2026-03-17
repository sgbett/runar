const std = @import("std");
const runtime = @import("runar");

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
};

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
