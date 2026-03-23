const std = @import("std");
const helpers = @import("helpers.zig");

// Import all test modules so the Zig test runner discovers their tests.
comptime {
    _ = @import("p2pkh_test.zig");
    _ = @import("counter_test.zig");
    _ = @import("escrow_test.zig");
    _ = @import("compile.zig");
}

test "integration_setup" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not running. Skipping integration tests.", .{});
        std.log.warn("Start with: cd integration && ./regtest.sh start", .{});
        return;
    }

    // Mine initial blocks so coinbase UTXOs mature (100 block maturity).
    const current_height = helpers.getBlockCount(allocator) catch |err| {
        std.log.err("Failed to get block count: {any}", .{err});
        return;
    };

    const target_height: i64 = 101;
    const blocks_needed = target_height - current_height;
    if (blocks_needed > 0) {
        std.log.info("Mining {d} blocks (current height: {d}, target: {d})...", .{ blocks_needed, current_height, target_height });
        helpers.mine(allocator, blocks_needed) catch |err| {
            std.log.err("Failed to mine initial blocks: {any}", .{err});
            return;
        };
    }

    std.log.info("Integration test setup complete. Block height >= {d}", .{target_height});
}
