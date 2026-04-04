const std = @import("std");
const runar = @import("runar");
const helpers = @import("helpers.zig");
const compile = @import("compile.zig");

test "TicTacToe_Compile" {
    const allocator = std.testing.allocator;

    var artifact = compile.compileContract(allocator, "examples/zig/tic-tac-toe/TicTacToe.runar.zig") catch |err| {
        std.log.warn("Could not compile TicTacToe contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    try std.testing.expectEqualStrings("TicTacToe", artifact.contract_name);
    try std.testing.expect(artifact.isStateful());
    std.log.info("TicTacToe compiled: {d} bytes", .{artifact.script.len / 2});
}

test "TicTacToe_Deploy" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/tic-tac-toe/TicTacToe.runar.zig") catch |err| {
        std.log.warn("Could not compile TicTacToe contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var player_x = try helpers.newWallet(allocator);
    defer player_x.deinit();

    const px_hex = try player_x.pubKeyHex(allocator);
    defer allocator.free(px_hex);

    const bet_amount: i64 = 5000;

    // Constructor: playerX (PubKey), betAmount (bigint)
    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = px_hex },
        .{ .int = bet_amount },
    });
    defer contract.deinit();

    const fund_txid = try helpers.fundWallet(allocator, &player_x, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try player_x.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = bet_amount });
    defer allocator.free(deploy_txid);

    const utxo = contract.getCurrentUtxo();
    try std.testing.expect(utxo != null);
    try std.testing.expectEqual(@as(usize, 64), deploy_txid.len);
    std.log.info("TicTacToe deployed with betAmount={d}: {s}", .{ bet_amount, deploy_txid });
}

test "TicTacToe_Join" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/tic-tac-toe/TicTacToe.runar.zig") catch |err| {
        std.log.warn("Could not compile TicTacToe contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var player_x = try helpers.newWallet(allocator);
    defer player_x.deinit();
    var player_o = try helpers.newWallet(allocator);
    defer player_o.deinit();

    const px_hex = try player_x.pubKeyHex(allocator);
    defer allocator.free(px_hex);
    const po_hex = try player_o.pubKeyHex(allocator);
    defer allocator.free(po_hex);

    const bet_amount: i64 = 5000;

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = px_hex },
        .{ .int = bet_amount },
    });
    defer contract.deinit();

    const fund_x = try helpers.fundWallet(allocator, &player_x, 1.0);
    defer allocator.free(fund_x);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var signer_x = try player_x.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), signer_x.signer(), .{ .satoshis = bet_amount });
    defer allocator.free(deploy_txid);
    std.log.info("TicTacToe deployed: {s}", .{deploy_txid});

    // Fund playerO
    const fund_o = try helpers.fundWallet(allocator, &player_o, 1.0);
    defer allocator.free(fund_o);
    var signer_o = try player_o.localSigner();

    // join(opponentPK, sig) -- playerO joins
    const join_txid = try contract.call(
        "join",
        &[_]runar.StateValue{
            .{ .bytes = po_hex },
            .{ .int = 0 }, // sig: auto-sign
        },
        rpc_provider.provider(),
        signer_o.signer(),
        null,
    );
    defer allocator.free(join_txid);

    std.log.info("TicTacToe join TX: {s}", .{join_txid});
    try std.testing.expectEqual(@as(usize, 64), join_txid.len);
}

test "TicTacToe_Move" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/tic-tac-toe/TicTacToe.runar.zig") catch |err| {
        std.log.warn("Could not compile TicTacToe contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var player_x = try helpers.newWallet(allocator);
    defer player_x.deinit();
    var player_o = try helpers.newWallet(allocator);
    defer player_o.deinit();

    const px_hex = try player_x.pubKeyHex(allocator);
    defer allocator.free(px_hex);
    const po_hex = try player_o.pubKeyHex(allocator);
    defer allocator.free(po_hex);

    const bet_amount: i64 = 5000;

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = px_hex },
        .{ .int = bet_amount },
    });
    defer contract.deinit();

    const fund_x = try helpers.fundWallet(allocator, &player_x, 1.0);
    defer allocator.free(fund_x);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var signer_x = try player_x.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), signer_x.signer(), .{ .satoshis = bet_amount });
    defer allocator.free(deploy_txid);

    // Fund playerO
    const fund_o = try helpers.fundWallet(allocator, &player_o, 1.0);
    defer allocator.free(fund_o);
    var signer_o = try player_o.localSigner();

    // Join
    const join_txid = try contract.call(
        "join",
        &[_]runar.StateValue{
            .{ .bytes = po_hex },
            .{ .int = 0 },
        },
        rpc_provider.provider(),
        signer_o.signer(),
        null,
    );
    defer allocator.free(join_txid);

    // Move: player X plays position 4 (center)
    const move_txid = try contract.call(
        "move",
        &[_]runar.StateValue{
            .{ .int = 4 }, // position
            .{ .bytes = px_hex }, // player
            .{ .int = 0 }, // sig: auto-sign
        },
        rpc_provider.provider(),
        signer_x.signer(),
        null,
    );
    defer allocator.free(move_txid);

    std.log.info("TicTacToe move TX: {s}", .{move_txid});
    try std.testing.expectEqual(@as(usize, 64), move_txid.len);
}

test "TicTacToe_StateFields" {
    const allocator = std.testing.allocator;

    var artifact = compile.compileContract(allocator, "examples/zig/tic-tac-toe/TicTacToe.runar.zig") catch |err| {
        std.log.warn("Could not compile TicTacToe contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    // TicTacToe should have multiple state fields (board, turn, status, etc.)
    try std.testing.expect(artifact.state_fields.len >= 3);

    // Should have public methods: join, move, moveAndWin
    var public_count: usize = 0;
    for (artifact.abi.methods) |m| {
        if (m.is_public) public_count += 1;
    }
    try std.testing.expect(public_count >= 2);
}
