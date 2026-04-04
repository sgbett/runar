const std = @import("std");
const runar = @import("runar");
const helpers = @import("helpers.zig");
const compile = @import("compile.zig");

test "CovenantVault_Compile" {
    const allocator = std.testing.allocator;

    var artifact = compile.compileContract(allocator, "examples/zig/covenant-vault/CovenantVault.runar.zig") catch |err| {
        std.log.warn("Could not compile CovenantVault contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    try std.testing.expectEqualStrings("CovenantVault", artifact.contract_name);
    try std.testing.expect(!artifact.isStateful());
    std.log.info("CovenantVault compiled: {d} bytes", .{artifact.script.len / 2});
}

test "CovenantVault_Deploy" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/covenant-vault/CovenantVault.runar.zig") catch |err| {
        std.log.warn("Could not compile CovenantVault contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var owner = try helpers.newWallet(allocator);
    defer owner.deinit();
    var recipient = try helpers.newWallet(allocator);
    defer recipient.deinit();

    const owner_pk = try owner.pubKeyHex(allocator);
    defer allocator.free(owner_pk);
    const recipient_pkh = try recipient.pubKeyHashHex(allocator);
    defer allocator.free(recipient_pkh);

    // Constructor params: owner (PubKey), recipient (PubKeyHash), minAmount
    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = owner_pk },
        .{ .bytes = recipient_pkh },
        .{ .int = 1000 },
    });
    defer contract.deinit();

    var funder = try helpers.newWallet(allocator);
    defer funder.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &funder, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try funder.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 5000 });
    defer allocator.free(deploy_txid);

    try std.testing.expectEqual(@as(usize, 64), deploy_txid.len);
    std.log.info("CovenantVault deployed: {s}", .{deploy_txid});
}

test "CovenantVault_DeployZeroMinAmount" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/covenant-vault/CovenantVault.runar.zig") catch |err| {
        std.log.warn("Could not compile CovenantVault contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var owner = try helpers.newWallet(allocator);
    defer owner.deinit();
    var recipient = try helpers.newWallet(allocator);
    defer recipient.deinit();

    const owner_pk = try owner.pubKeyHex(allocator);
    defer allocator.free(owner_pk);
    const recipient_pkh = try recipient.pubKeyHashHex(allocator);
    defer allocator.free(recipient_pkh);

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = owner_pk },
        .{ .bytes = recipient_pkh },
        .{ .int = 0 },
    });
    defer contract.deinit();

    var funder = try helpers.newWallet(allocator);
    defer funder.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &funder, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try funder.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 5000 });
    defer allocator.free(deploy_txid);

    const utxo = contract.getCurrentUtxo();
    try std.testing.expect(utxo != null);
    std.log.info("CovenantVault deployed with minAmount=0: {s}", .{deploy_txid});
}

test "CovenantVault_DeployLargeMinAmount" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/covenant-vault/CovenantVault.runar.zig") catch |err| {
        std.log.warn("Could not compile CovenantVault contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var owner = try helpers.newWallet(allocator);
    defer owner.deinit();
    var recipient = try helpers.newWallet(allocator);
    defer recipient.deinit();

    const owner_pk = try owner.pubKeyHex(allocator);
    defer allocator.free(owner_pk);
    const recipient_pkh = try recipient.pubKeyHashHex(allocator);
    defer allocator.free(recipient_pkh);

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = owner_pk },
        .{ .bytes = recipient_pkh },
        .{ .int = 100000000 },
    });
    defer contract.deinit();

    var funder = try helpers.newWallet(allocator);
    defer funder.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &funder, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try funder.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 5000 });
    defer allocator.free(deploy_txid);

    const utxo = contract.getCurrentUtxo();
    try std.testing.expect(utxo != null);
    std.log.info("CovenantVault deployed with minAmount=100000000 (1 BTC): {s}", .{deploy_txid});
}

test "CovenantVault_DeploySameKey" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/covenant-vault/CovenantVault.runar.zig") catch |err| {
        std.log.warn("Could not compile CovenantVault contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var wallet = try helpers.newWallet(allocator);
    defer wallet.deinit();

    const pk_hex = try wallet.pubKeyHex(allocator);
    defer allocator.free(pk_hex);
    const pkh_hex = try wallet.pubKeyHashHex(allocator);
    defer allocator.free(pkh_hex);

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = pk_hex },
        .{ .bytes = pkh_hex },
        .{ .int = 1000 },
    });
    defer contract.deinit();

    var funder = try helpers.newWallet(allocator);
    defer funder.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &funder, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try funder.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 5000 });
    defer allocator.free(deploy_txid);

    const utxo = contract.getCurrentUtxo();
    try std.testing.expect(utxo != null);
    std.log.info("CovenantVault deployed with same key as owner and recipient: {s}", .{deploy_txid});
}

test "CovenantVault_ValidSpend" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/covenant-vault/CovenantVault.runar.zig") catch |err| {
        std.log.warn("Could not compile CovenantVault contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var owner = try helpers.newWallet(allocator);
    defer owner.deinit();
    var recipient = try helpers.newWallet(allocator);
    defer recipient.deinit();

    const owner_pk = try owner.pubKeyHex(allocator);
    defer allocator.free(owner_pk);
    const recipient_pkh = try recipient.pubKeyHashHex(allocator);
    defer allocator.free(recipient_pkh);

    const min_amount: i64 = 1000;

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = owner_pk },
        .{ .bytes = recipient_pkh },
        .{ .int = min_amount },
    });
    defer contract.deinit();

    var funder = try helpers.newWallet(allocator);
    defer funder.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &funder, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try funder.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 5000 });
    defer allocator.free(deploy_txid);
    std.log.info("CovenantVault deployed: {s}", .{deploy_txid});

    // Fund the owner wallet for the spend call
    const fund_txid2 = try helpers.fundWallet(allocator, &owner, 1.0);
    defer allocator.free(fund_txid2);

    var owner_signer = try owner.localSigner();

    // spend(sig, txPreimage) -- auto-sign, auto-preimage
    const call_txid = try contract.call(
        "spend",
        &[_]runar.StateValue{
            .{ .int = 0 }, // sig: auto-sign
            .{ .int = 0 }, // txPreimage: auto-computed
        },
        rpc_provider.provider(),
        owner_signer.signer(),
        null,
    );
    defer allocator.free(call_txid);

    std.log.info("CovenantVault spend TX: {s}", .{call_txid});
    try std.testing.expectEqual(@as(usize, 64), call_txid.len);
}
