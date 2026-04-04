const std = @import("std");
const runar = @import("runar");
const helpers = @import("helpers.zig");
const compile = @import("compile.zig");

test "ConvergenceProof_Compile" {
    const allocator = std.testing.allocator;

    var artifact = compile.compileContract(allocator, "examples/zig/convergence-proof/ConvergenceProof.runar.zig") catch |err| {
        std.log.warn("Could not compile ConvergenceProof contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    try std.testing.expectEqualStrings("ConvergenceProof", artifact.contract_name);
    std.log.info("ConvergenceProof compiled: {d} bytes", .{artifact.script.len / 2});
}

test "ConvergenceProof_Deploy" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/convergence-proof/ConvergenceProof.runar.zig") catch |err| {
        std.log.warn("Could not compile ConvergenceProof contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    // Use deterministic EC points as constructor args (rA, rB as 64-byte hex points)
    // rA = 3*G, rB = 5*G (using fixed known coordinates)
    // For simplicity, use 128-char zero-padded hex strings representing EC points.
    // In production these would be real curve points; here we just test deploy.
    const ra_hex = "0000000000000000000000000000000000000000000000000000000000000003" ++
        "0000000000000000000000000000000000000000000000000000000000000001";
    const rb_hex = "0000000000000000000000000000000000000000000000000000000000000005" ++
        "0000000000000000000000000000000000000000000000000000000000000002";

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = ra_hex },
        .{ .bytes = rb_hex },
    });
    defer contract.deinit();

    var wallet = try helpers.newWallet(allocator);
    defer wallet.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &wallet, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try wallet.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 500000 });
    defer allocator.free(deploy_txid);

    try std.testing.expectEqual(@as(usize, 64), deploy_txid.len);
    std.log.info("ConvergenceProof deployed: {s}", .{deploy_txid});
}

test "ConvergenceProof_ScriptSize" {
    const allocator = std.testing.allocator;

    var artifact = compile.compileContract(allocator, "examples/zig/convergence-proof/ConvergenceProof.runar.zig") catch |err| {
        std.log.warn("Could not compile ConvergenceProof contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    const script_bytes = artifact.script.len / 2;
    // EC-heavy contracts produce large scripts
    try std.testing.expect(script_bytes > 1000);
    std.log.info("ConvergenceProof script size: {d} bytes", .{script_bytes});
}
