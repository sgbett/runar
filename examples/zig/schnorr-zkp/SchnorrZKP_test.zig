const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const SchnorrZKP = @import("SchnorrZKP.runar.zig").SchnorrZKP;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "schnorr-zkp/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check SchnorrZKP.runar.zig" {
    try runCompileChecks("SchnorrZKP.runar.zig");
}

test "SchnorrZKP init stores pubKey" {
    const pub_key = runar.ecMulGen(11);
    const contract = SchnorrZKP.init(pub_key);
    try std.testing.expectEqual(runar.ecPointX(pub_key), runar.ecPointX(contract.pubKey));
    try std.testing.expectEqual(runar.ecPointY(pub_key), runar.ecPointY(contract.pubKey));
}

test "SchnorrZKP rejects invalid points" {
    try root.expectAssertFailure("schnorr-zkp-invalid-r-point");
}
