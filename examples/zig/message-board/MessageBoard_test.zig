const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const MessageBoard = @import("MessageBoard.runar.zig").MessageBoard;

const contract_source = @embedFile("MessageBoard.runar.zig");

test "compile-check MessageBoard.runar.zig" {
    const allocator = std.testing.allocator;
    try root.runar.compileCheckSource(allocator, contract_source, "MessageBoard.runar.zig");
}

test "MessageBoard init stores message and owner" {
    const owner = runar.ALICE.pubKey;
    const board = MessageBoard.init("48656c6c6f", owner);
    try std.testing.expectEqualSlices(u8, "48656c6c6f", board.message);
    try std.testing.expectEqualSlices(u8, owner, board.owner);
}

test "MessageBoard post updates message" {
    var board = MessageBoard.init("00", runar.ALICE.pubKey);
    board.post("48656c6c6f");
    try std.testing.expectEqualSlices(u8, "48656c6c6f", board.message);
}

test "MessageBoard burn succeeds with owner signature" {
    const board = MessageBoard.init("00", runar.ALICE.pubKey);
    board.burn(runar.signTestMessage(runar.ALICE));
}
