const std = @import("std");

const root = @import("../examples_test.zig");

const contract_source = @embedFile("TicTacToe.runar.zig");

const TicTacToeMirror = struct {
    board: [9]u8 = [_]u8{0} ** 9,
    turn: u8 = 0,
    status: u8 = 0,

    fn join(self: *TicTacToeMirror) !void {
        if (self.status != 0) return error.AlreadyJoined;
        self.status = 1;
        self.turn = 1;
    }

    fn move(self: *TicTacToeMirror, position: usize, player: u8) !void {
        if (self.status != 1) return error.NotActive;
        if (position >= self.board.len) return error.InvalidPosition;
        if (self.turn != player) return error.WrongTurn;
        if (self.board[position] != 0) return error.CellOccupied;

        self.board[position] = player;
        self.turn = if (player == 1) 2 else 1;
    }

    fn checkWinAfterMove(self: *const TicTacToeMirror, position: usize, player: u8) bool {
        if (position >= self.board.len) return false;
        if (self.board[position] != 0 and self.board[position] != player) return false;

        var board = self.board;
        board[position] = player;

        const lines = [_][3]usize{
            .{ 0, 1, 2 },
            .{ 3, 4, 5 },
            .{ 6, 7, 8 },
            .{ 0, 3, 6 },
            .{ 1, 4, 7 },
            .{ 2, 5, 8 },
            .{ 0, 4, 8 },
            .{ 2, 4, 6 },
        };

        for (lines) |line| {
            if (board[line[0]] == player and board[line[1]] == player and board[line[2]] == player) {
                return true;
            }
        }
        return false;
    }

    fn countOccupied(self: *const TicTacToeMirror) i64 {
        var count: i64 = 0;
        for (self.board) |cell| {
            if (cell != 0) count += 1;
        }
        return count;
    }
};

test "compile-check TicTacToe.runar.zig" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "TicTacToe.runar.zig", .data = contract_source });

    const path = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..], "TicTacToe.runar.zig" });
    defer allocator.free(path);
    try root.runar.compileCheckFile(allocator, path);
    try root.runar.compileCheckSource(allocator, contract_source, "TicTacToe.runar.zig");
}

test "tic tac toe mirror joins and alternates turns" {
    var game = TicTacToeMirror{};
    try game.join();
    try std.testing.expectEqual(@as(u8, 1), game.status);
    try std.testing.expectEqual(@as(u8, 1), game.turn);

    try game.move(0, 1);
    try std.testing.expectEqual(@as(u8, 1), game.board[0]);
    try std.testing.expectEqual(@as(u8, 2), game.turn);

    try game.move(4, 2);
    try std.testing.expectEqual(@as(u8, 2), game.board[4]);
    try std.testing.expectEqual(@as(u8, 1), game.turn);
}

test "tic tac toe mirror detects wins and occupied count" {
    var game = TicTacToeMirror{
        .board = .{ 1, 1, 0, 2, 2, 0, 0, 0, 0 },
        .status = 1,
        .turn = 1,
    };

    try std.testing.expect(game.checkWinAfterMove(2, 1));
    try std.testing.expectEqual(@as(i64, 4), game.countOccupied());

    try game.move(2, 1);
    try std.testing.expectEqual(@as(i64, 5), game.countOccupied());
}
