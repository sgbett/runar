const std = @import("std");

const root = @import("../examples_test.zig");

const contract_source = @embedFile("Auction.runar.zig");

const AuctionMirror = struct {
    highest_bidder: i64,
    highest_bid: i64,
    deadline: i64,

    fn bid(self: *AuctionMirror, bidder: i64, bid_amount: i64, locktime: i64) !void {
        if (bid_amount <= self.highest_bid) return error.BidTooLow;
        if (locktime >= self.deadline) return error.AuctionClosed;
        self.highest_bidder = bidder;
        self.highest_bid = bid_amount;
    }

    fn close(self: *const AuctionMirror, locktime: i64) !void {
        if (locktime < self.deadline) return error.TooEarly;
    }
};

test "compile-check Auction.runar.zig" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "Auction.runar.zig", .data = contract_source });

    const path = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..], "Auction.runar.zig" });
    defer allocator.free(path);
    try root.runar.compileCheckFile(allocator, path);
    try root.runar.compileCheckSource(allocator, contract_source, "Auction.runar.zig");
}

test "auction mirror accepts a higher bid before deadline" {
    var auction = AuctionMirror{
        .highest_bidder = 1,
        .highest_bid = 100,
        .deadline = 500,
    };

    try auction.bid(2, 150, 499);
    try std.testing.expectEqual(@as(i64, 2), auction.highest_bidder);
    try std.testing.expectEqual(@as(i64, 150), auction.highest_bid);
}

test "auction mirror rejects late close and low bids" {
    var auction = AuctionMirror{
        .highest_bidder = 1,
        .highest_bid = 100,
        .deadline = 500,
    };

    try std.testing.expectError(error.BidTooLow, auction.bid(2, 100, 200));
    try std.testing.expectError(error.AuctionClosed, auction.bid(2, 150, 500));
    try std.testing.expectError(error.TooEarly, auction.close(499));
    try auction.close(500);
}
