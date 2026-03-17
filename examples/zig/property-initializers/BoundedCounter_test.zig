const std = @import("std");

const root = @import("../examples_test.zig");

const contract_source = @embedFile("BoundedCounter.runar.zig");

const BoundedCounterMirror = struct {
    count: i64 = 0,
    max_count: i64,
    active: bool = true,

    fn increment(self: *BoundedCounterMirror, amount: i64) !void {
        if (!self.active) return error.Inactive;
        const next = self.count + amount;
        if (next > self.max_count) return error.CountOverflow;
        self.count = next;
    }

    fn reset(self: *BoundedCounterMirror) void {
        self.count = 0;
    }
};

test "compile-check BoundedCounter.runar.zig" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "BoundedCounter.runar.zig", .data = contract_source });

    const path = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..], "BoundedCounter.runar.zig" });
    defer allocator.free(path);
    try root.runar.compileCheckFile(allocator, path);
    try root.runar.compileCheckSource(allocator, contract_source, "BoundedCounter.runar.zig");
}

test "bounded counter defaults active and resets" {
    var counter = BoundedCounterMirror{ .max_count = 10 };
    try std.testing.expect(counter.active);
    try std.testing.expectEqual(@as(i64, 0), counter.count);

    try counter.increment(4);
    try std.testing.expectEqual(@as(i64, 4), counter.count);

    counter.reset();
    try std.testing.expectEqual(@as(i64, 0), counter.count);
}

test "bounded counter enforces active flag and max" {
    var counter = BoundedCounterMirror{ .max_count = 5 };
    try counter.increment(5);
    try std.testing.expectEqual(@as(i64, 5), counter.count);
    try std.testing.expectError(error.CountOverflow, counter.increment(1));

    counter.active = false;
    try std.testing.expectError(error.Inactive, counter.increment(1));
}
