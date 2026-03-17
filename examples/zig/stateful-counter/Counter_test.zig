const std = @import("std");

const root = @import("../examples_test.zig");

const contract_source = @embedFile("Counter.runar.zig");

const CounterMirror = struct {
    count: i64,

    fn increment(self: *CounterMirror) void {
        self.count += 1;
    }

    fn decrement(self: *CounterMirror) !void {
        if (self.count <= 0) return error.CounterUnderflow;
        self.count -= 1;
    }
};

test "compile-check Counter.runar.zig" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "Counter.runar.zig", .data = contract_source });

    const path = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..], "Counter.runar.zig" });
    defer allocator.free(path);
    try root.runar.compileCheckFile(allocator, path);
    try root.runar.compileCheckSource(allocator, contract_source, "Counter.runar.zig");
}

test "counter mirror increments and decrements" {
    var counter = CounterMirror{ .count = 2 };

    counter.increment();
    try std.testing.expectEqual(@as(i64, 3), counter.count);

    try counter.decrement();
    try std.testing.expectEqual(@as(i64, 2), counter.count);
}

test "counter mirror rejects decrement at zero" {
    var counter = CounterMirror{ .count = 0 };
    try std.testing.expectError(error.CounterUnderflow, counter.decrement());
}
