const std = @import("std");
const builtin = @import("builtin");

pub fn main() !void {
    var passed: usize = 0;
    var failed: usize = 0;
    var skipped: usize = 0;

    for (builtin.test_functions) |t| {
        if (t.func()) |_| {
            std.debug.print("  test {s} ... \x1b[32mok\x1b[0m\n", .{t.name});
            passed += 1;
        } else |err| {
            if (err == error.SkipZigTest) {
                std.debug.print("  test {s} ... \x1b[33mskipped\x1b[0m\n", .{t.name});
                skipped += 1;
            } else {
                std.debug.print("  test {s} ... \x1b[31mFAIL ({s})\x1b[0m\n", .{ t.name, @errorName(err) });
                failed += 1;
            }
        }
    }

    std.debug.print("\n{d} passed, {d} failed, {d} skipped ({d} total)\n", .{
        passed,
        failed,
        skipped,
        passed + failed + skipped,
    });

    if (failed > 0) {
        return error.TestsFailed;
    }
}
