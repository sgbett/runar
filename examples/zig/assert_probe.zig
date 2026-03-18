const std = @import("std");
const runar = @import("runar");

pub fn main() !void {
    var args = std.process.args();
    _ = args.next(); // skip exe name
    const case = args.next() orelse {
        std.debug.print("usage: assert_probe <case>\n", .{});
        std.process.exit(2);
    };

    if (std.mem.eql(u8, case, "assert_false")) {
        runar.assert(false);
    } else if (std.mem.eql(u8, case, "assert_true")) {
        runar.assert(true);
    } else {
        std.debug.print("unknown case: {s}\n", .{case});
        std.process.exit(2);
    }
}
