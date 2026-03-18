const std = @import("std");

pub const Int = i64;
pub const Bigint = i64;
pub const PubKey = []const u8;
pub const Sig = []const u8;
pub const Addr = []const u8;
pub const ByteString = []const u8;
pub const Sha256 = []const u8;
pub const Ripemd160 = []const u8;
pub const SigHashPreimage = []const u8;
pub const RabinSig = []const u8;
pub const RabinPubKey = []const u8;
pub const Point = []const u8;

pub fn Readonly(comptime T: type) type {
    return T;
}

pub const OutputValue = union(enum) {
    bigint: Bigint,
    boolean: bool,
    bytes: ByteString,

    pub fn deinit(self: OutputValue, allocator: std.mem.Allocator) void {
        switch (self) {
            .bytes => |bytes| allocator.free(bytes),
            else => {},
        }
    }
};

pub const OutputSnapshot = struct {
    satoshis: Bigint,
    values: []OutputValue,

    pub fn deinit(self: *OutputSnapshot, allocator: std.mem.Allocator) void {
        for (self.values) |value| value.deinit(allocator);
        allocator.free(self.values);
        self.* = .{
            .satoshis = 0,
            .values = &.{},
        };
    }
};

pub const SmartContract = struct {};

pub const StatefulSmartContractError = error{
    UnsupportedOutputValue,
};

pub const StatefulRuntimeError = std.mem.Allocator.Error || StatefulSmartContractError;

pub const StatefulSmartContract = struct {
    allocator: std.mem.Allocator,
    txPreimage: SigHashPreimage,
    _outputs: std.ArrayListUnmanaged(OutputSnapshot),

    pub fn init(allocator: std.mem.Allocator) StatefulSmartContract {
        return .{
            .allocator = allocator,
            .txPreimage = &.{},
            ._outputs = .empty,
        };
    }

    pub fn deinit(self: *StatefulSmartContract) void {
        self.resetOutputs();
    }

    pub fn outputs(self: *const StatefulSmartContract) []const OutputSnapshot {
        return self._outputs.items;
    }

    pub fn setTxPreimage(self: *StatefulSmartContract, tx_preimage: SigHashPreimage) !void {
        self.txPreimage = try self.allocator.dupe(u8, tx_preimage);
    }

    pub fn resetOutputs(self: *StatefulSmartContract) void {
        if (self.txPreimage.len != 0) {
            self.allocator.free(self.txPreimage);
            self.txPreimage = &.{};
        }
        for (self._outputs.items) |*output| output.deinit(self.allocator);
        self._outputs.deinit(self.allocator);
        self._outputs = .empty;
    }

    pub fn addOutput(self: *StatefulSmartContract, satoshis: Bigint, values: anytype) StatefulRuntimeError!void {
        const copied_values = try duplicateTupleValues(self.allocator, values);
        try self._outputs.append(self.allocator, .{
            .satoshis = satoshis,
            .values = copied_values,
        });
    }

    pub fn getStateScript(self: *const StatefulSmartContract) ByteString {
        _ = self;
        return &.{};
    }
};

pub const StatefulContext = struct {
    runtime: *StatefulSmartContract,
    txPreimage: SigHashPreimage,

    pub fn init(runtime: *StatefulSmartContract, tx_preimage: SigHashPreimage) StatefulRuntimeError!StatefulContext {
        runtime.resetOutputs();
        try runtime.setTxPreimage(tx_preimage);
        return .{
            .runtime = runtime,
            .txPreimage = runtime.txPreimage,
        };
    }

    pub fn addOutput(self: StatefulContext, satoshis: Bigint, values: anytype) void {
        self.runtime.addOutput(satoshis, values) catch @panic("failed to record output");
    }

    pub fn getStateScript(self: StatefulContext) ByteString {
        return self.runtime.getStateScript();
    }

    pub fn outputs(self: StatefulContext) []const OutputSnapshot {
        return self.runtime.outputs();
    }
};

fn duplicateTupleValues(allocator: std.mem.Allocator, values: anytype) StatefulRuntimeError![]OutputValue {
    const Values = @TypeOf(values);
    const info = @typeInfo(Values);
    if (info != .@"struct" or !info.@"struct".is_tuple) {
        @compileError("addOutput expects a tuple literal like .{ value1, value2 }");
    }

    const fields = info.@"struct".fields;
    var copied = try allocator.alloc(OutputValue, fields.len);
    inline for (fields, 0..) |_, index| {
        copied[index] = try outputValueFrom(allocator, values[index]);
    }
    return copied;
}

fn outputValueFrom(allocator: std.mem.Allocator, value: anytype) StatefulRuntimeError!OutputValue {
    const Value = @TypeOf(value);
    return switch (@typeInfo(Value)) {
        .bool => .{ .boolean = value },
        .int, .comptime_int => .{ .bigint = std.math.cast(i64, value) orelse return error.UnsupportedOutputValue },
        .pointer, .array => .{ .bytes = try allocator.dupe(u8, asByteSlice(value) orelse return error.UnsupportedOutputValue) },
        else => error.UnsupportedOutputValue,
    };
}

fn asByteSlice(value: anytype) ?[]const u8 {
    const Value = @TypeOf(value);
    return switch (@typeInfo(Value)) {
        .pointer => |pointer| switch (pointer.size) {
            .slice => if (pointer.child == u8) value else null,
            .one => switch (@typeInfo(pointer.child)) {
                .array => |array| if (array.child == u8) value[0..] else null,
                else => null,
            },
            else => null,
        },
        .array => |array| if (array.child == u8) value[0..] else null,
        else => null,
    };
}

test "stateful runtime records and resets outputs" {
    var runtime = StatefulSmartContract.init(std.testing.allocator);
    defer runtime.deinit();

    try runtime.addOutput(10, .{ "alice", @as(i64, 7), true });
    try std.testing.expectEqual(@as(usize, 1), runtime.outputs().len);
    try std.testing.expectEqual(@as(i64, 10), runtime.outputs()[0].satoshis);
    try std.testing.expectEqualStrings("alice", switch (runtime.outputs()[0].values[0]) {
        .bytes => |bytes| bytes,
        else => return error.TestUnexpectedResult,
    });

    runtime.resetOutputs();
    try std.testing.expectEqual(@as(usize, 0), runtime.outputs().len);
}

test "Readonly returns the wrapped type unchanged" {
    try std.testing.expect(Readonly(i64) == i64);
}

test "StatefulContext exposes txPreimage and mutating output helpers" {
    var runtime = StatefulSmartContract.init(std.testing.allocator);
    defer runtime.deinit();

    const ctx = try StatefulContext.init(&runtime, "preimage");
    try std.testing.expectEqualStrings("preimage", ctx.txPreimage);

    ctx.addOutput(21, .{ "alice", @as(i64, 7) });
    try std.testing.expectEqual(@as(usize, 1), ctx.outputs().len);
    try std.testing.expectEqual(@as(i64, 21), ctx.outputs()[0].satoshis);
}
