const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const frontend_module = b.createModule(.{
        .root_source_file = b.path("../../compilers/zig/src/frontend_api.zig"),
        .target = target,
        .optimize = optimize,
    });

    const root_module = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    root_module.addImport("runar_frontend", frontend_module);

    const runar_module = b.addModule("runar", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    runar_module.addImport("runar_frontend", frontend_module);

    const tests = b.addTest(.{
        .root_module = root_module,
    });
    const run_tests = b.addRunArtifact(tests);

    const test_step = b.step("test", "Run runar-zig tests");
    test_step.dependOn(&run_tests.step);
}
