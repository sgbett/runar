const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const frontend_module = b.createModule(.{
        .root_source_file = b.path("../../compilers/zig/src/frontend_api.zig"),
        .target = target,
        .optimize = optimize,
    });

    const runar_module = b.createModule(.{
        .root_source_file = b.path("../../packages/runar-zig/src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    runar_module.addImport("runar_frontend", frontend_module);

    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples_test.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    tests.root_module.addImport("runar", runar_module);

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run Zig example tests");
    test_step.dependOn(&run_tests.step);
}
