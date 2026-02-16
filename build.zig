const std = @import("std");
const protobuf = @import("protobuf");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const protobuf_dep = b.dependency("protobuf", .{
        .target = target,
        .optimize = optimize,
    });

    // Proto module for generated protobuf files
    const proto_mod = b.addModule("proto", .{
        .root_source_file = b.path("src/proto/root.zig"),
        .target = target,
    });
    proto_mod.addImport("protobuf", protobuf_dep.module("protobuf"));

    // Observability module - shared with consumers for type identity
    const o11y_mod = b.addModule("observability", .{
        .root_source_file = b.path("src/observability/root.zig"),
        .target = target,
    });

    // Main library module exposed to consumers
    const mod = b.addModule("policy_zig", .{
        .root_source_file = b.path("src/policy/root.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "proto", .module = proto_mod },
            .{ .name = "protobuf", .module = protobuf_dep.module("protobuf") },
            .{ .name = "observability", .module = o11y_mod },
        },
    });

    // Link system libraries required by the library
    mod.link_libc = true;
    mod.linkSystemLibrary("hs", .{});

    // Tests
    const mod_tests = b.addTest(.{
        .root_module = mod,
    });
    mod_tests.root_module.link_libc = true;
    mod_tests.root_module.linkSystemLibrary("hs", .{});

    const run_mod_tests = b.addRunArtifact(mod_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);

    // Proto generation step (optional, requires protoc)
    const gen_proto_opt = b.option(bool, "gen-proto", "Generate protobuf files") orelse false;
    if (gen_proto_opt) {
        const gen_proto = b.step("gen-proto", "Generate zig files from protocol buffer definitions");
        const protoc_step = protobuf.RunProtocStep.create(protobuf_dep.builder, target, .{
            .destination_directory = b.path("src/proto"),
            .source_files = &.{
                "proto/tero/policy/v1/policy.proto",
                "proto/tero/policy/v1/log.proto",
                "proto/tero/policy/v1/metric.proto",
                "proto/tero/policy/v1/trace.proto",
                "proto/tero/policy/v1/shared.proto",
                "proto/opentelemetry/proto/common/v1/common.proto",
                "proto/opentelemetry/proto/resource/v1/resource.proto",
                "proto/opentelemetry/proto/logs/v1/logs.proto",
                "proto/opentelemetry/proto/metrics/v1/metrics.proto",
                "proto/opentelemetry/proto/trace/v1/trace.proto",
            },
            .include_directories = &.{
                "proto",
            },
        });
        gen_proto.dependOn(&protoc_step.step);
    }
}
