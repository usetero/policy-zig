const std = @import("std");
const protobuf = @import("protobuf");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const protobuf_dep = b.dependency("protobuf", .{ .target = target, .optimize = optimize });

    const proto_mod = b.addModule("proto", .{
        .root_source_file = b.path("src/proto/root.zig"),
        .target = target,
    });
    proto_mod.addImport("protobuf", protobuf_dep.module("protobuf"));

    const capacity_mod = b.addModule("policy_capacity", .{
        .root_source_file = b.path("src/policy/capacity.zig"),
        .target = target,
    });
    const image_mod = b.addModule("policy_image", .{
        .root_source_file = b.path("src/policy/image/root.zig"),
        .target = target,
    });
    const compiler_mod = b.addModule("policy_compiler", .{
        .root_source_file = b.path("src/policy/compiler/root.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "policy_capacity", .module = capacity_mod },
            .{ .name = "policy_image", .module = image_mod },
        },
    });
    const runtime_mod = b.addModule("policy_runtime", .{
        .root_source_file = b.path("src/policy/runtime/root.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "policy_capacity", .module = capacity_mod },
            .{ .name = "policy_image", .module = image_mod },
            .{ .name = "policy_compiler", .module = compiler_mod },
        },
    });
    const image_store_mod = b.addModule("policy_image_store", .{
        .root_source_file = b.path("src/policy/image/store.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "policy_capacity", .module = capacity_mod },
            .{ .name = "policy_image", .module = image_mod },
            .{ .name = "policy_compiler", .module = compiler_mod },
        },
    });
    const source_mod = b.addModule("policy_source", .{
        .root_source_file = b.path("src/policy/source/root.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "policy_compiler", .module = compiler_mod },
            .{ .name = "policy_image", .module = image_mod },
            .{ .name = "proto", .module = proto_mod },
        },
    });
    const replay_mod = b.addModule("policy_replay", .{
        .root_source_file = b.path("src/policy/runtime/replay.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "policy_runtime", .module = runtime_mod },
            .{ .name = "policy_compiler", .module = compiler_mod },
        },
    });

    const policy_mod = b.addModule("policy_zig", .{
        .root_source_file = b.path("src/policy/root.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "proto", .module = proto_mod },
            .{ .name = "policy_capacity", .module = capacity_mod },
            .{ .name = "policy_image", .module = image_mod },
            .{ .name = "policy_compiler", .module = compiler_mod },
            .{ .name = "policy_runtime", .module = runtime_mod },
            .{ .name = "policy_image_store", .module = image_store_mod },
            .{ .name = "policy_source", .module = source_mod },
            .{ .name = "policy_replay", .module = replay_mod },
        },
    });

    const test_step = b.step("test", "Run tests");
    const test_modules = [_]*std.Build.Module{
        policy_mod,
        capacity_mod,
        image_mod,
        compiler_mod,
        runtime_mod,
        image_store_mod,
        source_mod,
        replay_mod,
    };
    for (test_modules) |module| {
        const tests = b.addTest(.{ .root_module = module });
        test_step.dependOn(&b.addRunArtifact(tests).step);
    }

    addBenchmarks(b, target, policy_mod, runtime_mod);
    addProtoGeneration(b, protobuf_dep);
}

fn addBenchmarks(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    policy_mod: *std.Build.Module,
    runtime_mod: *std.Build.Module,
) void {
    const zbench_dep = b.dependency("zbench", .{ .target = target, .optimize = .ReleaseFast });
    const bench = b.addExecutable(.{
        .name = "bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/bench/main.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{
                .{ .name = "policy_zig", .module = policy_mod },
                .{ .name = "zbench", .module = zbench_dep.module("zbench") },
            },
        }),
    });
    const bench_step = b.step("bench", "Run policy runtime benchmarks");
    bench_step.dependOn(&b.addRunArtifact(bench).step);
    const build_bench_step = b.step("build-bench", "Build the benchmark executable");
    build_bench_step.dependOn(&b.addInstallArtifact(bench, .{}).step);

    const probe = b.addExecutable(.{
        .name = "policy-kernel-probe",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/bench/kernel_probe.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{.{ .name = "policy_runtime", .module = runtime_mod }},
        }),
    });
    probe.link_function_sections = true;
    const command = b.addSystemCommand(&.{ "bash", "scripts/check-kernel.sh" });
    command.addFileArg(probe.getEmittedBin());
    const kernel_step = b.step("check-kernel", "Check the linked evaluator page budget");
    kernel_step.dependOn(&command.step);
}

fn addProtoGeneration(b: *std.Build, protobuf_dep: *std.Build.Dependency) void {
    if (!(b.option(bool, "gen-proto", "Generate provider protobuf files") orelse false)) return;
    const step = b.step("gen-proto", "Generate provider protobuf files");
    const generator = protobuf_dep.artifact("protoc-gen-zig");
    const command = protobuf.RunProtocStep.createWithGenerator(b, generator, .{
        .destination_directory = b.path("src/proto"),
        .source_files = &.{
            b.path("proto/tero/policy/v1/policy.proto"),
            b.path("proto/tero/policy/v1/extension.proto"),
            b.path("proto/tero/policy/v1/tero_extensions.proto"),
            b.path("proto/tero/policy/v1/log.proto"),
            b.path("proto/tero/policy/v1/metric.proto"),
            b.path("proto/tero/policy/v1/trace.proto"),
            b.path("proto/tero/policy/v1/shared.proto"),
            b.path("proto/opentelemetry/proto/common/v1/common.proto"),
            b.path("proto/opentelemetry/proto/resource/v1/resource.proto"),
            b.path("proto/opentelemetry/proto/logs/v1/logs.proto"),
            b.path("proto/opentelemetry/proto/metrics/v1/metrics.proto"),
            b.path("proto/opentelemetry/proto/trace/v1/trace.proto"),
        },
        .include_directories = &.{b.path("proto")},
    });
    step.dependOn(&command.step);
}
