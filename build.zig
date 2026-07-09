const std = @import("std");
const protobuf = @import("protobuf");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const protobuf_dep = b.dependency("protobuf", .{
        .target = target,
        .optimize = optimize,
    });

    const regex_dep = b.dependency("regex", .{
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
            .{ .name = "regex", .module = regex_dep.module("regex") },
        },
    });

    // Link system libraries required by the library
    mod.link_libc = true;
    mod.linkSystemLibrary("hs", .{});

    // Extensions module (spec v1.6.0): concrete extension handlers (s3-dump).
    // Separate module so policy_zig stays free of I/O and of the z3
    // dependency; only consumers that enable extensions link it.
    const z3_dep = b.dependency("z3", .{
        .target = target,
        .optimize = optimize,
    });
    const ext_mod = b.addModule("extensions", .{
        .root_source_file = b.path("src/extensions/root.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "proto", .module = proto_mod },
            .{ .name = "policy_zig", .module = mod },
            .{ .name = "s3", .module = z3_dep.module("s3") },
        },
    });

    // Tests
    const mod_tests = b.addTest(.{
        .root_module = mod,
    });
    mod_tests.root_module.link_libc = true;
    mod_tests.root_module.linkSystemLibrary("hs", .{});

    const run_mod_tests = b.addRunArtifact(mod_tests);

    // Observability module tests (no libc/hyperscan dependency)
    const o11y_tests = b.addTest(.{
        .root_module = o11y_mod,
    });
    const run_o11y_tests = b.addRunArtifact(o11y_tests);

    // Extensions module tests (need libc/hyperscan transitively via policy_zig)
    const ext_tests = b.addTest(.{
        .root_module = ext_mod,
    });
    ext_tests.root_module.link_libc = true;
    ext_tests.root_module.linkSystemLibrary("hs", .{});
    const run_ext_tests = b.addRunArtifact(ext_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_o11y_tests.step);
    test_step.dependOn(&run_ext_tests.step);

    // Real-storage s3-dump smoke test (needs a running S3-compatible
    // server — see `task test:s3-e2e`). Deliberately NOT part of `test`:
    // it requires network I/O and external state, unlike every other test.
    const s3_e2e_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/extensions/s3_minio_test.zig"),
            .target = target,
            .imports = &.{
                .{ .name = "proto", .module = proto_mod },
                .{ .name = "policy_zig", .module = mod },
                .{ .name = "s3", .module = z3_dep.module("s3") },
            },
        }),
    });
    s3_e2e_tests.root_module.link_libc = true;
    s3_e2e_tests.root_module.linkSystemLibrary("hs", .{});
    const run_s3_e2e_tests = b.addRunArtifact(s3_e2e_tests);
    const s3_e2e_step = b.step("test-s3-e2e", "Run the s3-dump smoke test against a real S3-compatible server");
    s3_e2e_step.dependOn(&run_s3_e2e_tests.step);

    // s3-dump scale benchmarks (needs MinIO — see `task bench:s3`).
    // ReleaseFast like the other benchmarks; excluded from `test`. A plain
    // executable, not a test: it reports numbers, not pass/fail.
    const s3_bench = b.addExecutable(.{
        .name = "bench-s3",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/extensions/s3_bench.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{
                .{ .name = "proto", .module = proto_mod },
                .{ .name = "policy_zig", .module = mod },
                .{ .name = "s3", .module = z3_dep.module("s3") },
            },
        }),
    });
    s3_bench.root_module.link_libc = true;
    s3_bench.root_module.linkSystemLibrary("hs", .{});
    const run_s3_bench = b.addRunArtifact(s3_bench);
    const s3_bench_step = b.step("bench-s3", "Run s3-dump scale benchmarks against a real S3-compatible server");
    s3_bench_step.dependOn(&run_s3_bench.step);

    // Benchmarks
    const zbench_dep = b.dependency("zbench", .{ .target = target, .optimize = .ReleaseFast });
    const zbench_mod = zbench_dep.module("zbench");

    const bench_exe = b.addExecutable(.{
        .name = "bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/bench/main.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{
                .{ .name = "policy_zig", .module = mod },
                .{ .name = "observability", .module = o11y_mod },
                .{ .name = "zbench", .module = zbench_mod },
            },
        }),
    });
    bench_exe.root_module.link_libc = true;
    bench_exe.root_module.linkSystemLibrary("hs", .{});

    const run_bench = b.addRunArtifact(bench_exe);
    const bench_step = b.step("bench", "Run benchmarks");
    bench_step.dependOn(&run_bench.step);

    // Proto generation step (optional, requires protoc)
    const gen_proto_opt = b.option(bool, "gen-proto", "Generate protobuf files") orelse false;
    if (gen_proto_opt) {
        const gen_proto = b.step("gen-proto", "Generate zig files from protocol buffer definitions");
        const generator = protobuf_dep.artifact("protoc-gen-zig");
        const protoc_step = protobuf.RunProtocStep.createWithGenerator(b, generator, .{
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
            .include_directories = &.{
                b.path("proto"),
            },
        });
        gen_proto.dependOn(&protoc_step.step);
    }
}
