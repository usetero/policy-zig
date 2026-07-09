//! Scale benchmarks for the s3-dump extension against a real S3-compatible
//! backend (MinIO). Built as the `bench-s3` step (ReleaseFast executable,
//! excluded from `zig build test`) and driven by `task bench:s3`, which
//! starts MinIO in docker, runs this, and tears down.
//!
//! Scenarios, chosen to expose where scale hurts:
//!   A. deliver hot path, 1 thread   — encode+append+mutex cost per record
//!   B. deliver hot path, 4 threads  — the single-mutex contention ceiling
//!   C. upload throughput vs object size — small-object overhead on flush
//!   D. 64-policy fan-out            — per-object cost with client reuse
//!   E. outage cost per flush        — z3 connect-retry sleeps serialize flush

const std = @import("std");
const proto = @import("proto");
const s3 = @import("s3");
const s3_dump_mod = @import("./s3_dump.zig");
const S3Dump = s3_dump_mod.S3Dump;

// Bench allocations are large and churny; the debug testing allocator would
// dominate the measurement. smp_allocator is the ReleaseFast-appropriate
// general-purpose allocator.
const gpa = std.heap.smp_allocator;

const Env = struct {
    access_key: []const u8,
    secret_key: []const u8,
    endpoint: []const u8,
    bucket: []const u8,

    fn load(environ: std.process.Environ) ?Env {
        return .{
            .access_key = environ.getPosix("AWS_ACCESS_KEY_ID") orelse return null,
            .secret_key = environ.getPosix("AWS_SECRET_ACCESS_KEY") orelse return null,
            .endpoint = environ.getPosix("S3_ENDPOINT") orelse "http://127.0.0.1:9000",
            .bucket = environ.getPosix("S3_BUCKET") orelse "policy-zig-bench",
        };
    }
};

/// ~200-byte log-shaped line, the typical record size for a waste dump.
const record_line = "{\"timestamp\":\"2026-07-08T12:00:00Z\",\"severity\":\"DEBUG\",\"body\":\"GET /api/v1/checkout/cart 200 requested by user\",\"service.name\":\"checkout-api\",\"http.request.id\":\"01890a5d-ac96-774b-b84e-fe56\"}";

fn encodeRecord(record: *const anyopaque, writer: *std.Io.Writer) anyerror!void {
    _ = record;
    try writer.writeAll(record_line);
}

fn encodeTargetRef(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    var aw = std.Io.Writer.Allocating.init(allocator);
    errdefer aw.deinit();
    const ref: proto.policy.ExtensionTargetRef = .{ .kind = "s3", .name = name };
    try ref.encode(&aw.writer, allocator);
    var list = aw.toArrayList();
    return list.toOwnedSlice(allocator);
}

fn nowNs(io: std.Io) i128 {
    return std.Io.Timestamp.now(io, .awake).nanoseconds;
}

fn mibPerSec(bytes: usize, elapsed_ns: i128) f64 {
    const secs = @as(f64, @floatFromInt(elapsed_ns)) / std.time.ns_per_s;
    return @as(f64, @floatFromInt(bytes)) / (1024.0 * 1024.0) / secs;
}

fn perSec(count: usize, elapsed_ns: i128) f64 {
    const secs = @as(f64, @floatFromInt(elapsed_ns)) / std.time.ns_per_s;
    return @as(f64, @floatFromInt(count)) / secs;
}

/// Build a dump with one target and `policies` resolved slots. Caller deinits.
fn makeDump(
    io: std.Io,
    env: Env,
    options: S3Dump.Options,
    endpoint_override: ?[]const u8,
    policies: u32,
) !struct { dump: S3Dump, slots: []u32 } {
    var dump = S3Dump.init(gpa, options, .{
        .access_key_id = env.access_key,
        .secret_access_key = env.secret_key,
    });
    errdefer dump.deinit();

    const target_json = try std.fmt.allocPrint(
        gpa,
        \\{{"endpoint": "{s}", "region": "us-east-1", "bucket": "{s}", "prefix": "bench/", "force_path_style": true}}
    ,
        .{ endpoint_override orelse env.endpoint, env.bucket },
    );
    defer gpa.free(target_json);
    try dump.addTarget(io, "bench-target", target_json);

    const ref = try encodeTargetRef(gpa, "bench-target");
    defer gpa.free(ref);

    const slots = try gpa.alloc(u32, policies);
    errdefer gpa.free(slots);
    for (slots, 0..) |*slot, i| {
        var id_buf: [32]u8 = undefined;
        const policy_id = try std.fmt.bufPrint(&id_buf, "bench-policy-{d:0>3}", .{i});
        slot.* = dump.resolve(io, .log, policy_id, ref) orelse return error.ResolveFailed;
    }
    return .{ .dump = dump, .slots = slots };
}

fn deliverWorker(dump: *S3Dump, io: std.Io, slot: u32, count: usize) void {
    for (0..count) |_| {
        dump.deliver(io, slot, @ptrCast(&record_line), encodeRecord);
    }
}

pub fn main(init: std.process.Init) !void {
    const env = Env.load(init.minimal.environ) orelse {
        std.debug.print(
            "bench-s3 needs a running S3-compatible server:\n" ++
                "  AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY (required)\n" ++
                "  S3_ENDPOINT (default http://127.0.0.1:9000)\n" ++
                "  S3_BUCKET (default policy-zig-bench)\n" ++
                "or run `task bench:s3` to do all of it via docker.\n",
            .{},
        );
        return error.MissingS3Environment;
    };

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Ensure the bucket exists.
    var admin = try s3.S3Client.init(gpa, .{
        .access_key_id = env.access_key,
        .secret_access_key = env.secret_key,
        .endpoint = env.endpoint,
        .virtual_host_style = false,
    }, .{ .io = io });
    defer admin.deinit();
    var create_resp = try admin.createBucket(env.bucket, .{});
    create_resp.deinit();

    std.debug.print(
        "\ns3-dump scale benchmarks ({s}, record={d}B)\n" ++
            "{s}\n",
        .{ env.endpoint, record_line.len, "-" ** 78 },
    );

    // -------------------------------------------------------------------
    // A + B: deliver hot path, 1 vs 4 threads (no uploads; memory only).
    // -------------------------------------------------------------------
    const deliver_records: usize = 200_000;
    const deliver_opts: S3Dump.Options = .{ .max_sealed_bytes = 1 << 30 };
    inline for (.{ 1, 4 }) |workers| {
        var made = try makeDump(io, env, deliver_opts, null, workers);
        defer made.dump.deinit();
        defer gpa.free(made.slots);

        const per_worker = deliver_records / workers;
        const start = nowNs(io);
        if (workers == 1) {
            deliverWorker(&made.dump, io, made.slots[0], per_worker);
        } else {
            var group: std.Io.Group = .init;
            var spawn_failed = false;
            for (made.slots) |slot| {
                group.concurrent(io, deliverWorker, .{ &made.dump, io, slot, per_worker }) catch {
                    spawn_failed = true;
                    break;
                };
            }
            // Await before any early return so no worker outlives the dump.
            group.await(io) catch {};
            if (spawn_failed) return error.ConcurrencyUnavailable;
        }
        const elapsed = nowNs(io) - start;

        const dropped = made.dump.records_dropped.load(.monotonic);
        std.debug.print(
            "deliver {d} thread(s)      {d:>8} recs   {d:>11.0} recs/s  {d:>8.1} MiB/s  drops={d}\n",
            .{
                workers,
                deliver_records,
                perSec(deliver_records, elapsed),
                mibPerSec(deliver_records * (record_line.len + 1), elapsed),
                dropped,
            },
        );
    }

    // -------------------------------------------------------------------
    // C: upload throughput vs object size (~32MiB total per size).
    // -------------------------------------------------------------------
    const total_upload_bytes: usize = 32 << 20;
    inline for (.{ 64 << 10, 1 << 20, 4 << 20 }) |object_bytes| {
        var made = try makeDump(io, env, .{
            .max_batch_bytes = object_bytes,
            .max_sealed_bytes = 1 << 30,
            .max_attempts = 1,
        }, null, 1);
        defer made.dump.deinit();
        defer gpa.free(made.slots);

        const records = total_upload_bytes / (record_line.len + 1);
        deliverWorker(&made.dump, io, made.slots[0], records);

        const start = nowNs(io);
        const result = made.dump.flush(io, .{ .force = true });
        const elapsed = nowNs(io) - start;

        std.debug.print(
            "flush {d:>5} KiB objects   {d:>8} objs   {d:>11.1} objs/s  {d:>8.1} MiB/s  failed={d}\n",
            .{
                object_bytes / 1024,
                result.objects_uploaded,
                perSec(result.objects_uploaded, elapsed),
                mibPerSec(total_upload_bytes, elapsed),
                result.objects_failed,
            },
        );
    }

    // -------------------------------------------------------------------
    // D: 64-policy fan-out — one flush uploading 64 small objects.
    // -------------------------------------------------------------------
    {
        const fanout_policies: u32 = 64;
        const per_policy_bytes: usize = 128 << 10;
        var made = try makeDump(io, env, .{ .max_sealed_bytes = 1 << 30, .max_attempts = 1 }, null, fanout_policies);
        defer made.dump.deinit();
        defer gpa.free(made.slots);

        const records_per_policy = per_policy_bytes / (record_line.len + 1);
        for (made.slots) |slot| {
            deliverWorker(&made.dump, io, slot, records_per_policy);
        }

        const start = nowNs(io);
        const result = made.dump.flush(io, .{ .force = true });
        const elapsed = nowNs(io) - start;

        std.debug.print(
            "fan-out 64 policies       {d:>8} objs   {d:>11.1} objs/s  {d:>8.1} MiB/s  failed={d}\n",
            .{
                result.objects_uploaded,
                perSec(result.objects_uploaded, elapsed),
                mibPerSec(fanout_policies * per_policy_bytes, elapsed),
                result.objects_failed,
            },
        );
    }

    // -------------------------------------------------------------------
    // E: outage cost — dead endpoint, 8 batches, per-flush wall time.
    // z3 sleeps ~100ms between connect retries, serialized per object, so
    // max_attempts multiplies directly into flush latency during an outage.
    // -------------------------------------------------------------------
    inline for (.{ 1, 3 }) |attempts| {
        var made = try makeDump(io, env, .{
            .max_sealed_bytes = 1 << 30,
            .max_attempts = attempts,
        }, "http://127.0.0.1:9", 8);
        defer made.dump.deinit();
        defer gpa.free(made.slots);

        for (made.slots) |slot| {
            deliverWorker(&made.dump, io, slot, 16);
        }

        const start = nowNs(io);
        const result = made.dump.flush(io, .{ .force = true });
        const elapsed = nowNs(io) - start;

        std.debug.print(
            "outage flush (attempts={d}) {d:>7} objs   {d:>10.1} ms/flush        requeued={d}\n",
            .{
                attempts,
                result.objects_failed,
                @as(f64, @floatFromInt(elapsed)) / std.time.ns_per_ms,
                result.objects_requeued,
            },
        );
    }

    std.debug.print("{s}\n", .{"-" ** 78});
}
