//! Real-storage smoke test for the s3-dump extension, run against a local
//! MinIO container. Not part of `zig build test` — it needs a running
//! backend, so it's a separate build step (`zig build test-s3-e2e`) driven by
//! `task test:s3-e2e`, which starts MinIO via docker, runs this, and tears
//! down. See `src/extensions/s3_stub_test.zig` for the hermetic equivalent
//! that runs in every `zig build test`.
//!
//! Verifies the whole path against a real implementation of the S3 API that
//! the stub only approximates: bucket creation, SigV4 accepted by a real
//! server, and the object actually readable back afterward with
//! byte-identical content. The stub test (s3_stub_test.zig) covers retry
//! mechanics under scripted failures; this test covers "does a real
//! S3-compatible server accept what we send and return what we sent".

const std = @import("std");
const proto = @import("proto");
const s3 = @import("s3");
const s3_dump_mod = @import("./s3_dump.zig");
const S3Dump = s3_dump_mod.S3Dump;

const testing = std.testing;

fn requiredEnv(environ: std.process.Environ, name: []const u8) ?[]const u8 {
    return environ.getPosix(name);
}

const Env = struct {
    access_key: []const u8,
    secret_key: []const u8,
    endpoint: []const u8,
    bucket: []const u8,

    fn load() ?Env {
        const environ = std.testing.environ;
        return .{
            .access_key = requiredEnv(environ, "AWS_ACCESS_KEY_ID") orelse return null,
            .secret_key = requiredEnv(environ, "AWS_SECRET_ACCESS_KEY") orelse return null,
            .endpoint = requiredEnv(environ, "S3_ENDPOINT") orelse "http://127.0.0.1:9000",
            .bucket = requiredEnv(environ, "S3_BUCKET") orelse "policy-zig-e2e",
        };
    }
};

fn encodeTargetRef(allocator: std.mem.Allocator, kind: []const u8, name: []const u8) ![]u8 {
    var aw = std.Io.Writer.Allocating.init(allocator);
    errdefer aw.deinit();
    const ref: proto.policy.ExtensionTargetRef = .{ .kind = kind, .name = name };
    try ref.encode(&aw.writer, allocator);
    var list = aw.toArrayList();
    return list.toOwnedSlice(allocator);
}

fn encodeRecord(record: *const anyopaque, writer: *std.Io.Writer) anyerror!void {
    const msg: *const []const u8 = @ptrCast(@alignCast(record));
    try writer.writeAll(msg.*);
}

test "e2e minio: real upload round-trips through a real S3-compatible server" {
    const env = Env.load() orelse return error.SkipZigTest;
    const allocator = testing.allocator;

    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Ensure the bucket exists (idempotent: MinIO returns 409 if it's already
    // there, which z3's own test suite treats as success too).
    var admin = try s3.S3Client.init(allocator, .{
        .access_key_id = env.access_key,
        .secret_access_key = env.secret_key,
        .endpoint = env.endpoint,
        .virtual_host_style = false,
    }, .{ .io = io });
    defer admin.deinit();
    var create_resp = try admin.createBucket(env.bucket, .{});
    defer create_resp.deinit();
    try testing.expect(create_resp.http_head.status == .ok or create_resp.http_head.status == .conflict);

    // Drive the extension exactly as the engine would: resolve a target,
    // deliver two records, flush for real.
    var dump = S3Dump.init(allocator, .{ .max_attempts = 1 }, .{
        .access_key_id = env.access_key,
        .secret_access_key = env.secret_key,
    });
    defer dump.deinit();

    const target_json = try std.fmt.allocPrint(
        allocator,
        \\{{"endpoint": "{s}", "region": "us-east-1", "bucket": "{s}", "prefix": "e2e/", "force_path_style": true}}
    ,
        .{ env.endpoint, env.bucket },
    );
    defer allocator.free(target_json);
    try dump.addTarget(io, "minio", target_json);

    const ref = try encodeTargetRef(allocator, "s3", "minio");
    defer allocator.free(ref);
    const slot = dump.resolve(io, .log, "e2e-policy", ref).?;

    const rec1: []const u8 = "{\"body\":\"first record\"}";
    const rec2: []const u8 = "{\"body\":\"second record\"}";
    dump.deliver(io, slot, @ptrCast(&rec1), encodeRecord);
    dump.deliver(io, slot, @ptrCast(&rec2), encodeRecord);

    const result = dump.flush(io, .{ .force = true });
    try testing.expectEqual(@as(u32, 1), result.objects_uploaded);
    try testing.expectEqual(@as(u32, 0), result.objects_failed);
    try testing.expectEqual(@as(u64, 2), result.records_uploaded);

    // Verify against the real backend, not our own bookkeeping: list the
    // prefix, fetch the object, and check the bytes really landed.
    var listing = try admin.listObjects(env.bucket, .{ .prefix = "e2e/log/" });
    defer listing.deinit();
    // A fresh container (the task flow) holds exactly our object; a
    // long-lived server may hold leftovers from direct runs, so find ours
    // by key substring rather than assuming it's the only one.
    const key = blk: {
        for (listing.objects) |obj| {
            if (std.mem.indexOf(u8, obj.key, "e2e-policy-") != null) break :blk obj.key;
        }
        return error.UploadedObjectNotFound;
    };

    var get_resp = try admin.getObject(env.bucket, key, .{});
    defer get_resp.deinit();
    try testing.expectEqual(std.http.Status.ok, get_resp.http_head.status);
    try testing.expectEqualStrings(
        "{\"body\":\"first record\"}\n{\"body\":\"second record\"}\n",
        get_resp.body,
    );

    // Clean up so repeated runs don't accumulate objects.
    var del_resp = try admin.deleteObject(env.bucket, key, .{});
    del_resp.deinit();
}
