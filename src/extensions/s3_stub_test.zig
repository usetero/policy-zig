//! End-to-end verification of the s3-dump upload path against an in-process
//! HTTP server that speaks just enough S3 — no docker, no external network,
//! runs in plain `zig build test`. Verifies the bytes on the wire: method,
//! path-style URL and key layout, SigV4 signing, the payload hash S3 uses for
//! integrity verification, and the requeue-then-retry durability path.
//!
//! For a real-storage smoke test against MinIO, see `task test:s3-e2e`.

const std = @import("std");
const proto = @import("proto");
const s3_dump_mod = @import("./s3_dump.zig");
const S3Dump = s3_dump_mod.S3Dump;

const testing = std.testing;

/// Minimal S3 stand-in: accepts connections, records every request (method,
/// target, raw head bytes, body), and answers each with the next scripted
/// status. Runs concurrently with the flush under test via io.concurrent.
const StubS3Server = struct {
    const Received = struct {
        method: std.http.Method,
        target: []u8,
        head: []u8,
        body: []u8,
    };

    allocator: std.mem.Allocator,
    statuses: []const std.http.Status,
    listener: std.Io.net.Server,
    port: u16,
    received: std.ArrayList(Received) = .empty,

    fn start(
        allocator: std.mem.Allocator,
        io: std.Io,
        statuses: []const std.http.Status,
    ) !StubS3Server {
        // std.Io exposes no getsockname, so probe a small fixed range
        // instead of binding port 0.
        var attempt: u16 = 0;
        while (attempt < 32) : (attempt += 1) {
            const port: u16 = 42741 + attempt;
            const addr = try std.Io.net.IpAddress.parse("127.0.0.1", port);
            const listener = addr.listen(io, .{}) catch |err| switch (err) {
                error.AddressInUse => continue,
                else => return err,
            };
            return .{
                .allocator = allocator,
                .statuses = statuses,
                .listener = listener,
                .port = port,
            };
        }
        return error.AddressInUse;
    }

    fn deinit(self: *StubS3Server, io: std.Io) void {
        defer self.* = undefined;
        self.listener.deinit(io);
        for (self.received.items) |r| {
            self.allocator.free(r.target);
            self.allocator.free(r.head);
            self.allocator.free(r.body);
        }
        self.received.deinit(self.allocator);
    }

    /// Serve until every scripted status has been sent. Handles both
    /// keep-alive (several requests on one connection) and reconnects
    /// (a new client per flush).
    fn serve(self: *StubS3Server, io: std.Io) void {
        var served: usize = 0;
        outer: while (served < self.statuses.len) {
            var stream = self.listener.accept(io) catch return;
            defer stream.close(io);
            var recv_buf: [64 * 1024]u8 = undefined;
            var send_buf: [4 * 1024]u8 = undefined;
            var conn_reader = stream.reader(io, &recv_buf);
            var conn_writer = stream.writer(io, &send_buf);
            var http_server = std.http.Server.init(&conn_reader.interface, &conn_writer.interface);
            while (served < self.statuses.len) {
                var request = http_server.receiveHead() catch continue :outer;
                self.handleOne(&request, self.statuses[served]) catch continue :outer;
                served += 1;
            }
        }
    }

    fn handleOne(
        self: *StubS3Server,
        request: *std.http.Server.Request,
        status: std.http.Status,
    ) !void {
        // Head pointers are invalidated once the body stream starts — copy first.
        const method = request.head.method;
        const target = try self.allocator.dupe(u8, request.head.target);
        errdefer self.allocator.free(target);
        const head = try self.allocator.dupe(u8, request.head_buffer);
        errdefer self.allocator.free(head);

        var transfer_buf: [1024]u8 = undefined;
        const body_reader = try request.readerExpectContinue(&transfer_buf);
        const body = try body_reader.allocRemaining(self.allocator, .limited(1 << 20));
        errdefer self.allocator.free(body);

        try self.received.append(self.allocator, .{
            .method = method,
            .target = target,
            .head = head,
            .body = body,
        });
        try request.respond("", .{ .status = status });
    }

    fn headContains(head: []const u8, needle: []const u8) bool {
        return std.ascii.indexOfIgnoreCase(head, needle) != null;
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

fn targetJson(allocator: std.mem.Allocator, port: u16) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        \\{{"endpoint": "http://127.0.0.1:{d}", "region": "us-east-1", "bucket": "waste", "prefix": "dumps/"}}
    ,
        .{port},
    );
}

fn encodeRecord(record: *const anyopaque, writer: *std.Io.Writer) anyerror!void {
    const msg: *const []const u8 = @ptrCast(@alignCast(record));
    try writer.writeAll(msg.*);
}

const test_credentials: S3Dump.Credentials = .{
    .access_key_id = "test-access-key",
    .secret_access_key = "test-secret-key",
};

test "e2e stub: flush PUTs the signed ndjson batch under the sealed key" {
    const allocator = testing.allocator;
    // The shared test-runner io caps concurrency; the stub server needs a
    // real thread, so build our own Threaded io like a consumer binary would.
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var stub = try StubS3Server.start(allocator, io, &.{.ok});
    defer stub.deinit(io);
    var server_future = io.concurrent(StubS3Server.serve, .{ &stub, io }) catch
        return error.SkipZigTest;
    // If an assertion fires before the server saw its scripted requests,
    // cancel instead of hanging in accept(); on the happy path (already
    // awaited) this is a no-op.
    defer server_future.cancel(io);

    var dump = S3Dump.init(allocator, .{ .max_attempts = 1 }, test_credentials);
    defer dump.deinit();
    const tj = try targetJson(allocator, stub.port);
    defer allocator.free(tj);
    try dump.addTarget(io, "stub", tj);

    const ref = try encodeTargetRef(allocator, "s3", "stub");
    defer allocator.free(ref);
    const slot = dump.resolve(io, .log, "dump-policy", ref).?;

    const rec1: []const u8 = "{\"body\":\"one\"}";
    const rec2: []const u8 = "{\"body\":\"two\"}";
    dump.deliver(io, slot, @ptrCast(&rec1), encodeRecord);
    dump.deliver(io, slot, @ptrCast(&rec2), encodeRecord);

    const result = dump.flush(io, .{ .force = true });
    server_future.await(io);

    try testing.expectEqual(@as(u32, 1), result.objects_uploaded);
    try testing.expectEqual(@as(u64, 2), result.records_uploaded);
    try testing.expectEqual(@as(u32, 0), result.objects_failed);
    // bytes_uploaded matches the exact body size; the successfully uploaded
    // batch leaves nothing behind in the backlog gauge.
    try testing.expectEqual(@as(u64, "{\"body\":\"one\"}\n{\"body\":\"two\"}\n".len), result.bytes_uploaded);
    try testing.expectEqual(@as(usize, 0), result.backlog_bytes);

    try testing.expectEqual(@as(usize, 1), stub.received.items.len);
    const req = stub.received.items[0];
    try testing.expectEqual(std.http.Method.PUT, req.method);
    // Path-style URL: /{bucket}/{key} with the documented key layout.
    try testing.expect(std.mem.startsWith(u8, req.target, "/waste/dumps/log/"));
    try testing.expect(std.mem.endsWith(u8, req.target, ".ndjson"));
    try testing.expect(std.mem.indexOf(u8, req.target, "dump-policy-") != null);
    // The exact batch bytes arrived, one record per line.
    try testing.expectEqualStrings("{\"body\":\"one\"}\n{\"body\":\"two\"}\n", req.body);
    // SigV4-signed, with the payload hash S3 verifies end-to-end.
    try testing.expect(StubS3Server.headContains(req.head, "AWS4-HMAC-SHA256"));
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(req.body, &hash, .{});
    const hex = std.fmt.bytesToHex(hash, .lower);
    try testing.expect(StubS3Server.headContains(req.head, &hex));
    try testing.expect(StubS3Server.headContains(req.head, "application/x-ndjson"));
}

test "e2e stub: 5xx requeues; the retry succeeds under the same key with the same bytes" {
    const allocator = testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var stub = try StubS3Server.start(allocator, io, &.{ .internal_server_error, .ok });
    defer stub.deinit(io);
    var server_future = io.concurrent(StubS3Server.serve, .{ &stub, io }) catch
        return error.SkipZigTest;
    // If an assertion fires before the server saw its scripted requests,
    // cancel instead of hanging in accept(); on the happy path (already
    // awaited) this is a no-op.
    defer server_future.cancel(io);

    var dump = S3Dump.init(allocator, .{ .max_attempts = 1 }, test_credentials);
    defer dump.deinit();
    const tj = try targetJson(allocator, stub.port);
    defer allocator.free(tj);
    try dump.addTarget(io, "stub", tj);

    const ref = try encodeTargetRef(allocator, "s3", "stub");
    defer allocator.free(ref);
    const slot = dump.resolve(io, .log, "dump-policy", ref).?;

    const rec: []const u8 = "{\"body\":\"one\"}";
    dump.deliver(io, slot, @ptrCast(&rec), encodeRecord);

    // First flush: server answers 500 → batch requeued, nothing lost. The
    // backlog gauge goes nonzero here — this is the metric an edge alerts on
    // to catch a struggling destination before records_dropped climbs.
    const r1 = dump.flush(io, .{ .force = true });
    try testing.expectEqual(@as(u32, 0), r1.objects_uploaded);
    try testing.expectEqual(@as(u32, 1), r1.objects_failed);
    try testing.expectEqual(@as(u32, 1), r1.objects_requeued);
    try testing.expectEqual(@as(u64, 0), r1.records_dropped);
    try testing.expectEqual(@as(u64, rec.len + 1), r1.bytes_failed);
    try testing.expect(r1.backlog_bytes > 0);

    // Second flush: retry succeeds, and the gauge falls back to zero.
    const r2 = dump.flush(io, .{ .force = true });
    server_future.await(io);
    try testing.expectEqual(@as(u32, 1), r2.objects_uploaded);
    try testing.expectEqual(@as(u64, 1), r2.records_uploaded);
    try testing.expectEqual(@as(u64, rec.len + 1), r2.bytes_uploaded);
    try testing.expectEqual(@as(usize, 0), r2.backlog_bytes);

    // Both attempts used the SAME key and carried identical bytes — the
    // retry is an idempotent overwrite, never a duplicate object.
    try testing.expectEqual(@as(usize, 2), stub.received.items.len);
    try testing.expectEqualStrings(stub.received.items[0].target, stub.received.items[1].target);
    try testing.expectEqualStrings(stub.received.items[0].body, stub.received.items[1].body);
}

test "e2e stub: session_token creds sign an x-amz-security-token header" {
    const allocator = testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var stub = try StubS3Server.start(allocator, io, &.{.ok});
    defer stub.deinit(io);
    var server_future = io.concurrent(StubS3Server.serve, .{ &stub, io }) catch
        return error.SkipZigTest;
    defer server_future.cancel(io);

    // Temporary creds (Lambda role): access + secret + session token. z3 signs
    // the token in as x-amz-security-token; a static keypair carries no such
    // header (see the first test's head assertions).
    const sts_creds: S3Dump.Credentials = .{
        .access_key_id = "test-access-key",
        .secret_access_key = "test-secret-key",
        .session_token = "test-token",
    };
    var dump = S3Dump.init(allocator, .{ .max_attempts = 1 }, sts_creds);
    defer dump.deinit();
    const tj = try targetJson(allocator, stub.port);
    defer allocator.free(tj);
    try dump.addTarget(io, "stub", tj);

    const ref = try encodeTargetRef(allocator, "s3", "stub");
    defer allocator.free(ref);
    const slot = dump.resolve(io, .log, "dump-policy", ref).?;

    const rec: []const u8 = "{\"body\":\"one\"}";
    dump.deliver(io, slot, @ptrCast(&rec), encodeRecord);

    const result = dump.flush(io, .{ .force = true });
    server_future.await(io);

    try testing.expectEqual(@as(u32, 1), result.objects_uploaded);
    try testing.expectEqual(@as(usize, 1), stub.received.items.len);
    const req = stub.received.items[0];
    try testing.expect(StubS3Server.headContains(req.head, "x-amz-security-token"));
    try testing.expect(StubS3Server.headContains(req.head, "test-token"));
}
