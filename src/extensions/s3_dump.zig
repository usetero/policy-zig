//! `com.usetero/s3-dump` extension handler (policy spec v1.6.0).
//!
//! Routes records selected by a policy extension's mode to a pre-configured
//! S3-compatible destination as batched ndjson objects. See
//! design/extensions.md for the full design.
//!
//! Invariants:
//! - `deliver` copies (encodes) synchronously and holds no reference to the
//!   record after it returns; the hot path never performs network I/O.
//! - A destination outage costs waste records (counted drops), never pipeline
//!   latency: the sealed-backlog cap is checked before encoding.
//! - I/O happens only in consumer-driven `flush(io)`, per this repo's rule
//!   that `std.Io` is passed per call and never stored.

const std = @import("std");
const policy = @import("policy_zig");
const proto = @import("proto");
const s3 = @import("s3");

/// Renders one record to bytes (one ndjson line, no trailing newline).
/// Wired by the consumer per signal — the record type is the consumer's.
pub const EncodeFn = *const fn (record: *const anyopaque, writer: *std.Io.Writer) anyerror!void;

pub const S3Dump = struct {
    /// All knobs, as plain data with defaults so a consumer can deserialize
    /// them straight from a config file (e.g. std.json) later.
    pub const Options = struct {
        /// Open batch is sealed for upload once it reaches this size.
        max_batch_bytes: usize = 4 << 20,
        /// Open batch is sealed for upload once it holds this many records.
        max_batch_records: u32 = 10_000,
        /// flush() seals a non-empty open batch older than this.
        max_batch_age_ms: u64 = 30_000,
        /// Cap on sealed-but-not-uploaded bytes; past it new records drop.
        max_sealed_bytes: usize = 32 << 20,
        /// Per-request attempts passed to the S3 client (its built-in retry).
        max_attempts: usize = 3,
        content_type: []const u8 = "application/x-ndjson",
    };

    /// Static credentials, consumer-provided (e.g. read from env or a
    /// credentials file by the edge binary). Never carried in policies or
    /// targets. Null → uploads are counted as failed and batches dropped.
    pub const Credentials = struct {
        access_key_id: []const u8,
        secret_access_key: []const u8,
    };

    /// Kind-defined config carried in `ExtensionTarget.config` for kind
    /// "s3", authored as JSON.
    pub const TargetConfig = struct {
        endpoint: ?[]const u8 = null,
        region: []const u8 = "us-east-1",
        bucket: []const u8,
        prefix: []const u8 = "",
        force_path_style: bool = true,
    };

    const Target = struct {
        name: []const u8,
        parsed: std.json.Parsed(TargetConfig),
    };

    /// One open batch per (target, signal, policy). Created at resolve time
    /// (snapshot compile) so `deliver` is an array index, never a hash or
    /// string compare. Batches persist across snapshot rebuilds so pending
    /// data survives policy updates.
    const Batch = struct {
        target: u16,
        signal: policy.TelemetryType,
        policy_id: []const u8,
        buf: std.ArrayList(u8) = .empty,
        records: u32 = 0,
        /// Monotonic (.awake) time of the first record, for age sealing.
        first_ns: i128 = 0,
    };

    const Sealed = struct {
        target: u16,
        signal: policy.TelemetryType,
        /// Borrowed from the owning Batch (batches live until deinit).
        policy_id: []const u8,
        buf: []u8,
        records: u32,
    };

    pub const FlushOptions = struct {
        /// Seal and upload all open batches regardless of age (shutdown).
        force: bool = false,
    };

    pub const FlushResult = struct {
        objects_uploaded: u32 = 0,
        objects_failed: u32 = 0,
        records_uploaded: u64 = 0,
        records_failed: u64 = 0,
        /// Records dropped at delivery time (backlog full, encode failure,
        /// null io) since the previous flush.
        records_dropped: u64 = 0,
    };

    allocator: std.mem.Allocator,
    options: Options,
    credentials: ?Credentials,
    mutex: std.Io.Mutex = .init,
    targets: std.ArrayList(Target) = .empty,
    batches: std.ArrayList(*Batch) = .empty,
    sealed: std.ArrayList(Sealed) = .empty,
    sealed_bytes: usize = 0,
    /// Reusable encode buffer, guarded by `mutex`.
    scratch: std.ArrayList(u8) = .empty,
    records_dropped: std.atomic.Value(u64) = .init(0),
    object_seq: std.atomic.Value(u64) = .init(0),

    pub fn init(allocator: std.mem.Allocator, options: Options, credentials: ?Credentials) S3Dump {
        return .{
            .allocator = allocator,
            .options = options,
            .credentials = credentials,
        };
    }

    pub fn deinit(self: *S3Dump) void {
        defer self.* = undefined;
        for (self.batches.items) |batch| {
            batch.buf.deinit(self.allocator);
            self.allocator.free(batch.policy_id);
            self.allocator.destroy(batch);
        }
        self.batches.deinit(self.allocator);
        for (self.sealed.items) |s| self.allocator.free(s.buf);
        self.sealed.deinit(self.allocator);
        for (self.targets.items) |*t| {
            self.allocator.free(t.name);
            t.parsed.deinit();
        }
        self.targets.deinit(self.allocator);
        self.scratch.deinit(self.allocator);
    }

    // =========================================================================
    // Target configuration
    // =========================================================================

    /// Add or replace a named s3 target. `config_json` is the kind-defined
    /// JSON TargetConfig. Used for local (out-of-band) configuration; the
    /// broadcast path (`configure`) lands here too, so broadcast wins on a
    /// name collision.
    pub fn addTarget(self: *S3Dump, io: std.Io, name: []const u8, config_json: []const u8) !void {
        const parsed = try std.json.parseFromSlice(TargetConfig, self.allocator, config_json, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        });
        errdefer parsed.deinit();
        const name_copy = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(name_copy);

        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        for (self.targets.items) |*t| {
            if (std.mem.eql(u8, t.name, name)) {
                self.allocator.free(t.name);
                t.parsed.deinit();
                t.* = .{ .name = name_copy, .parsed = parsed };
                return;
            }
        }
        try self.targets.append(self.allocator, .{ .name = name_copy, .parsed = parsed });
    }

    /// Ingest broadcast target entries (`SyncResponse.extension_configs` for
    /// this type): each entry is a serialized ExtensionTarget whose `config`
    /// is JSON TargetConfig. Non-s3 kinds and malformed entries are skipped
    /// (fail-open).
    pub fn configure(self: *S3Dump, io: std.Io, entries: []const []const u8) void {
        for (entries) |bytes| {
            var reader = std.Io.Reader.fixed(bytes);
            var target = proto.policy.ExtensionTarget.decode(&reader, self.allocator) catch continue;
            defer target.deinit(self.allocator);
            if (!std.mem.eql(u8, target.kind, "s3")) continue;
            self.addTarget(io, target.name, target.config) catch continue;
        }
    }

    /// One serialized ExtensionTargetRef per configured target — the
    /// capability descriptors for `ClientMetadata.supported_extensions`.
    /// Caller owns the returned slices (allocated with `allocator`).
    pub fn capabilities(self: *S3Dump, io: std.Io, allocator: std.mem.Allocator) ![]const []const u8 {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        var out: std.ArrayList([]const u8) = .empty;
        errdefer {
            for (out.items) |item| allocator.free(item);
            out.deinit(allocator);
        }
        for (self.targets.items) |t| {
            var aw = std.Io.Writer.Allocating.init(allocator);
            errdefer aw.deinit();
            const ref: proto.policy.ExtensionTargetRef = .{ .kind = "s3", .name = t.name };
            try ref.encode(&aw.writer, allocator);
            var list = aw.toArrayList();
            try out.append(allocator, try list.toOwnedSlice(allocator));
        }
        return try out.toOwnedSlice(allocator);
    }

    // =========================================================================
    // Resolution (snapshot compile time, cold)
    // =========================================================================

    /// Resolve one policy extension config (a serialized ExtensionTargetRef)
    /// to a batch slot. Null → unsupported/invalid, the caller skips the
    /// extension fail-open. The same (target, signal, policy) triple always
    /// resolves to the same slot, so batches survive snapshot rebuilds.
    pub fn resolve(
        self: *S3Dump,
        io: std.Io,
        signal: policy.TelemetryType,
        policy_id: []const u8,
        config: []const u8,
    ) ?u32 {
        var reader = std.Io.Reader.fixed(config);
        var ref = proto.policy.ExtensionTargetRef.decode(&reader, self.allocator) catch return null;
        defer ref.deinit(self.allocator);
        if (!std.mem.eql(u8, ref.kind, "s3")) return null;

        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        const target_index: u16 = blk: {
            for (self.targets.items, 0..) |t, i| {
                if (std.mem.eql(u8, t.name, ref.name)) break :blk @intCast(i);
            }
            return null;
        };

        for (self.batches.items, 0..) |batch, i| {
            if (batch.target == target_index and batch.signal == signal and
                std.mem.eql(u8, batch.policy_id, policy_id))
            {
                return @intCast(i);
            }
        }

        const batch = self.allocator.create(Batch) catch return null;
        const id_copy = self.allocator.dupe(u8, policy_id) catch {
            self.allocator.destroy(batch);
            return null;
        };
        batch.* = .{ .target = target_index, .signal = signal, .policy_id = id_copy };
        self.batches.append(self.allocator, batch) catch {
            self.allocator.free(id_copy);
            self.allocator.destroy(batch);
            return null;
        };
        return @intCast(self.batches.items.len - 1);
    }

    // =========================================================================
    // Delivery (hot path — encode + append only, never I/O)
    // =========================================================================

    pub fn deliver(
        self: *S3Dump,
        io_opt: ?std.Io,
        slot: u32,
        record: *const anyopaque,
        encode: EncodeFn,
    ) void {
        const io = io_opt orelse return self.drop();

        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        // Stale/foreign slot: fail-open.
        if (slot >= self.batches.items.len) return self.drop();
        const batch = self.batches.items[slot];

        // Seal a full batch first — and check the sealed-backlog cap BEFORE
        // encoding, so a destination outage degrades to a counter increment.
        const must_seal = batch.buf.items.len >= self.options.max_batch_bytes or
            batch.records >= self.options.max_batch_records;
        if (must_seal) {
            if (self.sealed_bytes + batch.buf.items.len > self.options.max_sealed_bytes) {
                return self.drop();
            }
            self.sealLocked(batch) catch return self.drop();
        }

        // Encode into the reusable scratch buffer so a failed encode never
        // corrupts the batch.
        self.scratch.clearRetainingCapacity();
        var aw = std.Io.Writer.Allocating.fromArrayList(self.allocator, &self.scratch);
        const encode_err = encode(record, &aw.writer);
        self.scratch = aw.toArrayList();
        encode_err catch return self.drop();

        const line = self.scratch.items;
        if (line.len + 1 > self.options.max_batch_bytes) return self.drop();

        batch.buf.ensureUnusedCapacity(self.allocator, line.len + 1) catch return self.drop();
        batch.buf.appendSliceAssumeCapacity(line);
        batch.buf.appendAssumeCapacity('\n');
        batch.records += 1;
        if (batch.first_ns == 0) {
            batch.first_ns = std.Io.Timestamp.now(io, .awake).nanoseconds;
        }
    }

    fn drop(self: *S3Dump) void {
        _ = self.records_dropped.fetchAdd(1, .monotonic);
    }

    /// Move the open batch's buffer onto the sealed list and reset the batch.
    fn sealLocked(self: *S3Dump, batch: *Batch) !void {
        if (batch.buf.items.len == 0) return;
        const buf = try batch.buf.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(buf);
        try self.sealed.append(self.allocator, .{
            .target = batch.target,
            .signal = batch.signal,
            .policy_id = batch.policy_id,
            .buf = buf,
            .records = batch.records,
        });
        self.sealed_bytes += buf.len;
        batch.records = 0;
        batch.first_ns = 0;
    }

    // =========================================================================
    // Flush (consumer-driven I/O)
    // =========================================================================

    /// Seal over-age (or, with `force`, all) open batches and upload every
    /// sealed batch as one object. Failed uploads are counted and their
    /// batches dropped — no retry queue by design (design/extensions.md).
    pub fn flush(self: *S3Dump, io: std.Io, opts: FlushOptions) FlushResult {
        var result: FlushResult = .{};

        const now: i128 = std.Io.Timestamp.now(io, .awake).nanoseconds;
        const max_age_ns: i128 = @as(i128, self.options.max_batch_age_ms) * std.time.ns_per_ms;

        self.mutex.lockUncancelable(io);
        for (self.batches.items) |batch| {
            if (batch.buf.items.len == 0) continue;
            const expired = batch.first_ns != 0 and now - batch.first_ns >= max_age_ns;
            if (opts.force or expired) {
                // OOM here just leaves the batch for the next flush.
                self.sealLocked(batch) catch {};
            }
        }
        const to_upload = self.sealed.toOwnedSlice(self.allocator) catch {
            self.mutex.unlock(io);
            result.records_dropped = self.records_dropped.swap(0, .monotonic);
            return result;
        };
        self.sealed_bytes = 0;
        self.mutex.unlock(io);
        defer self.allocator.free(to_upload);

        for (to_upload) |*sealed_batch| {
            defer self.allocator.free(sealed_batch.buf);
            if (self.uploadOne(io, sealed_batch)) {
                result.objects_uploaded += 1;
                result.records_uploaded += sealed_batch.records;
            } else {
                result.objects_failed += 1;
                result.records_failed += sealed_batch.records;
            }
        }

        result.records_dropped = self.records_dropped.swap(0, .monotonic);
        return result;
    }

    fn uploadOne(self: *S3Dump, io: std.Io, sealed_batch: *const Sealed) bool {
        const creds = self.credentials orelse return false;
        // Target config is index-stable: targets are only appended or
        // replaced in place, never removed.
        const cfg = self.targets.items[sealed_batch.target].parsed.value;

        // ponytail: one client (connection) per object; reuse a per-target
        // client within a flush if profiles show connection setup mattering.
        var client = s3.S3Client.init(self.allocator, .{
            .access_key_id = creds.access_key_id,
            .secret_access_key = creds.secret_access_key,
            .region = cfg.region,
            .endpoint = cfg.endpoint,
            .virtual_host_style = !cfg.force_path_style,
        }, .{ .io = io }) catch return false;
        defer client.deinit();

        const key = self.buildKey(io, cfg.prefix, sealed_batch) catch return false;
        defer self.allocator.free(key);

        var response = client.putObject(cfg.bucket, key, sealed_batch.buf, .{
            .content_type = self.options.content_type,
            .request = .{ .max_attempts = self.options.max_attempts },
        }) catch return false;
        defer response.deinit();
        return response.http_head.status.class() == .success;
    }

    /// `{prefix}{signal}/{yyyy}/{mm}/{dd}/{hh}/{policy_id}-{unix_nanos}-{seq}.ndjson`
    fn buildKey(self: *S3Dump, io: std.Io, prefix: []const u8, sealed_batch: *const Sealed) ![]u8 {
        const wall_ns: i128 = std.Io.Timestamp.now(io, .real).nanoseconds;
        const secs: u64 = @intCast(@divTrunc(wall_ns, std.time.ns_per_s));
        const epoch_secs: std.time.epoch.EpochSeconds = .{ .secs = secs };
        const year_day = epoch_secs.getEpochDay().calculateYearDay();
        const month_day = year_day.calculateMonthDay();
        const seq = self.object_seq.fetchAdd(1, .monotonic);
        return std.fmt.allocPrint(
            self.allocator,
            "{s}{s}/{d:0>4}/{d:0>2}/{d:0>2}/{d:0>2}/{s}-{d}-{d}.ndjson",
            .{
                prefix,
                @tagName(sealed_batch.signal),
                year_day.year,
                month_day.month.numeric(),
                @as(u32, month_day.day_index) + 1,
                epoch_secs.getDaySeconds().getHoursIntoDay(),
                sealed_batch.policy_id,
                wall_ns,
                seq,
            },
        );
    }
};

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;
const test_io = std.Options.debug_io;

fn encodeTargetRef(allocator: std.mem.Allocator, kind: []const u8, name: []const u8) ![]u8 {
    var aw = std.Io.Writer.Allocating.init(allocator);
    errdefer aw.deinit();
    const ref: proto.policy.ExtensionTargetRef = .{ .kind = kind, .name = name };
    try ref.encode(&aw.writer, allocator);
    var list = aw.toArrayList();
    return list.toOwnedSlice(allocator);
}

const target_json =
    \\{"endpoint": "http://127.0.0.1:1", "region": "eu-west-1", "bucket": "waste", "prefix": "dumps/"}
;

fn testEncodeRecord(record: *const anyopaque, writer: *std.Io.Writer) anyerror!void {
    const msg: *const []const u8 = @ptrCast(@alignCast(record));
    try writer.writeAll(msg.*);
}

test "S3Dump: resolve validates kind and target, slots are stable" {
    var dump = S3Dump.init(testing.allocator, .{}, null);
    defer dump.deinit();
    try dump.addTarget(test_io, "eu-bucket", target_json);

    const good = try encodeTargetRef(testing.allocator, "s3", "eu-bucket");
    defer testing.allocator.free(good);
    const bad_kind = try encodeTargetRef(testing.allocator, "gcs", "eu-bucket");
    defer testing.allocator.free(bad_kind);
    const bad_name = try encodeTargetRef(testing.allocator, "s3", "nope");
    defer testing.allocator.free(bad_name);

    try testing.expect(dump.resolve(test_io, .log, "p1", bad_kind) == null);
    try testing.expect(dump.resolve(test_io, .log, "p1", bad_name) == null);

    const slot = dump.resolve(test_io, .log, "p1", good).?;
    // Same triple → same slot (snapshot rebuilds keep their batches).
    try testing.expectEqual(slot, dump.resolve(test_io, .log, "p1", good).?);
    // Different policy or signal → different slot.
    try testing.expect(dump.resolve(test_io, .log, "p2", good).? != slot);
    try testing.expect(dump.resolve(test_io, .trace, "p1", good).? != slot);
}

test "S3Dump: deliver batches records as ndjson lines" {
    var dump = S3Dump.init(testing.allocator, .{}, null);
    defer dump.deinit();
    try dump.addTarget(test_io, "eu-bucket", target_json);

    const cfg = try encodeTargetRef(testing.allocator, "s3", "eu-bucket");
    defer testing.allocator.free(cfg);
    const slot = dump.resolve(test_io, .log, "p1", cfg).?;

    const rec1: []const u8 = "{\"body\":\"one\"}";
    const rec2: []const u8 = "{\"body\":\"two\"}";
    dump.deliver(test_io, slot, @ptrCast(&rec1), testEncodeRecord);
    dump.deliver(test_io, slot, @ptrCast(&rec2), testEncodeRecord);

    const batch = dump.batches.items[slot];
    try testing.expectEqual(@as(u32, 2), batch.records);
    try testing.expectEqualStrings("{\"body\":\"one\"}\n{\"body\":\"two\"}\n", batch.buf.items);
    try testing.expectEqual(@as(u64, 0), dump.records_dropped.load(.monotonic));
}

test "S3Dump: batch seals at record limit; backlog cap drops instead of growing" {
    var dump = S3Dump.init(testing.allocator, .{
        .max_batch_records = 2,
        .max_sealed_bytes = 40,
    }, null);
    defer dump.deinit();
    try dump.addTarget(test_io, "eu-bucket", target_json);

    const cfg = try encodeTargetRef(testing.allocator, "s3", "eu-bucket");
    defer testing.allocator.free(cfg);
    const slot = dump.resolve(test_io, .log, "p1", cfg).?;

    const rec: []const u8 = "0123456789"; // 11 bytes per line with \n
    // Two records fill the batch; the third seals it (22 bytes ≤ 40) and
    // starts a new one.
    dump.deliver(test_io, slot, @ptrCast(&rec), testEncodeRecord);
    dump.deliver(test_io, slot, @ptrCast(&rec), testEncodeRecord);
    dump.deliver(test_io, slot, @ptrCast(&rec), testEncodeRecord);
    try testing.expectEqual(@as(usize, 1), dump.sealed.items.len);
    try testing.expectEqual(@as(u32, 2), dump.sealed.items[0].records);
    try testing.expectEqual(@as(u32, 1), dump.batches.items[slot].records);

    // Fill and roll again: sealing would put the backlog at 44 > 40, so the
    // record that forces the seal is dropped before encoding.
    dump.deliver(test_io, slot, @ptrCast(&rec), testEncodeRecord);
    dump.deliver(test_io, slot, @ptrCast(&rec), testEncodeRecord);
    try testing.expectEqual(@as(u64, 1), dump.records_dropped.load(.monotonic));
    try testing.expectEqual(@as(usize, 1), dump.sealed.items.len);
}

test "S3Dump: flush without credentials fails the batch, counts it, and resets state" {
    var dump = S3Dump.init(testing.allocator, .{}, null);
    defer dump.deinit();
    try dump.addTarget(test_io, "eu-bucket", target_json);

    const cfg = try encodeTargetRef(testing.allocator, "s3", "eu-bucket");
    defer testing.allocator.free(cfg);
    const slot = dump.resolve(test_io, .log, "p1", cfg).?;

    const rec: []const u8 = "{\"body\":\"one\"}";
    dump.deliver(test_io, slot, @ptrCast(&rec), testEncodeRecord);

    const result = dump.flush(test_io, .{ .force = true });
    try testing.expectEqual(@as(u32, 0), result.objects_uploaded);
    try testing.expectEqual(@as(u32, 1), result.objects_failed);
    try testing.expectEqual(@as(u64, 1), result.records_failed);
    try testing.expectEqual(@as(usize, 0), dump.sealed.items.len);
    try testing.expectEqual(@as(usize, 0), dump.sealed_bytes);
    try testing.expectEqual(@as(usize, 0), dump.batches.items[slot].buf.items.len);
}

test "S3Dump: non-forced flush leaves young batches open" {
    var dump = S3Dump.init(testing.allocator, .{ .max_batch_age_ms = 60_000 }, null);
    defer dump.deinit();
    try dump.addTarget(test_io, "eu-bucket", target_json);

    const cfg = try encodeTargetRef(testing.allocator, "s3", "eu-bucket");
    defer testing.allocator.free(cfg);
    const slot = dump.resolve(test_io, .log, "p1", cfg).?;

    const rec: []const u8 = "{\"body\":\"one\"}";
    dump.deliver(test_io, slot, @ptrCast(&rec), testEncodeRecord);

    const result = dump.flush(test_io, .{});
    try testing.expectEqual(@as(u32, 0), result.objects_uploaded + result.objects_failed);
    try testing.expectEqual(@as(u32, 1), dump.batches.items[slot].records);
}

test "S3Dump: configure ingests broadcast targets; capabilities round-trips refs" {
    var dump = S3Dump.init(testing.allocator, .{}, null);
    defer dump.deinit();

    // Broadcast one s3 target and one foreign-kind target (skipped).
    var aw = std.Io.Writer.Allocating.init(testing.allocator);
    defer aw.deinit();
    const bcast: proto.policy.ExtensionTarget = .{ .kind = "s3", .name = "us-bucket", .config = target_json };
    try bcast.encode(&aw.writer, testing.allocator);
    var list = aw.toArrayList();
    const bcast_bytes = try list.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(bcast_bytes);

    dump.configure(test_io, &.{ bcast_bytes, "not-a-proto" });
    try testing.expectEqual(@as(usize, 1), dump.targets.items.len);

    const caps = try dump.capabilities(test_io, testing.allocator);
    defer {
        for (caps) |c| testing.allocator.free(c);
        testing.allocator.free(caps);
    }
    try testing.expectEqual(@as(usize, 1), caps.len);
    var reader = std.Io.Reader.fixed(caps[0]);
    var ref = try proto.policy.ExtensionTargetRef.decode(&reader, testing.allocator);
    defer ref.deinit(testing.allocator);
    try testing.expectEqualStrings("s3", ref.kind);
    try testing.expectEqualStrings("us-bucket", ref.name);
}
