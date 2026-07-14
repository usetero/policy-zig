//! `com.usetero/s3-dump` extension handler (policy spec v1.6.0).
//!
//! Routes records selected by a policy extension's mode to a pre-configured
//! S3-compatible destination as batched ndjson objects. See
//! design/extensions.md for the full design.
//!
//! Invariants:
//! - `deliver` copies (encodes) synchronously and holds no reference to the
//!   record after it returns; the hot path never performs network I/O.
//! - A destination outage costs pipeline latency never: the sealed-backlog
//!   cap bounds all buffered memory, and past it records drop (counted).
//! - Failed uploads are requeued (within the same cap) and retried on later
//!   flushes under the SAME object key, so retries are idempotent. Records
//!   are lost only when the backlog cap overflows, never silently.
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
        /// Per-request attempts passed to the S3 client. The client only
        /// retries connection establishment, sleeping ~100ms between tries
        /// serialized per object — measured at ~290ms/object of added flush
        /// latency during an outage (`task bench:s3`). Since failed batches
        /// are requeued and retried on the next flush anyway, the default
        /// keeps flush fast; raise it only if the next-flush wait is too
        /// coarse for transient connect blips.
        max_attempts: usize = 1,
        content_type: []const u8 = "application/x-ndjson",
    };

    /// Static credentials, consumer-provided (e.g. read from env or a
    /// credentials file by the edge binary). Never carried in policies or
    /// targets. Null → uploads are counted as failed and batches dropped.
    pub const Credentials = struct {
        access_key_id: []const u8,
        secret_access_key: []const u8,
        /// Optional STS/session token (AWS_SESSION_TOKEN). Set for temporary
        /// creds (e.g. a Lambda execution role); null for a static IAM-user
        /// keypair. When present it is signed into the request as
        /// x-amz-security-token by z3.
        session_token: ?[]const u8 = null,
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
        /// Object key, fixed at seal time so retried uploads are idempotent
        /// (same key, identical content). Owned.
        key: []u8,
        buf: []u8,
        records: u32,
    };

    /// Flush-local copy of a target's connection config, duped into the
    /// flush arena under the mutex. Uploads read only snapshots, so a
    /// concurrent addTarget/configure (provider sync thread) can never
    /// invalidate memory mid-upload.
    const TargetSnapshot = struct {
        bucket: []const u8,
        region: []const u8,
        endpoint: ?[]const u8,
        virtual_host_style: bool,
    };

    /// PUT responses are tiny (empty or an XML error); never buffer more.
    const max_response_body: usize = 64 * 1024;

    pub const FlushOptions = struct {
        /// Seal and upload all open batches regardless of age (shutdown).
        force: bool = false,
    };

    /// Everything a consumer needs to turn one `flush()` call into metrics:
    /// counters (deltas since the previous flush) plus one gauge
    /// (`backlog_bytes`, a point-in-time snapshot, not a delta) for
    /// early-warning before the `max_sealed_bytes` cap starts dropping data.
    /// The library emits no metrics itself — this struct is the seam; the
    /// edge decides where counts and gauge go (OTel, Prometheus, statsd, ...).
    pub const FlushResult = struct {
        objects_uploaded: u32 = 0,
        /// Objects that failed to upload this flush. Unless the backlog cap
        /// forced a drop they are requeued and retried on the next flush.
        objects_failed: u32 = 0,
        /// Of the failed objects, how many were requeued for retry.
        objects_requeued: u32 = 0,
        records_uploaded: u64 = 0,
        records_failed: u64 = 0,
        /// Records dropped since the previous flush: at delivery time
        /// (backlog full, encode failure, null io) or because a failed batch
        /// could not be requeued within the backlog cap.
        records_dropped: u64 = 0,
        /// Object body bytes successfully PUT this flush. Feeds a
        /// throughput/cost counter (S3 PUT + egress pricing scales with this).
        bytes_uploaded: u64 = 0,
        /// Object body bytes in batches that failed to upload this flush
        /// (whether requeued or dropped).
        bytes_failed: u64 = 0,
        /// GAUGE, not a delta: sealed-but-not-yet-uploaded bytes remaining
        /// after this flush (open batches are excluded — they aren't at risk
        /// of the drop cliff yet). Alert on this approaching
        /// `Options.max_sealed_bytes`: that's the leading indicator of the
        /// destination falling behind, before `records_dropped` climbs.
        backlog_bytes: usize = 0,
    };

    allocator: std.mem.Allocator,
    options: Options,
    credentials: ?Credentials,
    mutex: std.Io.Mutex = .init,
    targets: std.ArrayList(Target) = .empty,
    batches: std.ArrayList(*Batch) = .empty,
    sealed: std.ArrayList(Sealed) = .empty,
    sealed_bytes: usize = 0,
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
        for (self.sealed.items) |s| {
            self.allocator.free(s.buf);
            self.allocator.free(s.key);
        }
        self.sealed.deinit(self.allocator);
        for (self.targets.items) |*t| {
            self.allocator.free(t.name);
            t.parsed.deinit();
        }
        self.targets.deinit(self.allocator);
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
            self.sealLocked(io, batch) catch return self.drop();
        }

        // Encode directly into the batch buffer — one write, no intermediate
        // copy. A failed or oversized encode is rolled back by truncating to
        // the pre-record length, so the batch is never corrupted.
        const len_before = batch.buf.items.len;
        var aw = std.Io.Writer.Allocating.fromArrayList(self.allocator, &batch.buf);
        var write_failed = false;
        encode(record, &aw.writer) catch {
            write_failed = true;
        };
        if (!write_failed) aw.writer.writeByte('\n') catch {
            write_failed = true;
        };
        batch.buf = aw.toArrayList();
        if (write_failed or batch.buf.items.len - len_before > self.options.max_batch_bytes) {
            // A rogue oversized record may have grown the buffer far past
            // anything a legal batch needs; release that memory rather than
            // pinning it on this slot forever. Legal batches never need more
            // than ~2x max_batch_bytes (seal-before-encode + one record).
            if (batch.buf.capacity > self.options.max_batch_bytes * 2) {
                batch.buf.shrinkAndFree(self.allocator, len_before);
            } else {
                batch.buf.shrinkRetainingCapacity(len_before);
            }
            return self.drop();
        }
        batch.records += 1;
        if (batch.first_ns == 0) {
            batch.first_ns = std.Io.Timestamp.now(io, .awake).nanoseconds;
        }
    }

    fn drop(self: *S3Dump) void {
        _ = self.records_dropped.fetchAdd(1, .monotonic);
    }

    /// Move the open batch's buffer onto the sealed list and reset the
    /// batch. The object key is fixed here, at seal time: a batch that fails
    /// to upload retries under the SAME key, so a PUT that actually
    /// succeeded server-side before the failure surfaced is overwritten with
    /// identical content instead of duplicated under a second key.
    fn sealLocked(self: *S3Dump, io: std.Io, batch: *Batch) !void {
        if (batch.buf.items.len == 0) return;
        const prefix = self.targets.items[batch.target].parsed.value.prefix;
        const key = try self.buildKey(io, prefix, batch.signal, batch.policy_id);
        errdefer self.allocator.free(key);
        const buf = try batch.buf.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(buf);
        try self.sealed.append(self.allocator, .{
            .target = batch.target,
            .signal = batch.signal,
            .policy_id = batch.policy_id,
            .key = key,
            .buf = buf,
            .records = batch.records,
        });
        self.sealed_bytes += buf.len;
        batch.records = 0;
        batch.first_ns = 0;
    }

    /// Requeue a failed batch for the next flush, bounded by the same
    /// backlog cap as delivery-time sealing. Returns false when the cap (or
    /// OOM) forced a drop instead.
    fn requeue(self: *S3Dump, io: std.Io, sealed_batch: Sealed) bool {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const fits = self.sealed_bytes + sealed_batch.buf.len <= self.options.max_sealed_bytes;
        if (fits) {
            if (self.sealed.append(self.allocator, sealed_batch)) |_| {
                self.sealed_bytes += sealed_batch.buf.len;
                return true;
            } else |_| {}
        }
        _ = self.records_dropped.fetchAdd(sealed_batch.records, .monotonic);
        self.allocator.free(sealed_batch.buf);
        self.allocator.free(sealed_batch.key);
        return false;
    }

    // =========================================================================
    // Flush (consumer-driven I/O)
    // =========================================================================

    /// Seal over-age (or, with `force`, all) open batches and upload every
    /// sealed batch as one object. A failed upload is requeued for the next
    /// flush (bounded by max_sealed_bytes) rather than dropped — z3 only
    /// retries connection establishment, not send/receive failures or 5xx
    /// responses, so handler-level retry is what makes a transient
    /// destination outage lossless.
    pub fn flush(self: *S3Dump, io: std.Io, opts: FlushOptions) FlushResult {
        var result: FlushResult = .{};

        const now: i128 = std.Io.Timestamp.now(io, .awake).nanoseconds;
        const max_age_ns: i128 = @as(i128, self.options.max_batch_age_ms) * std.time.ns_per_ms;

        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        var no_snapshots = [0]?TargetSnapshot{};
        var no_clients = [0]?s3.S3Client{};

        // Phase 1 (locked): seal due batches, steal the sealed list, and
        // snapshot target configs into the flush arena. Uploads read only
        // the snapshots, never `self.targets`.
        self.mutex.lockUncancelable(io);
        for (self.batches.items) |batch| {
            if (batch.buf.items.len == 0) continue;
            const expired = batch.first_ns != 0 and now - batch.first_ns >= max_age_ns;
            if (opts.force or expired) {
                // OOM here just leaves the batch open for the next flush.
                self.sealLocked(io, batch) catch {};
            }
        }
        const to_upload = self.sealed.toOwnedSlice(self.allocator) catch {
            self.mutex.unlock(io);
            result.records_dropped = self.records_dropped.swap(0, .monotonic);
            return result;
        };
        self.sealed_bytes = 0;
        const snapshots: []?TargetSnapshot =
            arena.alloc(?TargetSnapshot, self.targets.items.len) catch no_snapshots[0..];
        for (self.targets.items, 0..) |t, i| {
            if (i >= snapshots.len) break;
            snapshots[i] = snapshotTarget(arena, t.parsed.value) catch null;
        }
        self.mutex.unlock(io);
        defer self.allocator.free(to_upload);

        // Phase 2 (unlocked): create one client per target used this flush,
        // then upload. Client setup is a distinct step from the PUT — one
        // client per target so the std.http.Client connection pool is reused
        // across all of this flush's uploads to that target.
        const clients = self.makeClients(io, arena, snapshots, to_upload, no_clients[0..]);
        defer for (clients) |*c| {
            if (c.*) |*client| client.deinit();
        };

        for (to_upload) |sealed_batch| {
            const uploaded = ok: {
                const client = clientFor(clients, sealed_batch.target) orelse break :ok false;
                break :ok self.uploadOne(client, snapshots[sealed_batch.target].?, &sealed_batch);
            };
            if (uploaded) {
                result.objects_uploaded += 1;
                result.records_uploaded += sealed_batch.records;
                result.bytes_uploaded += sealed_batch.buf.len;
                self.allocator.free(sealed_batch.buf);
                self.allocator.free(sealed_batch.key);
            } else {
                result.objects_failed += 1;
                result.records_failed += sealed_batch.records;
                result.bytes_failed += sealed_batch.buf.len;
                if (self.requeue(io, sealed_batch)) result.objects_requeued += 1;
            }
        }

        result.records_dropped = self.records_dropped.swap(0, .monotonic);
        // Gauge read AFTER requeue has put failed-but-kept batches back onto
        // the backlog, so it reflects what's actually still queued.
        // `sealed_bytes` is plain state guarded by `mutex` (like the rest of
        // this struct), not an atomic — take the lock rather than tear it.
        self.mutex.lockUncancelable(io);
        result.backlog_bytes = self.sealed_bytes;
        self.mutex.unlock(io);
        return result;
    }

    fn snapshotTarget(arena: std.mem.Allocator, cfg: TargetConfig) !TargetSnapshot {
        return .{
            .bucket = try arena.dupe(u8, cfg.bucket),
            .region = try arena.dupe(u8, cfg.region),
            .endpoint = if (cfg.endpoint) |e| try arena.dupe(u8, e) else null,
            .virtual_host_style = !cfg.force_path_style,
        };
    }

    /// Create one S3 client per target that has a batch to upload this flush
    /// (deduped — several batches for one target share a client, hence one
    /// connection pool). Indexed by target, parallel to `snapshots`. A target
    /// with no credentials, no snapshot, or a failed client init is left null;
    /// its batches then fail the upload and requeue. Clients are owned by the
    /// caller (freed via the flush's `defer`), allocated in the flush arena.
    fn makeClients(
        self: *S3Dump,
        io: std.Io,
        arena: std.mem.Allocator,
        snapshots: []const ?TargetSnapshot,
        to_upload: []const Sealed,
        fallback: []?s3.S3Client,
    ) []?s3.S3Client {
        const clients = arena.alloc(?s3.S3Client, snapshots.len) catch return fallback;
        for (clients) |*c| c.* = null;

        const creds = self.credentials orelse return clients; // no creds → no clients
        for (to_upload) |sealed_batch| {
            const target = sealed_batch.target;
            if (target >= clients.len or clients[target] != null) continue;
            const snap = snapshots[target] orelse continue;
            clients[target] = s3.S3Client.init(self.allocator, .{
                .access_key_id = creds.access_key_id,
                .secret_access_key = creds.secret_access_key,
                .session_token = creds.session_token,
                .region = snap.region,
                .endpoint = snap.endpoint,
                .virtual_host_style = snap.virtual_host_style,
            }, .{ .io = io }) catch continue;
        }
        return clients;
    }

    /// The client for a target, or null if none was created for it (out of
    /// range, or setup skipped it — see `makeClients`).
    fn clientFor(clients: []?s3.S3Client, target: u16) ?*s3.S3Client {
        if (target >= clients.len) return null;
        return if (clients[target]) |*c| c else null;
    }

    /// PUT one sealed batch as a single object. No client lifecycle here — the
    /// client is created up front by `makeClients`.
    fn uploadOne(
        self: *S3Dump,
        client: *s3.S3Client,
        snap: TargetSnapshot,
        sealed_batch: *const Sealed,
    ) bool {
        var response = client.putObject(snap.bucket, sealed_batch.key, sealed_batch.buf, .{
            .content_type = self.options.content_type,
            .request = .{
                .max_attempts = self.options.max_attempts,
                .max_body_size = max_response_body,
            },
        }) catch return false;
        defer response.deinit();
        return response.http_head.status.class() == .success;
    }

    /// `{prefix}{signal}/{yyyy}/{mm}/{dd}/{hh}/{policy_id}-{unix_nanos}-{seq}.ndjson`
    fn buildKey(
        self: *S3Dump,
        io: std.Io,
        prefix: []const u8,
        signal: policy.TelemetryType,
        policy_id: []const u8,
    ) ![]u8 {
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
                @tagName(signal),
                year_day.year,
                month_day.month.numeric(),
                @as(u32, month_day.day_index) + 1,
                epoch_secs.getDaySeconds().getHoursIntoDay(),
                policy_id,
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

test "S3Dump: flush result carries byte counters and a backlog gauge" {
    var dump = S3Dump.init(testing.allocator, .{}, null); // no credentials → upload fails
    defer dump.deinit();
    try dump.addTarget(test_io, "eu-bucket", target_json);

    const cfg = try encodeTargetRef(testing.allocator, "s3", "eu-bucket");
    defer testing.allocator.free(cfg);
    const slot = dump.resolve(test_io, .log, "p1", cfg).?;

    const rec: []const u8 = "{\"body\":\"one\"}"; // 14 bytes + '\n' = 15
    dump.deliver(test_io, slot, @ptrCast(&rec), testEncodeRecord);
    dump.deliver(test_io, slot, @ptrCast(&rec), testEncodeRecord);

    const result = dump.flush(test_io, .{ .force = true });

    // Failed upload: bytes counted as failed, none as uploaded, and the
    // gauge reflects the batch sitting in the backlog after requeue.
    try testing.expectEqual(@as(u64, 30), result.bytes_failed);
    try testing.expectEqual(@as(u64, 0), result.bytes_uploaded);
    try testing.expectEqual(@as(usize, 30), result.backlog_bytes);
    try testing.expectEqual(dump.sealed_bytes, result.backlog_bytes);

    // A flush with nothing to do reports a zero gauge, not the last value.
    var empty_dump = S3Dump.init(testing.allocator, .{}, null);
    defer empty_dump.deinit();
    const empty_result = empty_dump.flush(test_io, .{ .force = true });
    try testing.expectEqual(@as(usize, 0), empty_result.backlog_bytes);
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

test "S3Dump: failed upload is requeued under a stable key, not dropped" {
    var dump = S3Dump.init(testing.allocator, .{}, null);
    defer dump.deinit();
    try dump.addTarget(test_io, "eu-bucket", target_json);

    const cfg = try encodeTargetRef(testing.allocator, "s3", "eu-bucket");
    defer testing.allocator.free(cfg);
    const slot = dump.resolve(test_io, .log, "p1", cfg).?;

    const rec: []const u8 = "{\"body\":\"one\"}";
    dump.deliver(test_io, slot, @ptrCast(&rec), testEncodeRecord);
    const batch_len = dump.batches.items[slot].buf.items.len;

    // No credentials → upload fails → the batch stays queued for retry.
    const r1 = dump.flush(test_io, .{ .force = true });
    try testing.expectEqual(@as(u32, 0), r1.objects_uploaded);
    try testing.expectEqual(@as(u32, 1), r1.objects_failed);
    try testing.expectEqual(@as(u32, 1), r1.objects_requeued);
    try testing.expectEqual(@as(u64, 1), r1.records_failed);
    try testing.expectEqual(@as(u64, 0), r1.records_dropped);
    try testing.expectEqual(@as(usize, 1), dump.sealed.items.len);
    try testing.expectEqual(batch_len, dump.sealed_bytes);
    try testing.expectEqual(@as(usize, 0), dump.batches.items[slot].buf.items.len);

    // The key was fixed at seal time and survives across retries, so a
    // retried PUT is idempotent. Snapshot it, retry, compare.
    const key_copy = try testing.allocator.dupe(u8, dump.sealed.items[0].key);
    defer testing.allocator.free(key_copy);
    try testing.expect(std.mem.startsWith(u8, key_copy, "dumps/log/"));
    try testing.expect(std.mem.endsWith(u8, key_copy, ".ndjson"));

    const r2 = dump.flush(test_io, .{ .force = true });
    try testing.expectEqual(@as(u32, 1), r2.objects_failed);
    try testing.expectEqual(@as(u32, 1), r2.objects_requeued);
    try testing.expectEqual(@as(usize, 1), dump.sealed.items.len);
    try testing.expectEqualStrings(key_copy, dump.sealed.items[0].key);
}

test "S3Dump: requeue drops when the backlog cap would be exceeded" {
    // Cap smaller than one batch: the failed upload cannot be requeued.
    var dump = S3Dump.init(testing.allocator, .{ .max_sealed_bytes = 4 }, null);
    defer dump.deinit();
    try dump.addTarget(test_io, "eu-bucket", target_json);

    const cfg = try encodeTargetRef(testing.allocator, "s3", "eu-bucket");
    defer testing.allocator.free(cfg);
    const slot = dump.resolve(test_io, .log, "p1", cfg).?;

    const rec: []const u8 = "{\"body\":\"one\"}";
    dump.deliver(test_io, slot, @ptrCast(&rec), testEncodeRecord);

    const result = dump.flush(test_io, .{ .force = true });
    try testing.expectEqual(@as(u32, 1), result.objects_failed);
    try testing.expectEqual(@as(u32, 0), result.objects_requeued);
    try testing.expectEqual(@as(u64, 1), result.records_dropped);
    try testing.expectEqual(@as(usize, 0), dump.sealed.items.len);
    try testing.expectEqual(@as(usize, 0), dump.sealed_bytes);
}

fn testEncodePartialFail(record: *const anyopaque, writer: *std.Io.Writer) anyerror!void {
    _ = record;
    try writer.writeAll("partial garbage");
    return error.EncodeFailed;
}

test "S3Dump: failed encode rolls the batch back to its previous contents" {
    var dump = S3Dump.init(testing.allocator, .{}, null);
    defer dump.deinit();
    try dump.addTarget(test_io, "eu-bucket", target_json);

    const cfg = try encodeTargetRef(testing.allocator, "s3", "eu-bucket");
    defer testing.allocator.free(cfg);
    const slot = dump.resolve(test_io, .log, "p1", cfg).?;

    const rec: []const u8 = "{\"body\":\"one\"}";
    dump.deliver(test_io, slot, @ptrCast(&rec), testEncodeRecord);
    // Partial write, then failure: everything it wrote must be truncated.
    dump.deliver(test_io, slot, @ptrCast(&rec), testEncodePartialFail);

    const batch = dump.batches.items[slot];
    try testing.expectEqual(@as(u32, 1), batch.records);
    try testing.expectEqualStrings("{\"body\":\"one\"}\n", batch.buf.items);
    try testing.expectEqual(@as(u64, 1), dump.records_dropped.load(.monotonic));
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
