const std = @import("std");
const policy_provider = @import("./provider.zig");
const types = @import("./types.zig");
const proto = @import("proto");
const o11y = @import("observability");

const PolicyCallback = policy_provider.PolicyCallback;
const StatsCollector = policy_provider.StatsCollector;
const PolicyStatsSnapshot = policy_provider.PolicyStatsSnapshot;
const VolumeSnapshot = policy_provider.VolumeSnapshot;
const SyncRequest = proto.policy.SyncRequest;
const SyncResponse = proto.policy.SyncResponse;
const ClientMetadata = proto.policy.ClientMetadata;
const PolicySyncStatus = proto.policy.PolicySyncStatus;
const TransformStageStatus = proto.policy.TransformStageStatus;
const PolicyStage = proto.policy.PolicyStage;
const KeyValue = proto.common.KeyValue;
const AnyValue = proto.common.AnyValue;
const ServiceMetadata = types.ServiceMetadata;
const EventBus = o11y.EventBus;

/// A header to be sent with HTTP requests
pub const Header = struct {
    name: []const u8 = "",
    value: []const u8 = "",
};

// =============================================================================
// Observability Events
// =============================================================================

const HttpInitialFetchFailed = struct { err: []const u8 };
const HttpFetchFailed = struct { url: []const u8, err: []const u8 };
const HttpJsonDecodeFailed = struct { err: []const u8, body_preview: []const u8 };
const HttpPoliciesUnchanged = struct { reason: []const u8 };
const HttpPolicyHashUpdated = struct { hash: []const u8 };
const HttpPoliciesLoaded = struct { count: usize, url: []const u8, sync_timestamp: u64 };
const HttpSyncRequestFailed = struct { url: []const u8, status: u16 };
// A 200 whose SyncResponse carries `error_message`: the control plane rejected
// the sync in-band, which is a failure even though the transport succeeded.
const HttpSyncRejected = struct { url: []const u8, err: []const u8 };
const HttpSyncRequestSucceeded = struct { url: []const u8, policy_statuses_sent: usize };
// Emitted once per policy status about to be sent, so we can confirm at runtime
// exactly which policies (and counts) are reported each sync.
const HttpSyncStatusReported = struct { id: []const u8, match_hits: i64, match_misses: i64, errors: usize };
// Emitted when a sync carries volume, for the same reason: confirming at
// runtime what was reported. Omitted volume (all-zero) emits nothing.
const HttpSyncVolumeReported = struct { volume: VolumeSnapshot };
const HttpFetchStarted = struct {};
const HttpFetchCompleted = struct {};

/// Extension sync plumbing lives in the generic provider layer now (it's
/// handed to every provider variant by the registry, like `StatsCollector`).
/// Re-exported here so existing `HttpProvider.ExtensionSyncHooks` references
/// keep resolving.
pub const ExtensionSyncHooks = policy_provider.ExtensionSyncHooks;

/// HTTP-based policy provider that polls a remote endpoint
pub const HttpProvider = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    /// Unique identifier for this provider
    id: []const u8,
    http_client: std.http.Client,
    config_url: []const u8,
    poll_interval_ns: u64,
    callback: ?PolicyCallback,
    poll_thread: ?std.Thread,
    shutdown_flag: std.atomic.Value(bool),
    /// Set once `close` has performed its final flush, so a second `close` (or
    /// none, if the caller skipped it) never fires a redundant sync.
    flushed: bool = false,

    // Service metadata for sync requests (not owned, references config)
    service: ServiceMetadata,
    last_sync_timestamp: u64,
    last_successful_hash: ?[]u8,

    // Custom headers to send with HTTP requests (owned, copied from config)
    custom_headers: []Header,

    // Mutex for thread-safe access to synced state
    sync_state_mutex: std.Io.Mutex,

    // Event bus for observability
    bus: *EventBus,

    // Pull-based stats source, set by PolicyRegistry.subscribe. Called before
    // each sync to obtain the per-policy hit/miss/error rows to report.
    stats_collector: ?StatsCollector,

    // Extension sync plumbing (v1.6.0), set via setExtensionSyncHooks.
    extension_hooks: ?ExtensionSyncHooks,

    pub const Config = struct {
        id: []const u8,
        url: []const u8,
        poll_interval_seconds: u64 = 30,
        service: ServiceMetadata = .{},
        headers: []const Header = &.{},
    };

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        bus: *EventBus,
        config: Config,
    ) !*HttpProvider {
        const self = try allocator.create(HttpProvider);
        errdefer allocator.destroy(self);

        const id_copy = try allocator.dupe(u8, config.id);
        errdefer allocator.free(id_copy);

        const url_copy = try allocator.dupe(u8, config.url);
        errdefer allocator.free(url_copy);

        // Copy headers (both the slice and the string contents)
        const headers_copy = try allocator.alloc(Header, config.headers.len);
        errdefer allocator.free(headers_copy);

        var headers_initialized: usize = 0;
        errdefer {
            for (headers_copy[0..headers_initialized]) |h| {
                allocator.free(h.name);
                allocator.free(h.value);
            }
        }

        for (config.headers, 0..) |h, i| {
            const name_copy = try allocator.dupe(u8, h.name);
            errdefer allocator.free(name_copy);
            const value_copy = try allocator.dupe(u8, h.value);
            headers_copy[i] = .{ .name = name_copy, .value = value_copy };
            headers_initialized = i + 1;
        }

        self.* = .{
            .allocator = allocator,
            .io = io,
            .id = id_copy,
            .http_client = std.http.Client{ .allocator = allocator, .io = io },
            .config_url = url_copy,
            .poll_interval_ns = config.poll_interval_seconds * std.time.ns_per_s,
            .callback = null,
            .poll_thread = null,
            .shutdown_flag = std.atomic.Value(bool).init(false),
            .service = config.service,
            .last_sync_timestamp = 0,
            .last_successful_hash = null,
            .custom_headers = headers_copy,
            .sync_state_mutex = .init,
            .bus = bus,
            .stats_collector = null,
            .extension_hooks = null,
        };

        return self;
    }

    /// Get the unique identifier for this provider
    pub fn getId(self: *HttpProvider) []const u8 {
        return self.id;
    }

    /// Wire extension sync plumbing (v1.6.0). Call before start().
    pub fn setExtensionSyncHooks(self: *HttpProvider, hooks: ExtensionSyncHooks) void {
        self.extension_hooks = hooks;
    }

    /// Record the hash from a successful sync.
    /// This hash will be sent in subsequent sync requests.
    pub fn recordSyncedHash(self: *HttpProvider, hash: []const u8) !void {
        self.sync_state_mutex.lockUncancelable(self.bus.io);
        defer self.sync_state_mutex.unlock(self.bus.io);

        // Free old hash if exists
        if (self.last_successful_hash) |old_hash| {
            self.allocator.free(old_hash);
        }

        self.last_successful_hash = try self.allocator.dupe(u8, hash);
    }

    /// Register the stats collector to pull per-policy stats from before each
    /// sync. Set by PolicyRegistry.subscribe.
    pub fn setStatsCollector(self: *HttpProvider, collector: StatsCollector) void {
        self.stats_collector = collector;
    }

    pub fn subscribe(self: *HttpProvider, callback: PolicyCallback) !void {
        self.callback = callback;

        // Initial fetch and notify (non-fatal if it fails)
        self.fetchAndNotify() catch |err| {
            const event: HttpInitialFetchFailed = .{ .err = @errorName(err) };
            self.bus.warn(event);
        };

        // Start polling
        self.poll_thread = try std.Thread.spawn(.{}, pollLoop, .{self});
    }

    pub fn shutdown(self: *HttpProvider) void {
        self.shutdown_flag.store(true, .release);

        if (self.poll_thread) |thread| {
            thread.join();
            self.poll_thread = null;
        }
    }

    /// Graceful close: stop the poll loop, then perform one final synchronous
    /// sync so per-policy stats accumulated since the last poll tick reach the
    /// control plane before teardown. Stopping the loop first guarantees this
    /// is the only sync in flight (no concurrent poll-thread fetch).
    ///
    /// Returns the final sync's error rather than swallowing it — the caller
    /// decides whether a lost tail report is worth logging or acting on. The
    /// flush is attempted at most once: `flushed` is set before the sync (the
    /// stats collector resets its counters when pulled, so the tail is gone on
    /// failure and a retry would only report zeros), so a second call is a
    /// no-op and the loop is stopped either way.
    ///
    /// Reuses the io bound at init (the same process-wide io is still live at
    /// shutdown), so this must run before that io is torn down — i.e. in the
    /// consumer's shutdown window, before `deinit`. `deinit` does not flush.
    pub fn close(self: *HttpProvider) !void {
        if (self.flushed) return;
        self.flushed = true;

        self.shutdown();

        try self.fetchAndNotify();
    }

    pub fn deinit(self: *HttpProvider) void {
        const allocator = self.allocator;
        // LIFO defer order: self.* = undefined runs first (while memory is
        // still valid), then destroy frees it.
        defer allocator.destroy(self);
        defer self.* = undefined;

        // Ensure shutdown is called first
        self.shutdown();

        if (self.last_successful_hash) |hash| {
            allocator.free(hash);
        }

        // Free custom headers
        for (self.custom_headers) |h| {
            allocator.free(h.name);
            allocator.free(h.value);
        }
        allocator.free(self.custom_headers);

        self.http_client.deinit();
        allocator.free(self.id);
        allocator.free(self.config_url);
    }

    fn pollLoop(self: *HttpProvider) !void {
        while (!self.shutdown_flag.load(.acquire)) {
            // Sleep in small increments so we can respond quickly to shutdown
            const sleep_increment_ns = 100 * std.time.ns_per_ms; // 100ms
            var slept_ns: u64 = 0;

            while (slept_ns < self.poll_interval_ns and !self.shutdown_flag.load(.acquire)) {
                try self.io.sleep(.fromNanoseconds(sleep_increment_ns), .awake);
                slept_ns += sleep_increment_ns;
            }

            if (self.shutdown_flag.load(.acquire)) break;

            self.fetchAndNotify() catch |err| {
                const event: HttpFetchFailed = .{
                    .url = self.config_url,
                    .err = @errorName(err),
                };
                self.bus.err(event);
            };
        }
    }

    const FetchResult = struct {
        parsed: std.json.Parsed(SyncResponse),
        response_body: []u8,
    };

    pub fn fetchAndNotify(self: *HttpProvider) !void {
        const fetch_started: HttpFetchStarted = .{};
        const fetch_completed: HttpFetchCompleted = .{};
        var span = self.bus.started(.debug, fetch_started);
        defer span.completed(fetch_completed);
        var result = try self.fetchPolicies();
        defer result.parsed.deinit();
        defer self.allocator.free(result.response_body);

        const response = result.parsed.value;

        // Update last sync timestamp
        self.last_sync_timestamp = response.sync_timestamp_unix_nano;

        // Check if content has changed by comparing hashes
        const hash_unchanged = blk: {
            if (response.hash.len == 0) break :blk false;
            if (self.last_successful_hash) |old_hash| {
                break :blk std.mem.eql(u8, old_hash, response.hash);
            }
            break :blk false;
        };

        if (hash_unchanged) {
            const event: HttpPoliciesUnchanged = .{ .reason = "hash" };
            self.bus.debug(event);
            return;
        }

        // Record the hash for future sync requests
        if (response.hash.len > 0) {
            try self.recordSyncedHash(response.hash);
            const event: HttpPolicyHashUpdated = .{ .hash = response.hash };
            self.bus.info(event);
        }

        // Route broadcast extension configs first, so targets they carry are
        // known before the registry compiles the policies that reference them.
        if (self.extension_hooks) |hooks| {
            hooks.apply_configs(self.bus.io, hooks.ctx, response.extension_configs.items);
        }

        // Notify callback with policies from response
        if (self.callback) |cb| {
            try cb.call(.{
                .policies = response.policies.items,
                .provider_id = self.id,
            });
        }

        const loaded_event: HttpPoliciesLoaded = .{
            .count = response.policies.items.len,
            .url = self.config_url,
            .sync_timestamp = response.sync_timestamp_unix_nano,
        };
        self.bus.info(loaded_event);
    }

    /// Refresh the HTTP client's cached wall-clock time before each request.
    ///
    /// std.http.Client sets `now` once on the first HTTPS request and reuses
    /// that frozen timestamp for all later certificate validity checks. Over a
    /// long-lived poll loop this means a rotated upstream cert (whose Not Before
    /// is newer than the frozen `now`) fails verification with
    /// CertificateNotYetValid, surfaced as error.TlsInitializationFailed, until
    /// the process restarts. Refreshing before each poll keeps the validity
    /// check honest. `now` is left null on the first request so the initial
    /// CA-bundle rescan (which only runs while `now == null`) still happens.
    fn refreshClientClock(self: *HttpProvider) void {
        if (self.http_client.now != null) {
            self.http_client.now = std.Io.Clock.real.now(self.io);
        }
    }

    fn fetchPolicies(self: *HttpProvider) !FetchResult {
        // Use arena allocator for all temporary structures during fetch.
        // This reduces fragmentation by freeing all temporary memory at once.
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const temp_allocator = arena.allocator();

        // Build resource_attributes: fixed service fields + caller-supplied extras.
        var resource_attributes: std.ArrayList(KeyValue) = .empty;
        try resource_attributes.ensureTotalCapacity(temp_allocator, 4 + self.service.resource_attributes.len);
        try resource_attributes.appendSlice(temp_allocator, &.{
            .{ .key = "service.name", .value = .{ .value = .{ .string_value = self.service.name } } },
            .{ .key = "service.instance.id", .value = .{ .value = .{ .string_value = self.service.instance_id } } },
            .{ .key = "service.version", .value = .{ .value = .{ .string_value = self.service.version } } },
            .{ .key = "service.namespace", .value = .{ .value = .{ .string_value = self.service.namespace } } },
        });
        for (self.service.resource_attributes) |pair| {
            const v: KeyValue = .{ .key = pair.key, .value = .{ .value = .{ .string_value = pair.value } } };
            try resource_attributes.append(temp_allocator, v);
        }

        var labels: std.ArrayList(KeyValue) = .empty;
        try labels.ensureTotalCapacity(temp_allocator, self.service.labels.len);
        for (self.service.labels) |pair| {
            const v: KeyValue = .{ .key = pair.key, .value = .{ .value = .{ .string_value = pair.value } } };
            try labels.append(temp_allocator, v);
        }

        // Build supported_policy_stages from service metadata
        // Different binaries support different stages (e.g., OTLP supports traces, Datadog does not)
        const supported_policy_stages = self.service.supported_stages;

        // Pull per-policy stats (hits/misses/errors) from the registry. The
        // collector returns one row per policy — including zero-hit ones — with
        // counters reset, all allocated in this arena. Everything is reported so
        // the control plane knows each policy is live and being evaluated.
        const stats: []const PolicyStatsSnapshot = if (self.stats_collector) |c|
            try c.call(temp_allocator)
        else
            &.{};

        const policy_statuses_list = try statsToSyncStatuses(temp_allocator, stats);

        // Drain total observed volume (v1.7.1). Draining is the reset, exactly
        // like the per-policy counters above: if this sync fails its interval is
        // gone rather than replayed, since the server cannot tell a replay from
        // new telemetry. Reported volume is a lower bound, not an exact total.
        const volume: VolumeSnapshot = if (self.stats_collector) |c| c.drainVolume() else .{};

        // Log exactly what we're about to report, so runtime expectations can be
        // verified against the live snapshot.
        for (policy_statuses_list.items) |status| {
            const reported: HttpSyncStatusReported = .{
                .id = status.id,
                .match_hits = status.match_hits,
                .match_misses = status.match_misses,
                .errors = status.errors.items.len,
            };
            self.bus.debug(reported);
        }

        // Get last successful hash (if any) - read under lock
        var last_hash: []const u8 = &.{};
        {
            self.sync_state_mutex.lockUncancelable(self.bus.io);
            defer self.sync_state_mutex.unlock(self.bus.io);
            last_hash = self.last_successful_hash orelse &.{};
        }

        // Extension capability advertisement (v1.6.0). Failure here must not
        // block a sync: advertise nothing instead.
        const supported_extensions: []proto.policy.ExtensionCapability = if (self.extension_hooks) |hooks|
            hooks.capabilities(self.bus.io, hooks.ctx, temp_allocator) catch &.{}
        else
            &.{};

        // Create SyncRequest with the new structure
        const sync_request: SyncRequest = .{
            .client_metadata = .{
                .supported_extensions = .{
                    .items = supported_extensions,
                    .capacity = supported_extensions.len,
                },
                .supported_policy_stages = .{
                    .items = @constCast(supported_policy_stages),
                    .capacity = supported_policy_stages.len,
                },
                .resource_attributes = .{
                    .items = resource_attributes.items,
                    .capacity = resource_attributes.capacity,
                },
                .labels = .{
                    .items = labels.items,
                    .capacity = labels.capacity,
                },
            },
            .full_sync = self.last_sync_timestamp == 0,
            .last_sync_timestamp_unix_nano = self.last_sync_timestamp,
            .last_successful_hash = last_hash,
            .policy_statuses = policy_statuses_list,
            // Omitted rather than sent zero-valued when nothing was seen, per
            // the spec's guidance for implementations that track no volume.
            .volume = if (volume.isZero()) null else volume.toProto(),
        };

        if (!volume.isZero()) {
            const volume_event: HttpSyncVolumeReported = .{ .volume = volume };
            self.bus.debug(volume_event);
        }

        // Encode SyncRequest to JSON
        const request_body = try sync_request.jsonEncode(.{}, .{ .emit_oneof_field_name = false }, temp_allocator);
        // No defer needed - arena handles cleanup

        // Prepare headers: content-type + custom headers
        const max_builtin_headers: usize = 1;
        const total_headers = max_builtin_headers + self.custom_headers.len;
        const headers_buffer = try temp_allocator.alloc(std.http.Header, total_headers);
        // No defer needed - arena handles cleanup

        var headers_count: usize = 0;

        headers_buffer[headers_count] = .{
            .name = "content-type",
            .value = "application/json",
        };
        headers_count += 1;

        // Add custom headers
        for (self.custom_headers) |h| {
            headers_buffer[headers_count] = .{
                .name = h.name,
                .value = h.value,
            };
            headers_count += 1;
        }

        const extra_headers = headers_buffer[0..headers_count];

        var body: std.Io.Writer.Allocating = .init(self.allocator);
        defer body.deinit();

        self.refreshClientClock();

        // Create request
        const result = try self.http_client.fetch(.{
            .location = .{ .url = self.config_url },
            .extra_headers = extra_headers,
            .method = .POST,
            .payload = request_body,
            .response_writer = &body.writer,
        });

        // Check status code
        if (result.status != .ok) {
            const event: HttpSyncRequestFailed = .{
                .url = self.config_url,
                .status = @intFromEnum(result.status),
            };
            self.bus.err(event);
            return error.HttpRequestFailed;
        }

        const sent_event: HttpSyncRequestSucceeded = .{
            .url = self.config_url,
            .policy_statuses_sent = policy_statuses_list.items.len,
        };
        self.bus.debug(sent_event);

        // Read response body - take ownership to keep memory alive for parsed result
        const response_body = try body.toOwnedSlice();
        errdefer self.allocator.free(response_body);

        // Decode SyncResponse from JSON
        const parsed = SyncResponse.jsonDecode(response_body, .{}, self.allocator) catch |err| {
            // Log the error with a preview of the response body for debugging
            const preview_len = @min(response_body.len, 200);
            const event: HttpJsonDecodeFailed = .{
                .err = @errorName(err),
                .body_preview = response_body[0..preview_len],
            };
            self.bus.err(event);
            return err;
        };

        // A 200 carrying `error_message` is an in-band rejection: the server did
        // not accept this sync, so it must not advance the hash or deliver
        // policies. Checked before touching sync state, as policy-go and
        // policy-rs do.
        if (parsed.value.error_message.len > 0) {
            var mut = parsed;
            defer mut.deinit();
            const event: HttpSyncRejected = .{
                .url = self.config_url,
                .err = parsed.value.error_message,
            };
            self.bus.err(event);
            return error.SyncRejected;
        }

        return .{
            .parsed = parsed,
            .response_body = response_body,
        };
    }
};

/// Convert collected per-policy stats into the wire `PolicySyncStatus` list for
/// a sync request. One status per stats row, preserving order, so every policy
/// the collector reported (including zero-hit ones) is sent. Transform counters
/// map to TransformStageStatus as hits = applied, misses = attempted - applied;
/// a stage with nothing attempted is omitted (null). All output is allocated in
/// `arena`, which must outlive the encode that follows.
fn statsToSyncStatuses(
    arena: std.mem.Allocator,
    stats: []const PolicyStatsSnapshot,
) !std.ArrayList(PolicySyncStatus) {
    var list: std.ArrayList(PolicySyncStatus) = .empty;
    try list.ensureTotalCapacity(arena, stats.len);
    for (stats) |snap| {
        const tr = snap.transform_result;
        list.appendAssumeCapacity(.{
            .id = snap.id,
            .match_hits = snap.hits,
            .match_misses = snap.misses,
            .errors = .{ .items = @constCast(snap.errors), .capacity = snap.errors.len },
            .remove = if (tr.removes_attempted > 0)
                .{
                    .hits = @intCast(tr.removes_applied),
                    .misses = @intCast(tr.removes_attempted - tr.removes_applied),
                }
            else
                null,
            .redact = if (tr.redacts_attempted > 0)
                .{
                    .hits = @intCast(tr.redacts_applied),
                    .misses = @intCast(tr.redacts_attempted - tr.redacts_applied),
                }
            else
                null,
            .rename = if (tr.renames_attempted > 0)
                .{
                    .hits = @intCast(tr.renames_applied),
                    .misses = @intCast(tr.renames_attempted - tr.renames_applied),
                }
            else
                null,
            .add = if (tr.adds_attempted > 0)
                .{
                    .hits = @intCast(tr.adds_applied),
                    .misses = @intCast(tr.adds_attempted - tr.adds_applied),
                }
            else
                null,
        });
    }
    return list;
}

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;

test "HttpProvider: setStatsCollector stores the collector" {
    const allocator = testing.allocator;

    var noop_bus: o11y.NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    var provider = try HttpProvider.init(
        allocator,
        std.Options.debug_io,
        noop_bus.eventBus(),
        .{ .id = "test-provider", .url = "http://test.local/policies", .poll_interval_seconds = 60 },
    );
    defer provider.deinit();

    try testing.expect(provider.stats_collector == null);

    const Stub = struct {
        fn collect(_: std.mem.Allocator, _: *anyopaque) anyerror![]PolicyStatsSnapshot {
            return &.{};
        }
    };
    var ctx: u8 = 0;
    provider.setStatsCollector(.{ .context = &ctx, .collect = Stub.collect });
    try testing.expect(provider.stats_collector != null);
}

test "HttpProvider: refreshClientClock advances stale now but leaves first request null" {
    const allocator = testing.allocator;

    var noop_bus: o11y.NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    var provider = try HttpProvider.init(
        allocator,
        std.Options.debug_io,
        noop_bus.eventBus(),
        .{ .id = "test-provider", .url = "https://test.local/policies", .poll_interval_seconds = 60 },
    );
    defer provider.deinit();

    // First request: `now` must stay null so std.http.Client runs its initial
    // CA-bundle rescan (it only rescans while `now == null`).
    provider.http_client.now = null;
    provider.refreshClientClock();
    try testing.expect(provider.http_client.now == null);

    // Subsequent request: a stale cached timestamp (here ~1970) must be bumped
    // to roughly-current wall-clock time so cert validity checks stay honest
    // after an upstream cert rotation. Without the refresh `now` stays stale and
    // a freshly-issued cert fails as CertificateNotYetValid ->
    // TlsInitializationFailed.
    const stale: std.Io.Timestamp = .{ .nanoseconds = 1 };
    provider.http_client.now = stale;
    provider.refreshClientClock();
    try testing.expect(provider.http_client.now != null);
    try testing.expect(provider.http_client.now.?.nanoseconds > stale.nanoseconds);
}

/// Minimal control-plane stub: accept one POST, record its body, answer with
/// `response` (200 and an empty SyncResponse by default). Serves exactly one
/// request, so an unexpected extra sync is observable as a hang/failure.
const SyncStub = struct {
    allocator: std.mem.Allocator,
    listener: std.Io.net.Server,
    port: u16,
    body: []u8 = &.{},
    served: bool = false,
    /// Response body. Set to something unparseable to exercise the decode
    /// failure path.
    response: []const u8 = "{}",

    fn start(a: std.mem.Allocator, sio: std.Io) !SyncStub {
        var attempt: u16 = 0;
        while (attempt < 32) : (attempt += 1) {
            const port: u16 = 42801 + attempt;
            const addr = try std.Io.net.IpAddress.parse("127.0.0.1", port);
            const listener = addr.listen(sio, .{}) catch |err| switch (err) {
                error.AddressInUse => continue,
                else => return err,
            };
            return .{ .allocator = a, .listener = listener, .port = port };
        }
        return error.AddressInUse;
    }

    fn deinit(self: *SyncStub, sio: std.Io) void {
        defer self.* = undefined;
        self.listener.deinit(sio);
        if (self.body.len > 0) self.allocator.free(self.body);
    }

    fn serve(self: *SyncStub, sio: std.Io) void {
        var stream = self.listener.accept(sio) catch return;
        defer stream.close(sio);
        var recv_buf: [16 * 1024]u8 = undefined;
        var send_buf: [4 * 1024]u8 = undefined;
        var conn_reader = stream.reader(sio, &recv_buf);
        var conn_writer = stream.writer(sio, &send_buf);
        var http_server = std.http.Server.init(&conn_reader.interface, &conn_writer.interface);
        var request = http_server.receiveHead() catch return;
        var transfer_buf: [8 * 1024]u8 = undefined;
        const body_reader = request.readerExpectContinue(&transfer_buf) catch return;
        self.body = body_reader.allocRemaining(self.allocator, .limited(1 << 20)) catch return;
        self.served = true;
        request.respond(self.response, .{ .status = .ok }) catch return;
    }

    /// Start a stub plus a provider pointed at it, in the shape every sync test
    /// needs. Caller owns both (see the deinit pattern in the tests below).
    fn provider(self: *const SyncStub, a: std.mem.Allocator, sio: std.Io, bus: *EventBus) !*HttpProvider {
        var url_buf: [64]u8 = undefined;
        const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/sync", .{self.port});
        return HttpProvider.init(a, sio, bus, .{
            .id = "p",
            .url = url,
            .poll_interval_seconds = 3600,
        });
    }
};

test "HttpProvider.close: flushes final stats once, then is idempotent" {
    const allocator = testing.allocator;
    // Own Threaded io so the stub control-plane server gets a real thread,
    // mirroring the s3 stub test.
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var stub = try SyncStub.start(allocator, io);
    defer stub.deinit(io);
    var server_future = io.concurrent(SyncStub.serve, .{ &stub, io }) catch
        return error.SkipZigTest;
    defer server_future.cancel(io);

    var noop_bus: o11y.NoopEventBus = undefined;
    noop_bus.init(io);

    const url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/sync", .{stub.port});
    defer allocator.free(url);

    var provider = try HttpProvider.init(
        allocator,
        io,
        noop_bus.eventBus(),
        .{ .id = "p", .url = url, .poll_interval_seconds = 3600 },
    );
    defer provider.deinit();

    // Collector counts calls and reports one policy with real hits — this is
    // the tail stat that must reach the control plane before teardown.
    const Collector = struct {
        var calls: usize = 0;
        fn collect(arena: std.mem.Allocator, _: *anyopaque) anyerror![]PolicyStatsSnapshot {
            calls += 1;
            const rows = try arena.alloc(PolicyStatsSnapshot, 1);
            rows[0] = .{ .id = "hot", .hits = 5, .misses = 1 };
            return rows;
        }
        fn drain(_: *anyopaque) VolumeSnapshot {
            return .{ .log_records = 9, .log_bytes = 512 };
        }
    };
    Collector.calls = 0;
    var ctx: u8 = 0;
    provider.setStatsCollector(.{
        .context = &ctx,
        .collect = Collector.collect,
        .collect_volume = Collector.drain,
    });

    try provider.close();
    server_future.await(io);

    try testing.expect(provider.flushed);
    try testing.expect(stub.served);
    try testing.expectEqual(@as(usize, 1), Collector.calls);
    // The final sync carried the tail stats: the policy id and its hit count.
    try testing.expect(std.mem.indexOf(u8, stub.body, "hot") != null);
    try testing.expect(std.mem.indexOf(u8, stub.body, "matchHits") != null);
    // …and the observed volume.
    try testing.expect(std.mem.indexOf(u8, stub.body, "\"logRecords\":\"9\"") != null);
    try testing.expect(std.mem.indexOf(u8, stub.body, "\"logBytes\":\"512\"") != null);

    // Second close is a no-op: no extra collect, no extra request (the stub
    // only served one and its port is about to close).
    try provider.close();
    try testing.expectEqual(@as(usize, 1), Collector.calls);
}

test "HttpProvider.close: propagates the final sync error" {
    const allocator = testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var noop_bus: o11y.NoopEventBus = undefined;
    noop_bus.init(io);

    // Port 1 has nothing listening → the final sync's POST fails, and close
    // hands that error back instead of swallowing it.
    var provider = try HttpProvider.init(
        allocator,
        io,
        noop_bus.eventBus(),
        .{ .id = "p", .url = "http://127.0.0.1:1/sync", .poll_interval_seconds = 3600 },
    );
    defer provider.deinit();

    if (provider.close()) |_| {
        try testing.expect(false); // expected the unreachable endpoint to error
    } else |_| {}
    // Even on failure the loop is stopped and the attempt is spent, so a
    // second close is a silent no-op.
    try testing.expect(provider.flushed);
    try provider.close();
}

test "HttpProvider: an all-zero volume is omitted from the sync request" {
    const allocator = testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var stub = try SyncStub.start(allocator, io);
    defer stub.deinit(io);
    var server_future = io.concurrent(SyncStub.serve, .{ &stub, io }) catch
        return error.SkipZigTest;
    defer server_future.cancel(io);

    var noop_bus: o11y.NoopEventBus = undefined;
    noop_bus.init(io);

    var provider = try stub.provider(allocator, io, noop_bus.eventBus());
    defer provider.deinit();

    // Collector wired, but nothing observed yet: the spec says omit the message
    // rather than send a zero-valued one.
    var ctx: u8 = 0;
    provider.setStatsCollector(.{
        .context = &ctx,
        .collect = struct {
            fn collect(_: std.mem.Allocator, _: *anyopaque) anyerror![]PolicyStatsSnapshot {
                return &.{};
            }
        }.collect,
        .collect_volume = struct {
            fn drain(_: *anyopaque) VolumeSnapshot {
                return .{};
            }
        }.drain,
    });

    try provider.close();
    server_future.await(io);

    try testing.expect(stub.served);
    try testing.expect(std.mem.indexOf(u8, stub.body, "volume") == null);
}

test "HttpProvider: a provider with no volume seam wired syncs without volume" {
    const allocator = testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var stub = try SyncStub.start(allocator, io);
    defer stub.deinit(io);
    var server_future = io.concurrent(SyncStub.serve, .{ &stub, io }) catch
        return error.SkipZigTest;
    defer server_future.cancel(io);

    var noop_bus: o11y.NoopEventBus = undefined;
    noop_bus.init(io);

    var provider = try stub.provider(allocator, io, noop_bus.eventBus());
    defer provider.deinit();

    // A collector built without the volume fns (an older consumer, or a
    // provider the registry never handed them to) must still sync cleanly.
    var ctx: u8 = 0;
    provider.setStatsCollector(.{
        .context = &ctx,
        .collect = struct {
            fn collect(arena: std.mem.Allocator, _: *anyopaque) anyerror![]PolicyStatsSnapshot {
                const rows = try arena.alloc(PolicyStatsSnapshot, 1);
                rows[0] = .{ .id = "p", .hits = 1 };
                return rows;
            }
        }.collect,
    });

    try provider.close();
    server_future.await(io);

    try testing.expect(stub.served);
    // Per-policy stats still reported; volume simply absent.
    try testing.expect(std.mem.indexOf(u8, stub.body, "matchHits") != null);
    try testing.expect(std.mem.indexOf(u8, stub.body, "volume") == null);
}

test "HttpProvider: a 200 carrying error_message is a failed sync" {
    const allocator = testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var stub = try SyncStub.start(allocator, io);
    defer stub.deinit(io);
    // Well-formed SyncResponse carrying policies, a hash and a timestamp, but
    // the control plane rejected the sync in-band. None of it may be adopted.
    stub.response =
        \\{"policies":[{"id":"p1","enabled":true}],
        \\ "hash":"should-not-be-adopted",
        \\ "syncTimestampUnixNano":"1234",
        \\ "errorMessage":"client not provisioned"}
    ;
    var server_future = io.concurrent(SyncStub.serve, .{ &stub, io }) catch
        return error.SkipZigTest;
    defer server_future.cancel(io);

    var noop_bus: o11y.NoopEventBus = undefined;
    noop_bus.init(io);

    var provider = try stub.provider(allocator, io, noop_bus.eventBus());
    defer provider.deinit();

    var ctx: u8 = 0;

    // Wired directly rather than via subscribe(), which would fire its own
    // initial fetch and consume the stub's single response.
    const Sink = struct {
        var notified: bool = false;
        fn onUpdate(_: *anyopaque, _: policy_provider.PolicyUpdate) anyerror!void {
            notified = true;
            return;
        }
    };
    Sink.notified = false;
    provider.callback = .{ .context = &ctx, .onUpdate = Sink.onUpdate };

    if (provider.close()) |_| {
        try testing.expect(false); // an in-band rejection is not a success
    } else |err| {
        try testing.expectEqual(error.SyncRejected, err);
    }
    server_future.await(io);

    // The rejected response's hash was not adopted as last-successful…
    try testing.expect(provider.last_successful_hash == null);
    // …its timestamp did not advance, so the next attempt is still a full sync…
    try testing.expectEqual(@as(u64, 0), provider.last_sync_timestamp);
    // …and its policies were never delivered to the registry.
    try testing.expect(!Sink.notified);
}

test "HttpProvider: a failed sync drops its volume instead of replaying it" {
    const allocator = testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var noop_bus: o11y.NoopEventBus = undefined;
    noop_bus.init(io);

    // Stand-in for the registry's counters, draining on pull exactly as
    // VolumeCounters.readAndReset does. There is deliberately no way to put a
    // reading back: the server cannot tell a replay from new telemetry, so a
    // failed sync's interval is lost rather than double counted.
    const Counters = struct {
        var pending: VolumeSnapshot = .{};
        var drains: usize = 0;
        fn collect(_: std.mem.Allocator, _: *anyopaque) anyerror![]PolicyStatsSnapshot {
            return &.{};
        }
        fn drain(_: *anyopaque) VolumeSnapshot {
            drains += 1;
            defer pending = .{};
            return pending;
        }
    };
    Counters.pending = .{ .log_records = 1, .log_bytes = 64, .spans = 1 };
    Counters.drains = 0;

    // Port 1 has nothing listening → the POST fails after the drain.
    var provider = try HttpProvider.init(
        allocator,
        io,
        noop_bus.eventBus(),
        .{ .id = "p", .url = "http://127.0.0.1:1/sync", .poll_interval_seconds = 3600 },
    );
    defer provider.deinit();
    var ctx: u8 = 0;
    provider.setStatsCollector(.{
        .context = &ctx,
        .collect = Counters.collect,
        .collect_volume = Counters.drain,
    });

    if (provider.close()) |_| {
        try testing.expect(false); // expected the unreachable endpoint to error
    } else |_| {}

    // The interval was read into the failed request and is gone: reported volume
    // is a lower bound on what was observed, never a replay.
    try testing.expectEqual(@as(usize, 1), Counters.drains);
    try testing.expect(Counters.pending.isZero());
}

test "statsToSyncStatuses: maps hits/misses/errors and reports every policy" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const errs = [_][]const u8{ "boom", "bad regex" };
    const stats = [_]PolicyStatsSnapshot{
        .{ .id = "hot", .hits = 7, .misses = 2, .errors = &errs },
        .{ .id = "cold", .hits = 0, .misses = 0 }, // zero-hit policy still reported
    };

    const list = try statsToSyncStatuses(a, &stats);

    // Every policy is present, in order.
    try testing.expectEqual(@as(usize, 2), list.items.len);

    const hot = list.items[0];
    try testing.expectEqualStrings("hot", hot.id);
    try testing.expectEqual(@as(i64, 7), hot.match_hits);
    try testing.expectEqual(@as(i64, 2), hot.match_misses);
    try testing.expectEqual(@as(usize, 2), hot.errors.items.len);
    try testing.expectEqualStrings("boom", hot.errors.items[0]);
    // No transforms attempted -> all stage statuses omitted.
    try testing.expect(hot.remove == null);
    try testing.expect(hot.redact == null);

    const cold = list.items[1];
    try testing.expectEqualStrings("cold", cold.id);
    try testing.expectEqual(@as(i64, 0), cold.match_hits);
    try testing.expectEqual(@as(usize, 0), cold.errors.items.len);
}

test "statsToSyncStatuses: transform counters map to stage hits/misses" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const stats = [_]PolicyStatsSnapshot{
        .{
            .id = "p",
            .transform_result = .{
                .redacts_attempted = 5,
                .redacts_applied = 3,
            },
        },
    };

    const list = try statsToSyncStatuses(arena.allocator(), &stats);
    const status = list.items[0];

    // redact stage: hits = applied (3), misses = attempted - applied (2).
    try testing.expect(status.redact != null);
    try testing.expectEqual(@as(i64, 3), status.redact.?.hits);
    try testing.expectEqual(@as(i64, 2), status.redact.?.misses);
    // Stages with nothing attempted stay omitted.
    try testing.expect(status.remove == null);
    try testing.expect(status.rename == null);
    try testing.expect(status.add == null);
}

// =============================================================================
// SyncResponse JSON deserialization tests
//
// These tests verify that SyncResponse.jsonDecode correctly parses the proto
// JSON format returned by the HTTP sync server (Go protojson with
// UseEnumNumbers: true, EmitDefaultValues: true). Each test corresponds to
// a failing conformance test case from policy-conformance/testcases/.
// =============================================================================

test "SyncResponse JSON: metrics_aggregation_temporality" {
    const allocator = testing.allocator;

    // Proto JSON as produced by Go protojson with UseEnumNumbers: true.
    // aggregationTemporality: 1 = AGGREGATION_TEMPORALITY_DELTA
    const json_input =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "drop-delta-metrics",
        \\      "name": "Drop metrics with delta aggregation temporality",
        \\      "enabled": true,
        \\      "metric": {
        \\        "match": [
        \\          { "aggregationTemporality": 1, "exists": true }
        \\        ],
        \\        "keep": false
        \\      }
        \\    }
        \\  ],
        \\  "hash": "abc123",
        \\  "syncTimestampUnixNano": "1000000",
        \\  "recommendedSyncIntervalSeconds": 30,
        \\  "syncType": 1,
        \\  "errorMessage": ""
        \\}
    ;

    var parsed = try SyncResponse.jsonDecode(json_input, .{}, allocator);
    defer parsed.deinit();

    const response = parsed.value;
    try testing.expectEqual(@as(usize, 1), response.policies.items.len);

    const p = response.policies.items[0];
    try testing.expectEqualStrings("drop-delta-metrics", p.id);
    try testing.expect(p.enabled);

    // Verify metric target
    try testing.expect(p.target != null);
    const metric = p.target.?.metric;
    try testing.expect(!metric.keep);
    try testing.expectEqual(@as(usize, 1), metric.match.items.len);

    // Verify matcher: field = aggregation_temporality(DELTA), match = exists(true)
    const matcher = metric.match.items[0];
    try testing.expect(matcher.field != null);
    try testing.expectEqual(
        proto.policy.AggregationTemporality.AGGREGATION_TEMPORALITY_DELTA,
        matcher.field.?.aggregation_temporality,
    );
    try testing.expect(matcher.match != null);
    try testing.expect(matcher.match.?.exists);
}

test "SyncResponse JSON: metrics_type_filter" {
    const allocator = testing.allocator;

    // metricType: 1 = METRIC_TYPE_GAUGE
    const json_input =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "drop-gauges",
        \\      "name": "Drop all gauge metrics",
        \\      "enabled": true,
        \\      "metric": {
        \\        "match": [
        \\          { "metricType": 1, "exists": true }
        \\        ],
        \\        "keep": false
        \\      }
        \\    }
        \\  ],
        \\  "hash": "def456",
        \\  "syncTimestampUnixNano": "1000000",
        \\  "recommendedSyncIntervalSeconds": 30,
        \\  "syncType": 1,
        \\  "errorMessage": ""
        \\}
    ;

    var parsed = try SyncResponse.jsonDecode(json_input, .{}, allocator);
    defer parsed.deinit();

    const response = parsed.value;
    try testing.expectEqual(@as(usize, 1), response.policies.items.len);

    const p = response.policies.items[0];
    try testing.expectEqualStrings("drop-gauges", p.id);

    const metric = p.target.?.metric;
    try testing.expect(!metric.keep);
    try testing.expectEqual(@as(usize, 1), metric.match.items.len);

    const matcher = metric.match.items[0];
    try testing.expect(matcher.field != null);
    try testing.expectEqual(proto.policy.MetricType.METRIC_TYPE_GAUGE, matcher.field.?.metric_type);
    try testing.expect(matcher.match != null);
    try testing.expect(matcher.match.?.exists);
}

test "SyncResponse JSON: traces_span_kind" {
    const allocator = testing.allocator;

    // spanKind: 1 = SPAN_KIND_INTERNAL
    const json_input =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "drop-internal-spans",
        \\      "name": "Drop internal spans (0% sampling)",
        \\      "enabled": true,
        \\      "trace": {
        \\        "match": [
        \\          { "spanKind": 1, "exists": true }
        \\        ],
        \\        "keep": {
        \\          "percentage": 0.0
        \\        }
        \\      }
        \\    }
        \\  ],
        \\  "hash": "ghi789",
        \\  "syncTimestampUnixNano": "1000000",
        \\  "recommendedSyncIntervalSeconds": 30,
        \\  "syncType": 1,
        \\  "errorMessage": ""
        \\}
    ;

    var parsed = try SyncResponse.jsonDecode(json_input, .{}, allocator);
    defer parsed.deinit();

    const response = parsed.value;
    try testing.expectEqual(@as(usize, 1), response.policies.items.len);

    const p = response.policies.items[0];
    try testing.expectEqualStrings("drop-internal-spans", p.id);

    const trace = p.target.?.trace;
    try testing.expect(trace.keep != null);
    try testing.expectEqual(@as(f32, 0.0), trace.keep.?.percentage);
    try testing.expectEqual(@as(usize, 1), trace.match.items.len);

    const matcher = trace.match.items[0];
    try testing.expect(matcher.field != null);
    try testing.expectEqual(proto.policy.SpanKind.SPAN_KIND_INTERNAL, matcher.field.?.span_kind);
    try testing.expect(matcher.match != null);
    try testing.expect(matcher.match.?.exists);
}

test "SyncResponse JSON: traces_keep_100pct" {
    const allocator = testing.allocator;

    // spanStatus: 2 = SPAN_STATUS_CODE_ERROR
    const json_input =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "keep-error-spans",
        \\      "name": "Keep all error spans (100% sampling)",
        \\      "enabled": true,
        \\      "trace": {
        \\        "match": [
        \\          { "spanStatus": 2, "exists": true }
        \\        ],
        \\        "keep": {
        \\          "percentage": 100.0
        \\        }
        \\      }
        \\    }
        \\  ],
        \\  "hash": "jkl012",
        \\  "syncTimestampUnixNano": "1000000",
        \\  "recommendedSyncIntervalSeconds": 30,
        \\  "syncType": 1,
        \\  "errorMessage": ""
        \\}
    ;

    var parsed = try SyncResponse.jsonDecode(json_input, .{}, allocator);
    defer parsed.deinit();

    const response = parsed.value;
    try testing.expectEqual(@as(usize, 1), response.policies.items.len);

    const p = response.policies.items[0];
    try testing.expectEqualStrings("keep-error-spans", p.id);

    const trace = p.target.?.trace;
    try testing.expect(trace.keep != null);
    try testing.expectEqual(@as(f32, 100.0), trace.keep.?.percentage);
    try testing.expectEqual(@as(usize, 1), trace.match.items.len);

    const matcher = trace.match.items[0];
    try testing.expect(matcher.field != null);
    try testing.expectEqual(proto.policy.SpanStatusCode.SPAN_STATUS_CODE_ERROR, matcher.field.?.span_status);
    try testing.expect(matcher.match != null);
    try testing.expect(matcher.match.?.exists);
}

test "SyncResponse JSON: traces_error_vs_health" {
    const allocator = testing.allocator;

    // Two policies: keep errors (100%) and drop health checks (0%)
    // traceField: 1 = TRACE_FIELD_NAME
    const json_input =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "keep-error-spans",
        \\      "name": "Keep all error spans (100% sampling)",
        \\      "enabled": true,
        \\      "trace": {
        \\        "match": [
        \\          { "spanStatus": 2, "exists": true }
        \\        ],
        \\        "keep": {
        \\          "percentage": 100.0
        \\        }
        \\      }
        \\    },
        \\    {
        \\      "id": "drop-health-checks",
        \\      "name": "Drop health check spans (0% sampling)",
        \\      "enabled": true,
        \\      "trace": {
        \\        "match": [
        \\          { "traceField": 1, "exact": "GET /health" }
        \\        ],
        \\        "keep": {
        \\          "percentage": 0.0
        \\        }
        \\      }
        \\    }
        \\  ],
        \\  "hash": "mno345",
        \\  "syncTimestampUnixNano": "1000000",
        \\  "recommendedSyncIntervalSeconds": 30,
        \\  "syncType": 1,
        \\  "errorMessage": ""
        \\}
    ;

    var parsed = try SyncResponse.jsonDecode(json_input, .{}, allocator);
    defer parsed.deinit();

    const response = parsed.value;
    try testing.expectEqual(@as(usize, 2), response.policies.items.len);

    // First policy: keep error spans
    {
        const p = response.policies.items[0];
        try testing.expectEqualStrings("keep-error-spans", p.id);

        const trace = p.target.?.trace;
        try testing.expect(trace.keep != null);
        try testing.expectEqual(@as(f32, 100.0), trace.keep.?.percentage);

        const matcher = trace.match.items[0];
        try testing.expectEqual(proto.policy.SpanStatusCode.SPAN_STATUS_CODE_ERROR, matcher.field.?.span_status);
        try testing.expect(matcher.match.?.exists);
    }

    // Second policy: drop health checks
    {
        const p = response.policies.items[1];
        try testing.expectEqualStrings("drop-health-checks", p.id);

        const trace = p.target.?.trace;
        try testing.expect(trace.keep != null);
        try testing.expectEqual(@as(f32, 0.0), trace.keep.?.percentage);

        const matcher = trace.match.items[0];
        try testing.expectEqual(proto.policy.TraceField.TRACE_FIELD_NAME, matcher.field.?.trace_field);
        try testing.expectEqualStrings("GET /health", matcher.match.?.exact);
    }
}

test "SyncResponse JSON: traces_multiple_matchers" {
    const allocator = testing.allocator;

    // One policy with two matchers (ANDed): span_kind=INTERNAL + resource_attribute=frontend
    // spanKind: 1 = SPAN_KIND_INTERNAL
    const json_input =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "drop-internal-frontend-spans",
        \\      "name": "Drop internal spans from frontend service",
        \\      "enabled": true,
        \\      "trace": {
        \\        "match": [
        \\          { "spanKind": 1, "exists": true },
        \\          { "resourceAttribute": { "path": ["service.name"] }, "exact": "frontend" }
        \\        ],
        \\        "keep": {
        \\          "percentage": 0.0
        \\        }
        \\      }
        \\    }
        \\  ],
        \\  "hash": "pqr678",
        \\  "syncTimestampUnixNano": "1000000",
        \\  "recommendedSyncIntervalSeconds": 30,
        \\  "syncType": 1,
        \\  "errorMessage": ""
        \\}
    ;

    var parsed = try SyncResponse.jsonDecode(json_input, .{}, allocator);
    defer parsed.deinit();

    const response = parsed.value;
    try testing.expectEqual(@as(usize, 1), response.policies.items.len);

    const p = response.policies.items[0];
    try testing.expectEqualStrings("drop-internal-frontend-spans", p.id);

    const trace = p.target.?.trace;
    try testing.expect(trace.keep != null);
    try testing.expectEqual(@as(f32, 0.0), trace.keep.?.percentage);
    try testing.expectEqual(@as(usize, 2), trace.match.items.len);

    // First matcher: span_kind = INTERNAL
    {
        const matcher = trace.match.items[0];
        try testing.expectEqual(proto.policy.SpanKind.SPAN_KIND_INTERNAL, matcher.field.?.span_kind);
        try testing.expect(matcher.match.?.exists);
    }

    // Second matcher: resource_attribute = "service.name", exact = "frontend"
    {
        const matcher = trace.match.items[1];
        const attr_path = matcher.field.?.resource_attribute;
        try testing.expectEqual(@as(usize, 1), attr_path.path.items.len);
        try testing.expectEqualStrings("service.name", attr_path.path.items[0]);
        try testing.expectEqualStrings("frontend", matcher.match.?.exact);
    }
}

test "SyncResponse JSON: traces_overlapping" {
    const allocator = testing.allocator;

    // Two overlapping policies: keep errors (100%) and drop health spans (0%)
    const json_input =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "keep-all-errors",
        \\      "name": "Keep all error spans",
        \\      "enabled": true,
        \\      "trace": {
        \\        "match": [
        \\          { "spanStatus": 2, "exists": true }
        \\        ],
        \\        "keep": {
        \\          "percentage": 100.0
        \\        }
        \\      }
        \\    },
        \\    {
        \\      "id": "drop-health-spans",
        \\      "name": "Drop health check spans",
        \\      "enabled": true,
        \\      "trace": {
        \\        "match": [
        \\          { "traceField": 1, "contains": "health" }
        \\        ],
        \\        "keep": {
        \\          "percentage": 0.0
        \\        }
        \\      }
        \\    }
        \\  ],
        \\  "hash": "stu901",
        \\  "syncTimestampUnixNano": "1000000",
        \\  "recommendedSyncIntervalSeconds": 30,
        \\  "syncType": 1,
        \\  "errorMessage": ""
        \\}
    ;

    var parsed = try SyncResponse.jsonDecode(json_input, .{}, allocator);
    defer parsed.deinit();

    const response = parsed.value;
    try testing.expectEqual(@as(usize, 2), response.policies.items.len);

    // First policy: keep all errors
    {
        const p = response.policies.items[0];
        try testing.expectEqualStrings("keep-all-errors", p.id);

        const trace = p.target.?.trace;
        try testing.expectEqual(@as(f32, 100.0), trace.keep.?.percentage);

        const matcher = trace.match.items[0];
        try testing.expectEqual(proto.policy.SpanStatusCode.SPAN_STATUS_CODE_ERROR, matcher.field.?.span_status);
        try testing.expect(matcher.match.?.exists);
    }

    // Second policy: drop health spans
    {
        const p = response.policies.items[1];
        try testing.expectEqualStrings("drop-health-spans", p.id);

        const trace = p.target.?.trace;
        try testing.expectEqual(@as(f32, 0.0), trace.keep.?.percentage);

        const matcher = trace.match.items[0];
        try testing.expectEqual(proto.policy.TraceField.TRACE_FIELD_NAME, matcher.field.?.trace_field);
        try testing.expectEqualStrings("health", matcher.match.?.contains);
    }
}
