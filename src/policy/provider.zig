const std = @import("std");
const proto = @import("proto");
const types = @import("types.zig");

const Policy = proto.policy.Policy;

/// Re-export TransformResult for use by providers
pub const TransformResult = types.TransformResult;

/// A point-in-time stats reading for a single policy, produced by the registry's
/// stats collector and consumed by a provider when building a sync request.
/// `id` and `errors` are allocated in the arena the collector is called with, so
/// the registry retains no ownership of the returned data.
pub const PolicyStatsSnapshot = struct {
    id: []const u8,
    hits: i64 = 0,
    misses: i64 = 0,
    transform_result: TransformResult = .{},
    errors: []const []const u8 = &.{},
};

/// Total telemetry that entered policy evaluation since the counters were last
/// read, regardless of match (spec v1.7.1 `VolumeStats`). Counted before the
/// keep and transform stages, so dropped/sampled/redacted records are included
/// at their pre-policy size.
///
/// Reported at most once: draining resets, whether or not the sync then
/// succeeds, so a failed sync loses its interval rather than replaying it. That
/// keeps volume on the same footing as `hits`/`misses` above — retaining one
/// side of `(hits + misses) / <signal count>` without the other would skew the
/// ratio — and a replay would double count, since the server has no interval
/// identifier to dedupe on. Volume is a lower bound, not an exact total.
///
/// Every field is independently optional: `0` means "not tracked" as much as
/// "none seen". Byte counts are only populated when the consumer calls
/// `registry.volume.addBytes` — the engine reads records through accessors and
/// has no serialized form to measure.
pub const VolumeSnapshot = struct {
    log_records: i64 = 0,
    log_bytes: i64 = 0,
    metric_data_points: i64 = 0,
    metric_bytes: i64 = 0,
    spans: i64 = 0,
    span_bytes: i64 = 0,

    pub fn isZero(self: VolumeSnapshot) bool {
        inline for (@typeInfo(VolumeSnapshot).@"struct".fields) |f| {
            if (@field(self, f.name) != 0) return false;
        }
        return true;
    }

    pub fn toProto(self: VolumeSnapshot) proto.policy.VolumeStats {
        return .{
            .log_records = self.log_records,
            .log_bytes = self.log_bytes,
            .metric_data_points = self.metric_data_points,
            .metric_bytes = self.metric_bytes,
            .spans = self.spans,
            .span_bytes = self.span_bytes,
        };
    }
};

/// Pull-based stats source handed to a provider by the registry at subscribe
/// time. The provider invokes `collect` immediately before each sync, passing a
/// per-sync arena; the registry returns one snapshot per policy — including
/// zero-hit policies — and resets the underlying counters. This keeps the
/// reference direction one-way (registry → provider): the provider holds a
/// function, not the registry itself, so there is no import cycle.
pub const StatsCollector = struct {
    context: *anyopaque,
    collect: *const fn (arena: std.mem.Allocator, context: *anyopaque) anyerror![]PolicyStatsSnapshot,
    /// Drain the registry's volume counters (spec v1.7.1), resetting them.
    /// Optional: a collector that leaves it null reports no volume, which is
    /// conformant.
    collect_volume: ?*const fn (context: *anyopaque) VolumeSnapshot = null,

    pub fn call(self: StatsCollector, arena: std.mem.Allocator) anyerror![]PolicyStatsSnapshot {
        return self.collect(arena, self.context);
    }

    pub fn drainVolume(self: StatsCollector) VolumeSnapshot {
        const f = self.collect_volume orelse return .{};
        return f(self.context);
    }
};

/// Extension sync plumbing (spec v1.6.0), implemented outside policy_zig by
/// the extensions module: capability advertisement for sync requests and
/// routing of broadcast extension configs from responses. A fn-pointer seam
/// like `StatsCollector` — not a vtable of behaviors, just the two crossings.
///
/// Handed to a provider by the registry at subscribe time, the same way
/// `StatsCollector` is. Providers with no control plane (file, testing) accept
/// the call and ignore it: there is nobody to advertise capabilities to and no
/// broadcast channel to receive from.
pub const ExtensionSyncHooks = struct {
    ctx: *anyopaque,
    /// Build ClientMetadata.supported_extensions. Allocate from `arena`.
    capabilities: *const fn (
        io: std.Io,
        ctx: *anyopaque,
        arena: std.mem.Allocator,
    ) anyerror![]proto.policy.ExtensionCapability,
    /// Receive SyncResponse.extension_configs. Called before policies are
    /// handed to the registry, so broadcast targets exist by the time the
    /// snapshot compiles extension bindings against them.
    apply_configs: *const fn (
        io: std.Io,
        ctx: *anyopaque,
        configs: []const proto.policy.ExtensionConfig,
    ) void,
};

/// Update notification sent by providers to subscribers
pub const PolicyUpdate = struct {
    policies: []const Policy,
    /// ID of the provider that sent this update
    provider_id: []const u8,
};

/// Callback signature for policy updates
/// Context is provider-specific state, onUpdate is called when policies change
pub const PolicyCallback = struct {
    context: *anyopaque,
    onUpdate: *const fn (context: *anyopaque, update: PolicyUpdate) anyerror!void,

    pub fn call(self: PolicyCallback, update: PolicyUpdate) !void {
        try self.onUpdate(self.context, update);
    }
};

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;

test "VolumeSnapshot.toProto: every field maps to its own proto field" {
    // Distinct values so a transposed pair (e.g. metric_bytes ↔ span_bytes)
    // fails instead of silently reporting the wrong signal's volume.
    const snap: VolumeSnapshot = .{
        .log_records = 11,
        .log_bytes = 22,
        .metric_data_points = 33,
        .metric_bytes = 44,
        .spans = 55,
        .span_bytes = 66,
    };

    const out = snap.toProto();
    try testing.expectEqual(@as(i64, 11), out.log_records);
    try testing.expectEqual(@as(i64, 22), out.log_bytes);
    try testing.expectEqual(@as(i64, 33), out.metric_data_points);
    try testing.expectEqual(@as(i64, 44), out.metric_bytes);
    try testing.expectEqual(@as(i64, 55), out.spans);
    try testing.expectEqual(@as(i64, 66), out.span_bytes);
}

test "VolumeSnapshot.isZero: any single tracked field defeats omission" {
    try testing.expect((VolumeSnapshot{}).isZero());

    // A consumer tracking only one signal, or only bytes, must still be
    // reported — omission is reserved for "nothing observed at all".
    inline for (@typeInfo(VolumeSnapshot).@"struct".fields) |f| {
        var snap: VolumeSnapshot = .{};
        @field(snap, f.name) = 1;
        try testing.expect(!snap.isZero());
    }
}

test "StatsCollector: volume seam is optional and no-ops when unwired" {
    // A collector from a provider the registry never gave a volume fn to (or an
    // older consumer building one by hand) must not crash and must report no
    // volume.
    var ctx: u8 = 0;
    const collector: StatsCollector = .{
        .context = &ctx,
        .collect = struct {
            fn collect(_: std.mem.Allocator, _: *anyopaque) anyerror![]PolicyStatsSnapshot {
                return &.{};
            }
        }.collect,
    };

    try testing.expect(collector.drainVolume().isZero());
    try testing.expect(collector.drainVolume().isZero());
}
