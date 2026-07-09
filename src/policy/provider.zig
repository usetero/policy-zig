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

/// Pull-based stats source handed to a provider by the registry at subscribe
/// time. The provider invokes `collect` immediately before each sync, passing a
/// per-sync arena; the registry returns one snapshot per policy — including
/// zero-hit policies — and resets the underlying counters. This keeps the
/// reference direction one-way (registry → provider): the provider holds a
/// function, not the registry itself, so there is no import cycle.
pub const StatsCollector = struct {
    context: *anyopaque,
    collect: *const fn (arena: std.mem.Allocator, context: *anyopaque) anyerror![]PolicyStatsSnapshot,

    pub fn call(self: StatsCollector, arena: std.mem.Allocator) anyerror![]PolicyStatsSnapshot {
        return self.collect(arena, self.context);
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
