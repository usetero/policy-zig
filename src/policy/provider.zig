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
