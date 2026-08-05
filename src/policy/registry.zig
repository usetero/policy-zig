const std = @import("std");
const proto = @import("proto");
const policy_source = @import("./source.zig");
const policy_provider = @import("./provider.zig");
const policy_types = @import("./types.zig");
const matcher_index = @import("./matcher_index.zig");
const parser = @import("./parser.zig");
const o11y = @import("observability");
const EventBus = o11y.EventBus;
const NoopEventBus = o11y.NoopEventBus;

const Policy = proto.policy.Policy;
const SourceType = policy_source.SourceType;
const PolicyMetadata = policy_source.PolicyMetadata;
const LogMatcherIndex = matcher_index.LogMatcherIndex;
const MetricMatcherIndex = matcher_index.MetricMatcherIndex;
const TraceMatcherIndex = matcher_index.TraceMatcherIndex;
const Provider = policy_types.Provider;

// =============================================================================
// Lock-free Policy Stats
// =============================================================================

/// Atomic counters for policy statistics - lock-free updates
pub const PolicyAtomicStats = struct {
    hits: std.atomic.Value(i64) = std.atomic.Value(i64).init(0),
    misses: std.atomic.Value(i64) = std.atomic.Value(i64).init(0),
    // Transform stats (adds, removes, etc.) - less frequent, can batch
    transforms_applied: std.atomic.Value(i64) = std.atomic.Value(i64).init(0),

    /// Atomically increment hits
    pub inline fn addHit(self: *PolicyAtomicStats) void {
        _ = self.hits.fetchAdd(1, .monotonic);
    }

    /// Atomically increment misses
    pub inline fn addMiss(self: *PolicyAtomicStats) void {
        _ = self.misses.fetchAdd(1, .monotonic);
    }

    /// Atomically increment transforms applied
    pub inline fn addTransform(self: *PolicyAtomicStats, count: i64) void {
        _ = self.transforms_applied.fetchAdd(count, .monotonic);
    }

    /// Read and reset stats atomically (for flushing)
    pub fn readAndReset(self: *PolicyAtomicStats) struct { hits: i64, misses: i64, transforms: i64 } {
        return .{
            .hits = self.hits.swap(0, .monotonic),
            .misses = self.misses.swap(0, .monotonic),
            .transforms = self.transforms_applied.swap(0, .monotonic),
        };
    }
};

// =============================================================================
// Volume Counters (spec v1.7.0)
// =============================================================================

/// Total telemetry entering policy evaluation, regardless of match. Lives on
/// the registry rather than the snapshot: a recompile allocates fresh
/// per-policy stats, and volume must survive that to stay a valid denominator
/// for hits/misses across a sync interval.
///
/// ponytail: one shared cache line of atomics, same shape as the per-policy
/// hit/miss counters. If per-record contention ever shows up in a profile,
/// shard per thread and sum on drain.
pub const VolumeCounters = struct {
    log_records: std.atomic.Value(i64) = .init(0),
    log_bytes: std.atomic.Value(i64) = .init(0),
    metric_data_points: std.atomic.Value(i64) = .init(0),
    metric_bytes: std.atomic.Value(i64) = .init(0),
    spans: std.atomic.Value(i64) = .init(0),
    span_bytes: std.atomic.Value(i64) = .init(0),

    /// Count one record of signal `T`. Called by the engine for every record
    /// entering evaluation; consumers never call this directly.
    pub inline fn record(self: *VolumeCounters, comptime T: policy_types.TelemetryType) void {
        const counter = switch (T) {
            .log => &self.log_records,
            .metric => &self.metric_data_points,
            .trace => &self.spans,
        };
        _ = counter.fetchAdd(1, .monotonic);
    }

    /// Add to the reported byte volume for signal `T`. Records are counted
    /// automatically by `evaluate`; bytes are opt-in and must be the
    /// uncompressed OTLP protobuf serialized size of the records as received
    /// (an estimate is fine) — the engine reads records through accessors and
    /// has no serialized form to measure. Leave it unreported rather than
    /// reporting another encoding's size.
    ///
    /// Typically called once per received batch with the batch's serialized
    /// size, not once per record.
    pub inline fn addBytes(self: *VolumeCounters, comptime T: policy_types.TelemetryType, bytes: i64) void {
        const counter = switch (T) {
            .log => &self.log_bytes,
            .metric => &self.metric_bytes,
            .trace => &self.span_bytes,
        };
        _ = counter.fetchAdd(bytes, .monotonic);
    }

    /// Read and zero every counter, for reporting on a sync request.
    pub fn readAndReset(self: *VolumeCounters) policy_provider.VolumeSnapshot {
        var out: policy_provider.VolumeSnapshot = .{};
        inline for (@typeInfo(policy_provider.VolumeSnapshot).@"struct".fields) |f| {
            @field(out, f.name) = @field(self, f.name).swap(0, .monotonic);
        }
        return out;
    }

    /// Add a drained reading back after a failed sync, so its records are
    /// included in the next attempt instead of being lost.
    pub fn add(self: *VolumeCounters, snapshot: policy_provider.VolumeSnapshot) void {
        inline for (@typeInfo(policy_provider.VolumeSnapshot).@"struct".fields) |f| {
            const v = @field(snapshot, f.name);
            if (v != 0) _ = @field(self, f.name).fetchAdd(v, .monotonic);
        }
    }
};

// =============================================================================
// Observability Events
// =============================================================================

const PolicyRegistryUnchanged = struct {};

/// Policy config types - derived from the Policy.target field
pub const PolicyConfigType = enum {
    /// Policy has a LogTarget (target.log)
    log_target,
    /// Policy has a MetricTarget (target.metric)
    metric_target,
    /// Policy has a TraceTarget (target.trace)
    trace_target,
    /// Policy has no config set
    none,

    /// Get the config type from a policy
    pub fn fromPolicy(policy: *const Policy) PolicyConfigType {
        const target = policy.target orelse return .none;
        return switch (target) {
            .log => .log_target,
            .metric => .metric_target,
            .trace => .trace_target,
        };
    }
};

/// Immutable snapshot of policies for lock-free reads
pub const PolicySnapshot = struct {
    /// All policies in this snapshot
    policies: []const Policy,

    /// Indices into policies array for log target policies
    /// Allows efficient lookup of policies by their config type
    log_target_indices: []const u32,

    /// Indices into policies array for metric target policies
    metric_target_indices: []const u32,

    /// Indices into policies array for trace target policies
    trace_target_indices: []const u32,

    /// Compiled Hyperscan-based matcher index for efficient log evaluation
    log_index: LogMatcherIndex,

    /// Compiled Hyperscan-based matcher index for efficient metric evaluation
    metric_index: MetricMatcherIndex,

    /// Compiled Hyperscan-based matcher index for efficient trace evaluation (OTLP only)
    trace_index: TraceMatcherIndex,

    /// Lock-free atomic stats per policy (indexed by policy position)
    /// Mutable even though snapshot is "immutable" - stats are append-only
    policy_stats: []PolicyAtomicStats,

    version: u64,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *PolicySnapshot) void {
        defer self.* = undefined;

        self.log_index.deinit();
        self.metric_index.deinit();
        self.trace_index.deinit();
        self.allocator.free(self.policies);
        self.allocator.free(self.log_target_indices);
        self.allocator.free(self.metric_target_indices);
        self.allocator.free(self.trace_target_indices);
        self.allocator.free(self.policy_stats);
    }

    /// Get atomic stats for a policy by index (for lock-free updates)
    pub fn getStats(self: *const PolicySnapshot, idx: u32) ?*PolicyAtomicStats {
        if (idx >= self.policy_stats.len) {
            return null;
        }
        return &self.policy_stats[idx];
    }

    /// Get a policy by index
    pub fn getPolicy(self: *const PolicySnapshot, idx: u32) ?*const Policy {
        if (idx >= self.policies.len) {
            return null;
        }
        return &self.policies[idx];
    }

    /// Get all log target policies
    pub fn getLogTargetPolicies(self: *const PolicySnapshot) []const Policy {
        if (self.log_target_indices.len == 0) {
            return &.{};
        }
        // Return a slice view - caller iterates using indices
        return self.policies;
    }

    /// Get log target policy indices for iteration
    pub fn getLogTargetIndices(self: *const PolicySnapshot) []const u32 {
        return self.log_target_indices;
    }

    /// Get metric target policy indices for iteration
    pub fn getMetricTargetIndices(self: *const PolicySnapshot) []const u32 {
        return self.metric_target_indices;
    }

    /// Iterator for log target policies
    pub fn iterateLogTargetPolicies(self: *const PolicySnapshot) LogTargetPolicyIterator {
        return .{
            .snapshot = self,
            .index = 0,
        };
    }

    /// Iterator for metric target policies
    pub fn iterateMetricTargetPolicies(self: *const PolicySnapshot) MetricTargetPolicyIterator {
        return .{
            .snapshot = self,
            .index = 0,
        };
    }

    pub const LogTargetPolicyIterator = struct {
        snapshot: *const PolicySnapshot,
        index: usize,

        pub fn next(self: *LogTargetPolicyIterator) ?*const Policy {
            if (self.index >= self.snapshot.log_target_indices.len) {
                return null;
            }
            const policy_idx = self.snapshot.log_target_indices[self.index];
            self.index += 1;
            return &self.snapshot.policies[policy_idx];
        }
    };

    pub const MetricTargetPolicyIterator = struct {
        snapshot: *const PolicySnapshot,
        index: usize,

        pub fn next(self: *MetricTargetPolicyIterator) ?*const Policy {
            if (self.index >= self.snapshot.metric_target_indices.len) {
                return null;
            }
            const policy_idx = self.snapshot.metric_target_indices[self.index];
            self.index += 1;
            return &self.snapshot.policies[policy_idx];
        }
    };
};

/// Grace period in nanoseconds before freeing old snapshots.
/// This allows in-flight readers to complete before memory is reclaimed.
const snapshot_grace_period_ns: u64 = 100 * std.time.ns_per_ms; // 100ms

/// Maximum number of pending snapshots waiting for cleanup.
/// If this limit is reached, we force cleanup of the oldest snapshots.
const max_pending_snapshots: usize = 8;

/// A snapshot pending cleanup after its grace period expires
const PendingSnapshot = struct {
    snapshot: *const PolicySnapshot,
    retire_time: i128, // Timestamp when snapshot was retired
};

/// Centralized policy registry with multi-source support
pub const PolicyRegistry = struct {
    // All policies stored together
    policies: std.ArrayList(Policy),

    // Source tracking for deduplication and priority
    // Key: policy id, Value: PolicyMetadata
    policy_sources: std.StringHashMap(PolicyMetadata),

    // Synchronization
    mutex: std.Io.Mutex,
    allocator: std.mem.Allocator,
    version: std.atomic.Value(u64),

    // Current immutable snapshot for lock-free reads
    current_snapshot: std.atomic.Value(?*const PolicySnapshot),

    // Snapshots pending cleanup after grace period
    pending_snapshots: std.ArrayList(PendingSnapshot),

    // Compile errors per policy id, replaced wholesale on each recompile.
    // The registry owns these (both keys and message strings) and surfaces them
    // to providers through the stats collector so they reach the control plane.
    policy_errors: std.StringHashMapUnmanaged(std.ArrayList([]const u8)),

    // Subscription contexts (stable pointers for callbacks)
    subscriptions: std.ArrayList(*Subscription),

    // Event bus for observability
    bus: *EventBus,

    // Optional extension resolver (v1.6.0), consulted at snapshot compile
    // time to resolve/validate each policy's extension declarations.
    extension_resolver: ?policy_types.ExtensionResolver,

    // Optional extension sync hooks (v1.6.0), pushed to each provider on
    // subscribe for capability advertisement + broadcast-config routing.
    extension_sync_hooks: ?policy_provider.ExtensionSyncHooks,

    // Total telemetry seen by the engine since the last successful sync
    // (v1.7.0), independent of any policy or snapshot.
    volume: VolumeCounters,

    /// Subscription context for provider callbacks.
    /// Allocated with stable address so the callback pointer remains valid.
    const Subscription = struct {
        registry: *PolicyRegistry,
        source_type: SourceType,

        fn handleUpdate(context: *anyopaque, update: policy_provider.PolicyUpdate) anyerror!void {
            const self: *Subscription = @ptrCast(@alignCast(context));
            try self.registry.updatePolicies(update.policies, update.provider_id, self.source_type);
        }

        fn init(registry: *PolicyRegistry, source_type: SourceType) Subscription {
            return .{
                .registry = registry,
                .source_type = source_type,
            };
        }
    };

    pub fn init(
        allocator: std.mem.Allocator,
        bus: *EventBus,
    ) PolicyRegistry {
        return .{
            .policies = .empty,
            .policy_sources = std.StringHashMap(PolicyMetadata).init(allocator),
            .mutex = .init,
            .allocator = allocator,
            .version = std.atomic.Value(u64).init(0),
            .current_snapshot = std.atomic.Value(?*const PolicySnapshot).init(null),
            .pending_snapshots = .empty,
            .policy_errors = .empty,
            .subscriptions = .empty,
            .bus = bus,
            .extension_resolver = null,
            .extension_sync_hooks = null,
            .volume = .{},
        };
    }

    /// Wire an extension resolver (v1.6.0), consulted at snapshot compile
    /// time. Call before providers deliver policies; takes effect on the next
    /// recompile. Without one, declared extensions are skipped (fail-open)
    /// and reported via PolicySyncStatus.errors.
    pub fn setExtensionResolver(self: *PolicyRegistry, resolver: policy_types.ExtensionResolver) void {
        self.extension_resolver = resolver;
    }

    /// Wire extension sync hooks (v1.6.0). Stored here and pushed to each
    /// provider on `subscribe`, so the consumer wires them once instead of
    /// per-provider. Call before `subscribe`; providers subscribed earlier
    /// won't retroactively receive them (matches the stats-collector contract).
    pub fn setExtensionSyncHooks(self: *PolicyRegistry, hooks: policy_provider.ExtensionSyncHooks) void {
        self.extension_sync_hooks = hooks;
    }

    /// Subscribe a provider to the registry in one step: hand it our stats
    /// collector (so it can pull per-policy hit/miss/error rows before each sync),
    /// hand it the extension sync hooks if any are wired, and subscribe to its
    /// policy updates with an internal callback that feeds updates back into the
    /// registry.
    pub fn subscribe(self: *PolicyRegistry, prov: Provider) !void {
        const sub = try self.allocator.create(Subscription);
        errdefer self.allocator.destroy(sub);
        sub.* = Subscription.init(self, prov.sourceType());

        try self.subscriptions.append(self.allocator, sub);
        errdefer _ = self.subscriptions.pop();

        prov.setStatsCollector(.{
            .context = self,
            .collect = collectStatsThunk,
            .collect_volume = drainVolumeThunk,
            .restore_volume = restoreVolumeThunk,
        });

        if (self.extension_sync_hooks) |hooks| {
            prov.setExtensionSyncHooks(hooks);
        }

        try prov.subscribe(.{
            .context = @ptrCast(sub),
            .onUpdate = Subscription.handleUpdate,
        });
    }

    fn collectStatsThunk(arena: std.mem.Allocator, context: *anyopaque) anyerror![]policy_provider.PolicyStatsSnapshot {
        const self: *PolicyRegistry = @ptrCast(@alignCast(context));
        return self.collectStats(arena);
    }

    fn drainVolumeThunk(context: *anyopaque) policy_provider.VolumeSnapshot {
        const self: *PolicyRegistry = @ptrCast(@alignCast(context));
        return self.volume.readAndReset();
    }

    fn restoreVolumeThunk(context: *anyopaque, snapshot: policy_provider.VolumeSnapshot) void {
        const self: *PolicyRegistry = @ptrCast(@alignCast(context));
        self.volume.add(snapshot);
    }

    /// Collect a stats row for every policy in the current snapshot, resetting
    /// the underlying atomic counters, and attach any compile errors recorded
    /// since the last recompile. Every policy is reported, including zero-hit
    /// ones, so the control plane knows the policy is live and being evaluated.
    ///
    /// Results (ids and error strings) are allocated in `arena` so they survive
    /// a concurrent recompile on another provider's thread; the registry retains
    /// no ownership of the returned slice.
    pub fn collectStats(self: *PolicyRegistry, arena: std.mem.Allocator) ![]policy_provider.PolicyStatsSnapshot {
        const snapshot = self.getSnapshot() orelse return &.{};

        self.mutex.lockUncancelable(self.bus.io);
        defer self.mutex.unlock(self.bus.io);

        const out = try arena.alloc(policy_provider.PolicyStatsSnapshot, snapshot.policies.len);
        for (snapshot.policies, 0..) |*p, i| {
            var hits: i64 = 0;
            var misses: i64 = 0;
            if (snapshot.getStats(@intCast(i))) |s| {
                const counters = s.readAndReset();
                hits = counters.hits;
                misses = counters.misses;
            }

            var errors: []const []const u8 = &.{};
            if (self.policy_errors.get(p.id)) |list| {
                const copy = try arena.alloc([]const u8, list.items.len);
                for (list.items, 0..) |msg, j| copy[j] = try arena.dupe(u8, msg);
                errors = copy;
            }

            out[i] = .{
                .id = try arena.dupe(u8, p.id),
                .hits = hits,
                .misses = misses,
                .transform_result = .{},
                .errors = errors,
            };
        }
        return out;
    }

    /// Record a compile error for a policy. Errors persist until the next
    /// recompile (which clears them via `clearPolicyErrorsLocked`) and are sent
    /// on every sync in between via `collectStats`.
    pub fn recordPolicyError(self: *PolicyRegistry, policy_id: []const u8, error_message: []const u8) void {
        self.mutex.lockUncancelable(self.bus.io);
        defer self.mutex.unlock(self.bus.io);
        self.recordPolicyErrorLocked(policy_id, error_message);
    }

    /// Store a policy error in the registry-owned map. Assumes the registry mutex
    /// is already held by the caller (used from `createSnapshot`, which runs under
    /// the lock — `recordPolicyError` would otherwise deadlock re-locking it).
    fn recordPolicyErrorLocked(self: *PolicyRegistry, policy_id: []const u8, error_message: []const u8) void {
        const msg_copy = self.allocator.dupe(u8, error_message) catch return;

        const gop = self.policy_errors.getOrPut(self.allocator, policy_id) catch {
            self.allocator.free(msg_copy);
            return;
        };
        if (!gop.found_existing) {
            const id_copy = self.allocator.dupe(u8, policy_id) catch {
                self.allocator.free(msg_copy);
                _ = self.policy_errors.remove(policy_id);
                return;
            };
            gop.key_ptr.* = id_copy;
            gop.value_ptr.* = .empty;
        }
        gop.value_ptr.append(self.allocator, msg_copy) catch self.allocator.free(msg_copy);
    }

    /// Free all stored policy errors. Assumes the registry mutex is held.
    fn clearPolicyErrorsLocked(self: *PolicyRegistry) void {
        var it = self.policy_errors.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items) |msg| self.allocator.free(msg);
            entry.value_ptr.deinit(self.allocator);
            self.allocator.free(entry.key_ptr.*);
        }
        self.policy_errors.clearRetainingCapacity();
    }

    pub fn deinit(self: *PolicyRegistry) void {
        defer self.* = undefined;

        // Free all stored policies (we own them via dupe)
        for (self.policies.items) |*policy| {
            policy.deinit(self.allocator);
        }
        self.policies.deinit(self.allocator);

        // Free source tracking keys and hashmap
        var it = self.policy_sources.keyIterator();
        while (it.next()) |key| {
            self.allocator.free(key.*);
        }
        self.policy_sources.deinit();

        // Free stored policy errors (keys + message strings + lists)
        self.clearPolicyErrorsLocked();
        self.policy_errors.deinit(self.allocator);

        // Free subscription contexts
        for (self.subscriptions.items) |sub| {
            self.allocator.destroy(sub);
        }
        self.subscriptions.deinit(self.allocator);

        // Free all pending snapshots (force cleanup, no grace period on shutdown)
        for (self.pending_snapshots.items) |pending| {
            @constCast(pending.snapshot).deinit();
            self.allocator.destroy(pending.snapshot);
        }
        self.pending_snapshots.deinit(self.allocator);

        // Free current snapshot if exists
        // Note: snapshot.policies is a shallow copy of self.policies, so its Policy
        // structs share pointers with the originals we just freed. snapshot.deinit()
        // only frees the array itself and matcher_index, not the policy contents.
        if (self.current_snapshot.load(.acquire)) |snapshot| {
            @constCast(snapshot).deinit();
            self.allocator.destroy(snapshot);
        }
    }

    /// Update policies from a specific provider
    /// Deduplicates by id and applies priority rules based on source_type
    pub fn updatePolicies(
        self: *PolicyRegistry,
        policies: []const Policy,
        provider_id: []const u8,
        source_type: SourceType,
    ) !void {
        self.mutex.lockUncancelable(self.bus.io);
        defer self.mutex.unlock(self.bus.io);

        // Track if any changes were made
        var changed = false;

        // Track which policy ids from this provider are in the new set
        var new_policy_ids = std.StringHashMap(void).init(self.allocator);
        defer {
            var it = new_policy_ids.keyIterator();
            while (it.next()) |key| {
                self.allocator.free(key.*);
            }
            new_policy_ids.deinit();
        }

        // Process each incoming policy
        for (policies) |policy| {
            const id_copy = try self.allocator.dupe(u8, policy.id);
            errdefer self.allocator.free(id_copy);

            // Track this id as present in new set
            try new_policy_ids.put(id_copy, {});

            // Check if policy already exists
            if (self.policy_sources.get(policy.id)) |existing_meta| {
                // Apply priority rules
                if (existing_meta.shouldReplace(source_type)) {
                    // Remove old policy and its source tracking
                    self.removePolicyById(policy.id);
                    if (self.policy_sources.fetchRemove(policy.id)) |kv| {
                        self.allocator.free(kv.key);
                    }

                    // Add new policy
                    try self.addPolicyInternal(policy, provider_id, source_type);
                    changed = true;
                }
                // else: higher priority source has priority, keep existing
            } else {
                // New policy, add it
                try self.addPolicyInternal(policy, provider_id, source_type);
                changed = true;
            }
        }

        // Remove policies from this provider that are no longer present
        const removed = try self.removeStalePolicies(provider_id, &new_policy_ids);
        if (removed > 0) {
            changed = true;
        }

        // Only create new snapshot if something changed
        if (changed) {
            try self.createSnapshot();
        } else {
            const event: PolicyRegistryUnchanged = .{};
            self.bus.debug(event);
        }
    }

    /// Add a policy and track its source
    /// Deep copies the policy so the registry owns the memory
    fn addPolicyInternal(
        self: *PolicyRegistry,
        policy: Policy,
        provider_id: []const u8,
        source_type: SourceType,
    ) !void {
        // Deep copy the policy so we own the memory
        var policy_copy = try policy.dupe(self.allocator);
        errdefer policy_copy.deinit(self.allocator);

        try self.policies.append(self.allocator, policy_copy);

        // Track source metadata by policy id
        const id_key = try self.allocator.dupe(u8, policy.id);
        errdefer self.allocator.free(id_key);

        try self.policy_sources.put(id_key, PolicyMetadata.init(self.bus.io, provider_id, source_type));
    }

    /// Remove a policy by id and free its memory
    fn removePolicyById(self: *PolicyRegistry, id: []const u8) void {
        for (self.policies.items, 0..) |*policy, i| {
            if (std.mem.eql(u8, policy.id, id)) {
                policy.deinit(self.allocator);
                _ = self.policies.swapRemove(i);
                break;
            }
        }
    }

    /// Remove policies from provider that are no longer in the new set
    /// Returns the number of policies removed
    fn removeStalePolicies(
        self: *PolicyRegistry,
        provider_id: []const u8,
        new_ids: *const std.StringHashMap(void),
    ) !usize {
        var ids_to_remove: std.ArrayList([]const u8) = .empty;
        defer ids_to_remove.deinit(self.allocator);

        // Find policies from this provider not in new set
        var it = self.policy_sources.iterator();
        while (it.next()) |entry| {
            const id = entry.key_ptr.*;
            const metadata = entry.value_ptr.*;

            // Only consider policies from this provider
            if (!std.mem.eql(u8, metadata.provider_id, provider_id)) continue;

            // If not in new set, mark for removal
            if (!new_ids.contains(id)) {
                try ids_to_remove.append(self.allocator, id);
            }
        }

        // Remove stale policies
        for (ids_to_remove.items) |id| {
            self.removePolicyById(id);

            // Remove from source tracking
            _ = self.policy_sources.remove(id);
            self.allocator.free(id);
        }

        return ids_to_remove.items.len;
    }

    /// Create immutable snapshot of current policies.
    ///
    /// All policies the registry currently holds are placed in the snapshot;
    /// capability-mismatch handling (a consumer's accessor not wiring `set`,
    /// `delete`, or `move`) happens at evaluate-time inside the transform
    /// dispatch, where transforms whose required primitive is null no-op
    /// silently. This keeps the registry capability-agnostic so a single
    /// snapshot can serve any number of consumers with differing accessors.
    fn createSnapshot(self: *PolicyRegistry) !void {
        const policies_slice = try self.allocator.alloc(Policy, self.policies.items.len);
        errdefer self.allocator.free(policies_slice);
        @memcpy(policies_slice, self.policies.items);

        // Sort policies by ID so that policy index order = alphanumeric ID order.
        // The spec requires transforms to be applied in alphanumeric order by policy ID.
        std.mem.sort(Policy, policies_slice, {}, struct {
            fn lessThan(_: void, a: Policy, b: Policy) bool {
                return std.mem.order(u8, a.id, b.id) == .lt;
            }
        }.lessThan);

        // Build indices by config type
        // First pass: count policies of each type
        var log_target_count: usize = 0;
        var metric_target_count: usize = 0;
        var trace_target_count: usize = 0;
        for (policies_slice) |*policy| {
            const config_type = PolicyConfigType.fromPolicy(policy);
            switch (config_type) {
                .log_target => log_target_count += 1,
                .metric_target => metric_target_count += 1,
                .trace_target => trace_target_count += 1,
                .none => {},
            }
        }

        // Allocate index arrays
        const log_target_indices = try self.allocator.alloc(u32, log_target_count);
        errdefer self.allocator.free(log_target_indices);

        const metric_target_indices = try self.allocator.alloc(u32, metric_target_count);
        errdefer self.allocator.free(metric_target_indices);

        const trace_target_indices = try self.allocator.alloc(u32, trace_target_count);
        errdefer self.allocator.free(trace_target_indices);

        // Second pass: populate indices
        var log_target_idx: usize = 0;
        var metric_target_idx: usize = 0;
        var trace_target_idx: usize = 0;
        for (policies_slice, 0..) |*policy, i| {
            const config_type = PolicyConfigType.fromPolicy(policy);
            switch (config_type) {
                .log_target => {
                    log_target_indices[log_target_idx] = @intCast(i);
                    log_target_idx += 1;
                },
                .metric_target => {
                    metric_target_indices[metric_target_idx] = @intCast(i);
                    metric_target_idx += 1;
                },
                .trace_target => {
                    trace_target_indices[trace_target_idx] = @intCast(i);
                    trace_target_idx += 1;
                },
                .none => {},
            }
        }

        // Build matcher indices for Hyperscan-based matching. Validation is
        // part of compilation: each builder validates the policies it owns,
        // skips any that fail (keeping them inert — never matching, dropping,
        // sampling, or transforming) while still compiling the rest of the
        // batch, and records the failures in `comp_errors`. See
        // IndexBuilder.validatePolicy and the spec's Error Handling section.
        var comp_errors = matcher_index.CompilationErrors.init(self.allocator);
        defer comp_errors.deinit();

        var log_idx = try LogMatcherIndex.build(
            self.allocator,
            self.bus,
            policies_slice,
            &comp_errors,
            self.extension_resolver,
        );
        errdefer log_idx.deinit();

        var metric_idx = try MetricMatcherIndex.build(
            self.allocator,
            self.bus,
            policies_slice,
            &comp_errors,
            self.extension_resolver,
        );
        errdefer metric_idx.deinit();

        var trace_idx = try TraceMatcherIndex.build(
            self.allocator,
            self.bus,
            policies_slice,
            &comp_errors,
            self.extension_resolver,
        );
        errdefer trace_idx.deinit();

        // Surface compilation errors via collectStats -> PolicySyncStatus.errors.
        // Replace the prior recompile's errors wholesale: this recompile is the
        // authoritative set, so stale errors for now-fixed policies must not
        // linger. createSnapshot runs under the registry mutex, so the locked
        // helpers are safe to call here.
        self.clearPolicyErrorsLocked();
        for (comp_errors.items.items) |entry| {
            self.recordPolicyErrorLocked(entry.policy_id, entry.message);
        }

        // Increment version
        const new_version = self.version.load(.monotonic) + 1;
        self.version.store(new_version, .monotonic);

        // Allocate atomic stats array for lock-free per-policy counters
        const policy_stats = try self.allocator.alloc(PolicyAtomicStats, policies_slice.len);
        errdefer self.allocator.free(policy_stats);
        // Initialize all stats to zero (default init does this)
        for (policy_stats) |*stat| {
            stat.* = .{};
        }

        // Create new snapshot with indices
        const snapshot = try self.allocator.create(PolicySnapshot);
        snapshot.* = .{
            .policies = policies_slice,
            .log_target_indices = log_target_indices,
            .metric_target_indices = metric_target_indices,
            .trace_target_indices = trace_target_indices,
            .log_index = log_idx,
            .metric_index = metric_idx,
            .trace_index = trace_idx,
            .policy_stats = policy_stats,
            .version = new_version,
            .allocator = self.allocator,
        };

        // Swap snapshot atomically
        const old_snapshot = self.current_snapshot.swap(snapshot, .acq_rel);

        // Defer cleanup of old snapshot to allow in-flight readers to complete.
        // This implements a simple grace period mechanism to prevent use-after-free.
        if (old_snapshot) |old| {
            // Monotonic clock: retire_time/elapsed is a grace-period duration,
            // so use `.awake` (immune to wall-clock/NTP jumps), consistent with
            // the read in cleanupExpiredSnapshots.
            const now: i128 = std.Io.Timestamp.now(self.bus.io, .awake).nanoseconds;
            try self.pending_snapshots.append(self.allocator, .{
                .snapshot = old,
                .retire_time = now,
            });
        }

        // Clean up snapshots whose grace period has expired
        self.cleanupExpiredSnapshots();
    }

    /// Clean up snapshots whose grace period has expired.
    /// Also forces cleanup if we have too many pending snapshots.
    fn cleanupExpiredSnapshots(self: *PolicyRegistry) void {
        // Monotonic clock to match the retire_time set during snapshot swap.
        const now: i128 = std.Io.Timestamp.now(self.bus.io, .awake).nanoseconds;
        var i: usize = 0;

        while (i < self.pending_snapshots.items.len) {
            const pending = self.pending_snapshots.items[i];
            const elapsed = now - pending.retire_time;
            const grace_expired = elapsed >= snapshot_grace_period_ns;
            const force_cleanup = self.pending_snapshots.items.len > max_pending_snapshots;

            if (grace_expired or force_cleanup) {
                // Grace period expired or too many pending - free this snapshot
                @constCast(pending.snapshot).deinit();
                self.allocator.destroy(pending.snapshot);
                _ = self.pending_snapshots.swapRemove(i);
                // Don't increment i - swapRemove moved an element into this position
            } else {
                i += 1;
            }
        }
    }

    /// Get current policy snapshot (lock-free read)
    pub fn getSnapshot(self: *const PolicyRegistry) ?*const PolicySnapshot {
        return self.current_snapshot.load(.acquire);
    }

    /// Clear all policies from a specific source
    /// Clear all policies from a specific provider
    pub fn clearProvider(self: *PolicyRegistry, provider_id: []const u8) !void {
        self.mutex.lockUncancelable(self.bus.io);
        defer self.mutex.unlock(self.bus.io);

        var ids_to_remove: std.ArrayList([]const u8) = .empty;
        defer ids_to_remove.deinit(self.allocator);

        // Find all policies from this provider
        var it = self.policy_sources.iterator();
        while (it.next()) |entry| {
            if (std.mem.eql(u8, entry.value_ptr.provider_id, provider_id)) {
                try ids_to_remove.append(self.allocator, entry.key_ptr.*);
            }
        }

        // Remove each policy
        for (ids_to_remove.items) |id| {
            self.removePolicyById(id);
            _ = self.policy_sources.remove(id);
            self.allocator.free(id);
        }

        // Create new snapshot
        try self.createSnapshot();
    }

    /// Get total policy count
    pub fn getPolicyCount(self: *const PolicyRegistry) usize {
        return self.policies.items.len;
    }
};

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;
const PolicyCallback = policy_provider.PolicyCallback;
const PolicyUpdate = policy_provider.PolicyUpdate;
const TestProvider = policy_types.TestProvider;

/// Helper to create a test policy with minimal required fields
fn createTestPolicy(
    allocator: std.mem.Allocator,
    name: []const u8,
) !Policy {
    var policy: Policy = .{
        .id = try allocator.dupe(u8, name), // Use name as id for tests
        .name = try allocator.dupe(u8, name),
        .enabled = true,
    };
    _ = &policy;

    return policy;
}

/// Helper to free a test policy created with createTestPolicy
fn freeTestPolicy(allocator: std.mem.Allocator, policy: *Policy) void {
    policy.deinit(allocator);
}

// -----------------------------------------------------------------------------
// Basic Registry Operations Tests
// -----------------------------------------------------------------------------

test "PolicyRegistry: init and deinit with no policies" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    try testing.expectEqual(@as(usize, 0), registry.getPolicyCount());
    try testing.expect(registry.getSnapshot() == null);
}

test "PolicyRegistry: add single policy" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var policy = try createTestPolicy(allocator, "test-policy");
    defer freeTestPolicy(allocator, &policy);

    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);
    try testing.expectEqual(@as(usize, 1), snapshot.?.policies.len);
    try testing.expectEqualStrings("test-policy", snapshot.?.policies[0].name);
}

test "PolicyRegistry: add multiple policies" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var policy1 = try createTestPolicy(allocator, "policy-1");
    defer freeTestPolicy(allocator, &policy1);

    var policy2 = try createTestPolicy(allocator, "policy-2");
    defer freeTestPolicy(allocator, &policy2);

    var policy3 = try createTestPolicy(allocator, "policy-3");
    defer freeTestPolicy(allocator, &policy3);

    try registry.updatePolicies(&.{ policy1, policy2, policy3 }, "file-provider", .file);

    try testing.expectEqual(@as(usize, 3), registry.getPolicyCount());

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);
    try testing.expectEqual(@as(usize, 3), snapshot.?.policies.len);
}

test "PolicyRegistry: update existing policy from same source" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Add initial policy
    var policy1 = try createTestPolicy(allocator, "test-policy");
    defer freeTestPolicy(allocator, &policy1);

    try registry.updatePolicies(&.{policy1}, "file-provider", .file);
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());

    // Update with same name but different description
    var policy2 = try createTestPolicy(allocator, "test-policy");
    policy2.description = try allocator.dupe(u8, "updated description");
    defer freeTestPolicy(allocator, &policy2);

    try registry.updatePolicies(&.{policy2}, "file-provider", .file);

    // Should still have 1 policy, but updated
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);
    try testing.expectEqualStrings("updated description", snapshot.?.policies[0].description);
}

// -----------------------------------------------------------------------------
// Source Priority Tests
// -----------------------------------------------------------------------------

test "PolicyRegistry: HTTP source takes priority over file source" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Add policy from HTTP source
    var http_policy = try createTestPolicy(allocator, "shared-policy");
    http_policy.description = try allocator.dupe(u8, "http version");
    defer freeTestPolicy(allocator, &http_policy);

    try registry.updatePolicies(&.{http_policy}, "http-provider", .http);

    // Try to update with file source (should be ignored)
    var file_policy = try createTestPolicy(allocator, "shared-policy");
    file_policy.description = try allocator.dupe(u8, "file version");
    defer freeTestPolicy(allocator, &file_policy);

    try registry.updatePolicies(&.{file_policy}, "file-provider", .file);

    // Should still have the HTTP version
    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);
    try testing.expectEqual(@as(usize, 1), snapshot.?.policies.len);
    try testing.expectEqualStrings("http version", snapshot.?.policies[0].description);
}

test "PolicyRegistry: HTTP source can update file source policy" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Add policy from file source
    var file_policy = try createTestPolicy(allocator, "shared-policy");
    file_policy.description = try allocator.dupe(u8, "file version");
    defer freeTestPolicy(allocator, &file_policy);

    try registry.updatePolicies(&.{file_policy}, "file-provider", .file);

    // Update with HTTP source (should replace)
    var http_policy = try createTestPolicy(allocator, "shared-policy");
    http_policy.description = try allocator.dupe(u8, "http version");
    defer freeTestPolicy(allocator, &http_policy);

    try registry.updatePolicies(&.{http_policy}, "http-provider", .http);

    // Should have the HTTP version
    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);
    try testing.expectEqual(@as(usize, 1), snapshot.?.policies.len);
    try testing.expectEqualStrings("http version", snapshot.?.policies[0].description);
}

test "PolicyRegistry: multiple sources with different policies" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Add policies from file source
    var file_policy = try createTestPolicy(allocator, "file-only-policy");
    defer freeTestPolicy(allocator, &file_policy);

    try registry.updatePolicies(&.{file_policy}, "file-provider", .file);

    // Add policies from HTTP source
    var http_policy = try createTestPolicy(allocator, "http-only-policy");
    defer freeTestPolicy(allocator, &http_policy);

    try registry.updatePolicies(&.{http_policy}, "http-provider", .http);

    // Should have both policies
    try testing.expectEqual(@as(usize, 2), registry.getPolicyCount());
}

// -----------------------------------------------------------------------------
// Stale Policy Removal Tests
// -----------------------------------------------------------------------------

test "PolicyRegistry: stale policies are removed when source updates" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Add two policies from file source
    var policy1 = try createTestPolicy(allocator, "policy-1");
    defer freeTestPolicy(allocator, &policy1);

    var policy2 = try createTestPolicy(allocator, "policy-2");
    defer freeTestPolicy(allocator, &policy2);

    try registry.updatePolicies(&.{ policy1, policy2 }, "file-provider", .file);
    try testing.expectEqual(@as(usize, 2), registry.getPolicyCount());

    // Update with only one policy (policy-2 should be removed)
    try registry.updatePolicies(&.{policy1}, "file-provider", .file);
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);
    try testing.expectEqualStrings("policy-1", snapshot.?.policies[0].name);
}

test "PolicyRegistry: stale removal only affects same source" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Add policy from file source
    var file_policy = try createTestPolicy(allocator, "file-policy");
    defer freeTestPolicy(allocator, &file_policy);

    try registry.updatePolicies(&.{file_policy}, "file-provider", .file);

    // Add policy from HTTP source
    var http_policy = try createTestPolicy(allocator, "http-policy");
    defer freeTestPolicy(allocator, &http_policy);

    try registry.updatePolicies(&.{http_policy}, "http-provider", .http);
    try testing.expectEqual(@as(usize, 2), registry.getPolicyCount());

    // Update file source with empty set (should only remove file-policy)
    try registry.updatePolicies(&.{}, "file-provider", .file);
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);
    try testing.expectEqualStrings("http-policy", snapshot.?.policies[0].name);
}

test "PolicyRegistry: clearProvider removes all policies from provider" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Add policies from both sources
    var file_policy = try createTestPolicy(allocator, "file-policy");
    defer freeTestPolicy(allocator, &file_policy);

    var http_policy = try createTestPolicy(allocator, "http-policy");
    defer freeTestPolicy(allocator, &http_policy);

    try registry.updatePolicies(&.{file_policy}, "file-provider", .file);
    try registry.updatePolicies(&.{http_policy}, "http-provider", .http);
    try testing.expectEqual(@as(usize, 2), registry.getPolicyCount());

    // Clear file provider
    try registry.clearProvider("file-provider");
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);
    try testing.expectEqualStrings("http-policy", snapshot.?.policies[0].name);
}

// -----------------------------------------------------------------------------
// Snapshot Versioning Tests
// -----------------------------------------------------------------------------

test "PolicyRegistry: snapshot version increments on update" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var policy = try createTestPolicy(allocator, "test-policy");
    defer freeTestPolicy(allocator, &policy);

    // First update
    try registry.updatePolicies(&.{policy}, "file-provider", .file);
    const snapshot1 = registry.getSnapshot();
    try testing.expect(snapshot1 != null);
    try testing.expectEqual(@as(u64, 1), snapshot1.?.version);

    // Second update
    try registry.updatePolicies(&.{policy}, "file-provider", .file);
    const snapshot2 = registry.getSnapshot();
    try testing.expect(snapshot2 != null);
    try testing.expectEqual(@as(u64, 2), snapshot2.?.version);

    // Third update
    try registry.updatePolicies(&.{}, "file-provider", .file);
    const snapshot3 = registry.getSnapshot();
    try testing.expect(snapshot3 != null);
    try testing.expectEqual(@as(u64, 3), snapshot3.?.version);
}

test "PolicyRegistry: clearProvider increments version" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var policy = try createTestPolicy(allocator, "test-policy");
    defer freeTestPolicy(allocator, &policy);

    try registry.updatePolicies(&.{policy}, "file-provider", .file);
    const version_before = registry.getSnapshot().?.version;

    try registry.clearProvider("file-provider");
    const version_after = registry.getSnapshot().?.version;

    try testing.expect(version_after > version_before);
}

// -----------------------------------------------------------------------------
// TestProvider Integration Tests
// -----------------------------------------------------------------------------

test "TestProvider: basic functionality" {
    const allocator = testing.allocator;

    var prov = TestProvider.init(allocator, "file-provider", .file);
    defer prov.deinit();

    // Add a policy
    var policy = try createTestPolicy(allocator, "provider-policy");
    defer freeTestPolicy(allocator, &policy);

    try prov.addPolicy(policy);
    try testing.expectEqual(@as(usize, 1), prov.policies.items.len);

    // Remove the policy
    prov.removePolicy("provider-policy");
    try testing.expectEqual(@as(usize, 0), prov.policies.items.len);
}

test "TestProvider: integrates with PolicyRegistry" {
    const allocator = testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var file_provider = TestProvider.init(allocator, "file-provider", .file);
    defer file_provider.deinit();

    // Add policy to provider
    var policy = try createTestPolicy(allocator, "provider-policy");
    defer freeTestPolicy(allocator, &policy);

    try file_provider.addPolicy(policy);

    // Create callback that updates registry
    const Ctx = struct {
        const Self = @This();

        registry: *PolicyRegistry,
        source_type: SourceType,

        fn onUpdate(ctx_ptr: *anyopaque, update: PolicyUpdate) anyerror!void {
            const self: *Self = @ptrCast(@alignCast(ctx_ptr));
            try self.registry.updatePolicies(update.policies, update.provider_id, self.source_type);
        }
    };

    var ctx: Ctx = .{ .registry = &registry, .source_type = .file };
    const callback: PolicyCallback = .{
        .context = &ctx,
        .onUpdate = Ctx.onUpdate,
    };

    // Subscribe - should immediately update registry
    try file_provider.subscribe(callback);

    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());
    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);
    try testing.expectEqualStrings("provider-policy", snapshot.?.policies[0].name);
}

test "TestProvider: multiple providers with different sources" {
    const allocator = testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var file_provider = TestProvider.init(allocator, "file-provider", .file);
    defer file_provider.deinit();

    var http_provider = TestProvider.init(allocator, "http-provider", .http);
    defer http_provider.deinit();

    // Add policies to providers
    var file_policy = try createTestPolicy(allocator, "file-policy");
    defer freeTestPolicy(allocator, &file_policy);

    var http_policy = try createTestPolicy(allocator, "http-policy");
    defer freeTestPolicy(allocator, &http_policy);

    try file_provider.addPolicy(file_policy);
    try http_provider.addPolicy(http_policy);

    // Create callbacks with source types
    const Ctx = struct {
        const Self = @This();

        registry: *PolicyRegistry,
        source_type: SourceType,

        fn onUpdate(ctx_ptr: *anyopaque, update: PolicyUpdate) anyerror!void {
            const self: *Self = @ptrCast(@alignCast(ctx_ptr));
            try self.registry.updatePolicies(update.policies, update.provider_id, self.source_type);
        }
    };

    var file_ctx: Ctx = .{ .registry = &registry, .source_type = .file };
    const file_callback: PolicyCallback = .{
        .context = &file_ctx,
        .onUpdate = Ctx.onUpdate,
    };

    var http_ctx: Ctx = .{ .registry = &registry, .source_type = .http };
    const http_callback: PolicyCallback = .{
        .context = &http_ctx,
        .onUpdate = Ctx.onUpdate,
    };

    // Subscribe to both providers
    try file_provider.subscribe(file_callback);
    try http_provider.subscribe(http_callback);

    // Registry should have both policies
    try testing.expectEqual(@as(usize, 2), registry.getPolicyCount());
}

test "TestProvider: notifySubscribers updates registry" {
    const allocator = testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var prov = TestProvider.init(allocator, "file-provider", .file);
    defer prov.deinit();

    // Create and subscribe callback
    const Ctx = struct {
        const Self = @This();

        registry: *PolicyRegistry,
        source_type: SourceType,

        fn onUpdate(ctx_ptr: *anyopaque, update: PolicyUpdate) anyerror!void {
            const self: *Self = @ptrCast(@alignCast(ctx_ptr));
            try self.registry.updatePolicies(update.policies, update.provider_id, self.source_type);
        }
    };

    var ctx: Ctx = .{ .registry = &registry, .source_type = .file };
    const callback: PolicyCallback = .{
        .context = &ctx,
        .onUpdate = Ctx.onUpdate,
    };

    try prov.subscribe(callback);
    try testing.expectEqual(@as(usize, 0), registry.getPolicyCount());

    // Add policy and notify
    var policy1 = try createTestPolicy(allocator, "policy-1");
    defer freeTestPolicy(allocator, &policy1);

    try prov.addPolicy(policy1);
    try prov.notifySubscribers();

    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());

    // Add another policy and notify
    var policy2 = try createTestPolicy(allocator, "policy-2");
    defer freeTestPolicy(allocator, &policy2);

    try prov.addPolicy(policy2);
    try prov.notifySubscribers();

    try testing.expectEqual(@as(usize, 2), registry.getPolicyCount());

    // Remove policy and notify
    prov.removePolicy("policy-1");
    try prov.notifySubscribers();

    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);
    try testing.expectEqualStrings("policy-2", snapshot.?.policies[0].name);
}

test "TestProvider: HTTP provider overrides file provider" {
    const allocator = testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var file_provider = TestProvider.init(allocator, "file-provider", .file);
    defer file_provider.deinit();

    var http_provider = TestProvider.init(allocator, "http-provider", .http);
    defer http_provider.deinit();

    // Create callbacks with source types
    const Ctx = struct {
        const Self = @This();

        registry: *PolicyRegistry,
        source_type: SourceType,

        fn onUpdate(ctx_ptr: *anyopaque, update: PolicyUpdate) anyerror!void {
            const self: *Self = @ptrCast(@alignCast(ctx_ptr));
            try self.registry.updatePolicies(update.policies, update.provider_id, self.source_type);
        }
    };

    var file_ctx: Ctx = .{ .registry = &registry, .source_type = .file };
    const file_callback: PolicyCallback = .{
        .context = &file_ctx,
        .onUpdate = Ctx.onUpdate,
    };

    var http_ctx: Ctx = .{ .registry = &registry, .source_type = .http };
    const http_callback: PolicyCallback = .{
        .context = &http_ctx,
        .onUpdate = Ctx.onUpdate,
    };

    // Add same-named policy to file provider first
    var file_policy = try createTestPolicy(allocator, "shared-policy");
    file_policy.description = try allocator.dupe(u8, "file version 1");
    defer freeTestPolicy(allocator, &file_policy);

    try file_provider.addPolicy(file_policy);
    try file_provider.subscribe(file_callback);

    // Verify file policy is in registry
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());
    try testing.expectEqualStrings(
        "file version 1",
        registry.getSnapshot().?.policies[0].description,
    );

    // Add same-named policy to HTTP provider (should override)
    var http_policy = try createTestPolicy(allocator, "shared-policy");
    http_policy.description = try allocator.dupe(u8, "http version");
    defer freeTestPolicy(allocator, &http_policy);

    try http_provider.addPolicy(http_policy);
    try http_provider.subscribe(http_callback);

    // Verify HTTP policy replaced file policy
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());
    try testing.expectEqualStrings(
        "http version",
        registry.getSnapshot().?.policies[0].description,
    );

    // Update file provider - should NOT override HTTP
    file_provider.clearPolicies();
    var file_policy2 = try createTestPolicy(allocator, "shared-policy");
    file_policy2.description = try allocator.dupe(u8, "file version 2");
    defer freeTestPolicy(allocator, &file_policy2);

    try file_provider.addPolicy(file_policy2);
    try file_provider.notifySubscribers();

    // Should still have HTTP version
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());
    try testing.expectEqualStrings(
        "http version",
        registry.getSnapshot().?.policies[0].description,
    );
}

// -----------------------------------------------------------------------------
// Policy Config Type Indexing Tests
// -----------------------------------------------------------------------------

const LogTarget = proto.policy.LogTarget;

/// Helper to create a test policy with a log target config
fn createTestPolicyWithFilter(
    allocator: std.mem.Allocator,
    name: []const u8,
) !Policy {
    var policy: Policy = .{
        .id = try allocator.dupe(u8, name), // Use name as id for tests
        .name = try allocator.dupe(u8, name),
        .enabled = true,
        .target = .{ .log = LogTarget{
            .match = .empty,
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    _ = &policy;

    return policy;
}

test "PolicyConfigType: fromPolicy returns log_target when log is set" {
    const allocator = testing.allocator;

    var policy = try createTestPolicyWithFilter(allocator, "filter-policy");
    defer freeTestPolicy(allocator, &policy);

    const config_type = PolicyConfigType.fromPolicy(&policy);
    try testing.expectEqual(PolicyConfigType.log_target, config_type);
}

test "PolicyConfigType: fromPolicy returns none when log is null" {
    const allocator = testing.allocator;

    var policy = try createTestPolicy(allocator, "no-filter-policy");
    defer freeTestPolicy(allocator, &policy);

    const config_type = PolicyConfigType.fromPolicy(&policy);
    try testing.expectEqual(PolicyConfigType.none, config_type);
}

test "PolicySnapshot: log_target_indices contains only log policies" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create mix of policies with and without log targets
    var policy_no_filter = try createTestPolicy(allocator, "no-filter");
    defer freeTestPolicy(allocator, &policy_no_filter);

    var policy_with_filter = try createTestPolicyWithFilter(allocator, "with-filter");
    defer freeTestPolicy(allocator, &policy_with_filter);

    var another_no_filter = try createTestPolicy(allocator, "another-no-filter");
    defer freeTestPolicy(allocator, &another_no_filter);

    try registry.updatePolicies(&.{ policy_no_filter, policy_with_filter, another_no_filter }, "file-provider", .file);

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);

    // Should have 3 total policies but only 1 log target index
    try testing.expectEqual(@as(usize, 3), snapshot.?.policies.len);
    try testing.expectEqual(@as(usize, 1), snapshot.?.log_target_indices.len);

    // The indexed policy should be the one with log target
    const indexed_policy = snapshot.?.policies[snapshot.?.log_target_indices[0]];
    try testing.expectEqualStrings("with-filter", indexed_policy.name);
    try testing.expect(indexed_policy.target != null);
}

test "PolicySnapshot: multiple log policies are indexed" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var filter1 = try createTestPolicyWithFilter(allocator, "filter-1");
    defer freeTestPolicy(allocator, &filter1);

    var filter2 = try createTestPolicyWithFilter(allocator, "filter-2");
    defer freeTestPolicy(allocator, &filter2);

    var filter3 = try createTestPolicyWithFilter(allocator, "filter-3");
    defer freeTestPolicy(allocator, &filter3);

    try registry.updatePolicies(&.{ filter1, filter2, filter3 }, "file-provider", .file);

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);

    // All 3 policies should be indexed
    try testing.expectEqual(@as(usize, 3), snapshot.?.policies.len);
    try testing.expectEqual(@as(usize, 3), snapshot.?.log_target_indices.len);
}

test "PolicySnapshot: empty when no log policies" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var policy1 = try createTestPolicy(allocator, "policy-1");
    defer freeTestPolicy(allocator, &policy1);

    var policy2 = try createTestPolicy(allocator, "policy-2");
    defer freeTestPolicy(allocator, &policy2);

    try registry.updatePolicies(&.{ policy1, policy2 }, "file-provider", .file);

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);

    // No log target indices
    try testing.expectEqual(@as(usize, 2), snapshot.?.policies.len);
    try testing.expectEqual(@as(usize, 0), snapshot.?.log_target_indices.len);
}

test "PolicySnapshot: iterateLogTargetPolicies returns all log policies" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var no_filter = try createTestPolicy(allocator, "no-filter");
    defer freeTestPolicy(allocator, &no_filter);

    var filter1 = try createTestPolicyWithFilter(allocator, "filter-1");
    defer freeTestPolicy(allocator, &filter1);

    var filter2 = try createTestPolicyWithFilter(allocator, "filter-2");
    defer freeTestPolicy(allocator, &filter2);

    try registry.updatePolicies(&.{ no_filter, filter1, filter2 }, "file-provider", .file);

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);

    // Iterate and collect names
    var iter = snapshot.?.iterateLogTargetPolicies();
    var count: usize = 0;
    var found_filter1 = false;
    var found_filter2 = false;

    while (iter.next()) |policy| {
        count += 1;
        try testing.expect(policy.target != null);

        if (std.mem.eql(u8, policy.name, "filter-1")) {
            found_filter1 = true;
        } else if (std.mem.eql(u8, policy.name, "filter-2")) {
            found_filter2 = true;
        }
    }

    try testing.expectEqual(@as(usize, 2), count);
    try testing.expect(found_filter1);
    try testing.expect(found_filter2);
}

test "PolicySnapshot: iterator returns null when no log policies" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var policy = try createTestPolicy(allocator, "no-filter");
    defer freeTestPolicy(allocator, &policy);

    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);

    var iter = snapshot.?.iterateLogTargetPolicies();
    try testing.expect(iter.next() == null);
}

test "PolicySnapshot: indices update when policies change" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Start with one log policy
    var filter1 = try createTestPolicyWithFilter(allocator, "filter-1");
    defer freeTestPolicy(allocator, &filter1);

    try registry.updatePolicies(&.{filter1}, "file-provider", .file);

    var snapshot = registry.getSnapshot();
    try testing.expectEqual(@as(usize, 1), snapshot.?.log_target_indices.len);

    // Add another log policy
    var filter2 = try createTestPolicyWithFilter(allocator, "filter-2");
    defer freeTestPolicy(allocator, &filter2);

    try registry.updatePolicies(&.{ filter1, filter2 }, "file-provider", .file);

    snapshot = registry.getSnapshot();
    try testing.expectEqual(@as(usize, 2), snapshot.?.log_target_indices.len);

    // Remove log policies, add non-log
    var no_filter = try createTestPolicy(allocator, "no-filter");
    defer freeTestPolicy(allocator, &no_filter);

    try registry.updatePolicies(&.{no_filter}, "file-provider", .file);

    snapshot = registry.getSnapshot();
    try testing.expectEqual(@as(usize, 0), snapshot.?.log_target_indices.len);
}

// -----------------------------------------------------------------------------
// Policy Error Routing Tests
// -----------------------------------------------------------------------------

/// Test helper: find the collected stats row for a policy id.
fn findStats(
    stats: []const policy_provider.PolicyStatsSnapshot,
    id: []const u8,
) ?policy_provider.PolicyStatsSnapshot {
    for (stats) |s| {
        if (std.mem.eql(u8, s.id, id)) return s;
    }
    return null;
}

/// Test helper: does the collected stats row for `id` contain error `msg`?
fn statsHasError(
    stats: []const policy_provider.PolicyStatsSnapshot,
    id: []const u8,
    msg: []const u8,
) bool {
    const s = findStats(stats, id) orelse return false;
    for (s.errors) |e| {
        if (std.mem.eql(u8, e, msg)) return true;
    }
    return false;
}

test "PolicyRegistry: collectStats drains hit/miss counters and reports every policy" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var hot = try createTestPolicy(allocator, "hot-policy");
    defer freeTestPolicy(allocator, &hot);
    var cold = try createTestPolicy(allocator, "cold-policy");
    defer freeTestPolicy(allocator, &cold);
    try registry.updatePolicies(&.{ hot, cold }, "http-provider", .http);

    // Simulate the data path bumping lock-free counters on the live snapshot.
    const snapshot = registry.getSnapshot() orelse return error.NoSnapshot;
    for (snapshot.policies, 0..) |*p, i| {
        if (std.mem.eql(u8, p.id, "hot-policy")) {
            const s = snapshot.getStats(@intCast(i)).?;
            s.addHit();
            s.addHit();
            s.addHit();
            s.addMiss();
        }
    }

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const stats = try registry.collectStats(arena.allocator());

    // Both policies are reported, including the one that never matched.
    try testing.expectEqual(@as(usize, 2), stats.len);
    const hot_row = findStats(stats, "hot-policy") orelse return error.MissingHot;
    try testing.expectEqual(@as(i64, 3), hot_row.hits);
    try testing.expectEqual(@as(i64, 1), hot_row.misses);
    const cold_row = findStats(stats, "cold-policy") orelse return error.MissingCold;
    try testing.expectEqual(@as(i64, 0), cold_row.hits);
    try testing.expectEqual(@as(i64, 0), cold_row.misses);

    // A second collect reports zeros — the first collect reset the counters.
    const stats2 = try registry.collectStats(arena.allocator());
    const hot_row2 = findStats(stats2, "hot-policy") orelse return error.MissingHot;
    try testing.expectEqual(@as(i64, 0), hot_row2.hits);
    try testing.expectEqual(@as(i64, 0), hot_row2.misses);
}

test "PolicyRegistry: volume counters survive recompiles and accept add-back" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    registry.volume.record(.log);
    registry.volume.addBytes(.log, 100);
    registry.volume.record(.metric); // metric bytes left untracked
    registry.volume.record(.trace);
    registry.volume.addBytes(.trace, 40);

    // A recompile allocates fresh per-policy stats; volume lives outside the
    // snapshot and must not be zeroed by it.
    var p = try createTestPolicy(allocator, "p");
    defer freeTestPolicy(allocator, &p);
    try registry.updatePolicies(&.{p}, "http-provider", .http);

    const drained = registry.volume.readAndReset();
    try testing.expectEqual(@as(i64, 1), drained.log_records);
    try testing.expectEqual(@as(i64, 100), drained.log_bytes);
    try testing.expectEqual(@as(i64, 1), drained.metric_data_points);
    try testing.expectEqual(@as(i64, 0), drained.metric_bytes);
    try testing.expectEqual(@as(i64, 1), drained.spans);
    try testing.expectEqual(@as(i64, 40), drained.span_bytes);
    try testing.expect(registry.volume.readAndReset().isZero());

    // A failed sync hands the reading back; records seen in the meantime are
    // preserved, so the next attempt reports the sum.
    registry.volume.record(.log);
    registry.volume.addBytes(.log, 7);
    registry.volume.add(drained);
    const retried = registry.volume.readAndReset();
    try testing.expectEqual(@as(i64, 2), retried.log_records);
    try testing.expectEqual(@as(i64, 107), retried.log_bytes);
    try testing.expectEqual(@as(i64, 1), retried.spans);
}

test "VolumeCounters: add folds every field back into its own counter" {
    var counters: VolumeCounters = .{};

    // All six distinct and non-zero, so a field dropped or crossed over in
    // `add` shows up instead of being masked by a zero.
    counters.add(.{
        .log_records = 1,
        .log_bytes = 2,
        .metric_data_points = 3,
        .metric_bytes = 4,
        .spans = 5,
        .span_bytes = 6,
    });
    // Folding is additive, not assignment: a second add sums.
    counters.add(.{
        .log_records = 10,
        .log_bytes = 20,
        .metric_data_points = 30,
        .metric_bytes = 40,
        .spans = 50,
        .span_bytes = 60,
    });

    const out = counters.readAndReset();
    try testing.expectEqual(@as(i64, 11), out.log_records);
    try testing.expectEqual(@as(i64, 22), out.log_bytes);
    try testing.expectEqual(@as(i64, 33), out.metric_data_points);
    try testing.expectEqual(@as(i64, 44), out.metric_bytes);
    try testing.expectEqual(@as(i64, 55), out.spans);
    try testing.expectEqual(@as(i64, 66), out.span_bytes);
    try testing.expect(counters.readAndReset().isZero());
}

test "PolicyRegistry: subscribe wires the volume seam to this registry" {
    const provider_http = @import("./provider_http.zig");

    const allocator = testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Port 1 has nothing listening: subscribe's initial fetch fails and is
    // warned about, which is fine — the wiring under test happens before it.
    var provider = try provider_http.HttpProvider.init(
        allocator,
        io,
        noop_bus.eventBus(),
        .{ .id = "p", .url = "http://127.0.0.1:1/sync", .poll_interval_seconds = 3600 },
    );
    defer provider.deinit();
    try registry.subscribe(.{ .http = provider });
    // Stop the poll thread before the registry it drains goes away.
    provider.shutdown();

    // Nothing else in the suite proves subscribe passed the volume fns (the
    // provider tests install collectors by hand), so assert the seam exists and
    // that both directions land on *this* registry's counters.
    const collector = provider.stats_collector orelse return error.NoCollector;
    try testing.expect(collector.collect_volume != null);
    try testing.expect(collector.restore_volume != null);

    registry.volume.record(.log);
    registry.volume.addBytes(.log, 64);
    const drained = collector.drainVolume();
    try testing.expectEqual(@as(i64, 1), drained.log_records);
    try testing.expectEqual(@as(i64, 64), drained.log_bytes);
    try testing.expect(registry.volume.readAndReset().isZero());

    collector.returnVolume(drained);
    const restored = registry.volume.readAndReset();
    try testing.expectEqual(@as(i64, 1), restored.log_records);
    try testing.expectEqual(@as(i64, 64), restored.log_bytes);
}

test "PolicyRegistry: collectStats reports exactly the current policy set across updates" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    // Start with two policies.
    var a = try createTestPolicy(allocator, "policy-a");
    defer freeTestPolicy(allocator, &a);
    var b = try createTestPolicy(allocator, "policy-b");
    defer freeTestPolicy(allocator, &b);
    try registry.updatePolicies(&.{ a, b }, "http-provider", .http);

    {
        const stats = try registry.collectStats(arena.allocator());
        try testing.expectEqual(@as(usize, 2), stats.len);
        try testing.expect(findStats(stats, "policy-a") != null);
        try testing.expect(findStats(stats, "policy-b") != null);
    }

    // Replace the provider's set with a different policy: b is gone, c is added.
    var c = try createTestPolicy(allocator, "policy-c");
    defer freeTestPolicy(allocator, &c);
    try registry.updatePolicies(&.{ a, c }, "http-provider", .http);

    {
        const stats = try registry.collectStats(arena.allocator());
        // Exactly the current set — no stale policy-b, no duplicates.
        try testing.expectEqual(@as(usize, 2), stats.len);
        try testing.expect(findStats(stats, "policy-a") != null);
        try testing.expect(findStats(stats, "policy-c") != null);
        try testing.expect(findStats(stats, "policy-b") == null);
    }
}

test "PolicyRegistry: recordPolicyError is surfaced per policy via collectStats" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Add policies from different sources
    var file_policy = try createTestPolicy(allocator, "file-policy-1");
    defer freeTestPolicy(allocator, &file_policy);

    var http_policy = try createTestPolicy(allocator, "http-policy-1");
    defer freeTestPolicy(allocator, &http_policy);

    try registry.updatePolicies(&.{file_policy}, "file-provider", .file);
    try registry.updatePolicies(&.{http_policy}, "http-provider", .http);

    // Record errors (after the last recompile, so they persist until the next)
    registry.recordPolicyError("file-policy-1", "Invalid regex in file policy");
    registry.recordPolicyError("http-policy-1", "Invalid regex in http policy");

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const stats = try registry.collectStats(arena.allocator());

    // Each error is attached to its own policy's stats row...
    try testing.expect(statsHasError(stats, "file-policy-1", "Invalid regex in file policy"));
    try testing.expect(statsHasError(stats, "http-policy-1", "Invalid regex in http policy"));

    // ...with no cross-contamination.
    try testing.expect(!statsHasError(stats, "file-policy-1", "Invalid regex in http policy"));
    try testing.expect(!statsHasError(stats, "http-policy-1", "Invalid regex in file policy"));
}

test "PolicyRegistry: invalid policy is inert and reported, valid policy in same batch still compiles" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // One valid policy and one with an uncompilable regex, in the same batch.
    const policies = try parser.parsePoliciesBytes(allocator,
        \\{"policies":[
        \\  {"id":"aaa-valid","name":"valid","log":{
        \\    "match":[{"log_field":"body","regex":"error"}],"keep":"none"}},
        \\  {"id":"zzz-broken","name":"broken","log":{
        \\    "match":[{"log_field":"body","regex":"([a-z"}],"keep":"all"}}
        \\]}
    );
    defer {
        for (policies) |*p| @constCast(p).deinit(allocator);
        allocator.free(policies);
    }

    // The broken regex must NOT abort the batch: updatePolicies succeeds even
    // though one policy fails to compile.
    try registry.updatePolicies(policies, "file-provider", .file);

    const snapshot = registry.getSnapshot() orelse return error.NoSnapshot;

    // Both policies are retained by the registry...
    try testing.expectEqual(@as(usize, 2), registry.getPolicyCount());

    // ...but only the valid one is compiled into the matcher index; the broken
    // one is inert (absent from the index, so it can never match).
    try testing.expect(snapshot.log_index.getPolicy("aaa-valid") != null);
    try testing.expect(snapshot.log_index.getPolicy("zzz-broken") == null);

    // The broken policy's compilation error is surfaced via collectStats, and
    // the valid policy produces no error.
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const stats = try registry.collectStats(arena.allocator());

    const broken = findStats(stats, "zzz-broken") orelse return error.MissingBroken;
    try testing.expect(broken.errors.len >= 1);

    const valid = findStats(stats, "aaa-valid") orelse return error.MissingValid;
    try testing.expectEqual(@as(usize, 0), valid.errors.len);
}

test "PolicyRegistry: error for unknown policy is not surfaced by collectStats" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var real_policy = try createTestPolicy(allocator, "real-policy");
    defer freeTestPolicy(allocator, &real_policy);
    try registry.updatePolicies(&.{real_policy}, "file-provider", .file);

    // An error for a real policy is surfaced; one for an absent policy is not
    // (collectStats only emits rows for policies in the current snapshot).
    registry.recordPolicyError("real-policy", "Some error");
    registry.recordPolicyError("ghost-policy", "Should be dropped");

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const stats = try registry.collectStats(arena.allocator());

    try testing.expect(statsHasError(stats, "real-policy", "Some error"));
    try testing.expect(findStats(stats, "ghost-policy") == null);
}

test "PolicyRegistry: multiple errors for same policy accumulate" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var policy = try createTestPolicy(allocator, "error-prone-policy");
    defer freeTestPolicy(allocator, &policy);
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    // Record multiple errors for the same policy
    registry.recordPolicyError("error-prone-policy", "First error");
    registry.recordPolicyError("error-prone-policy", "Second error");
    registry.recordPolicyError("error-prone-policy", "Third error");

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const stats = try registry.collectStats(arena.allocator());

    const row = findStats(stats, "error-prone-policy") orelse return error.MissingPolicy;
    try testing.expectEqual(@as(usize, 3), row.errors.len);
    try testing.expect(statsHasError(stats, "error-prone-policy", "First error"));
    try testing.expect(statsHasError(stats, "error-prone-policy", "Second error"));
    try testing.expect(statsHasError(stats, "error-prone-policy", "Third error"));
}

test "PolicyRegistry: policies keyed by id not name" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create two policies with same name but different ids
    var policy1: Policy = .{
        .id = try allocator.dupe(u8, "id-1"),
        .name = try allocator.dupe(u8, "same-name"),
        .enabled = true,
    };
    defer policy1.deinit(allocator);

    var policy2: Policy = .{
        .id = try allocator.dupe(u8, "id-2"),
        .name = try allocator.dupe(u8, "same-name"),
        .enabled = true,
    };
    defer policy2.deinit(allocator);

    // Both should be added (different ids)
    try registry.updatePolicies(&.{ policy1, policy2 }, "file-provider", .file);

    try testing.expectEqual(@as(usize, 2), registry.getPolicyCount());

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);
    try testing.expectEqual(@as(usize, 2), snapshot.?.policies.len);
}

test "PolicyRegistry: policy update by id replaces correctly" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Add initial policy
    var policy_v1: Policy = .{
        .id = try allocator.dupe(u8, "policy-123"),
        .name = try allocator.dupe(u8, "my-policy"),
        .enabled = true,
        .description = try allocator.dupe(u8, "version 1"),
    };
    defer policy_v1.deinit(allocator);

    try registry.updatePolicies(&.{policy_v1}, "file-provider", .file);
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());

    var snapshot = registry.getSnapshot();
    try testing.expectEqualStrings("version 1", snapshot.?.policies[0].description);

    // Update with same id, different description
    var policy_v2: Policy = .{
        .id = try allocator.dupe(u8, "policy-123"),
        .name = try allocator.dupe(u8, "my-policy-renamed"),
        .enabled = true,
        .description = try allocator.dupe(u8, "version 2"),
    };
    defer policy_v2.deinit(allocator);

    try registry.updatePolicies(&.{policy_v2}, "file-provider", .file);

    // Should still have 1 policy, but updated
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());

    snapshot = registry.getSnapshot();
    try testing.expectEqualStrings("version 2", snapshot.?.policies[0].description);
    try testing.expectEqualStrings("my-policy-renamed", snapshot.?.policies[0].name);
}

// -----------------------------------------------------------------------------
// Metric Policy Tests
// -----------------------------------------------------------------------------

const MetricTarget = proto.policy.MetricTarget;

test "PolicyConfigType: fromPolicy returns metric_target when metric is set" {
    const allocator = testing.allocator;

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "metric-policy"),
        .name = try allocator.dupe(u8, "metric-policy"),
        .enabled = true,
        .target = .{ .metric = MetricTarget{
            .match = .empty,
            .keep = true,
        } },
    };
    defer policy.deinit(allocator);

    const config_type = PolicyConfigType.fromPolicy(&policy);
    try testing.expectEqual(PolicyConfigType.metric_target, config_type);
}

test "PolicySnapshot: metric_target_indices contains only metric policies" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a log policy
    var log_policy: Policy = .{
        .id = try allocator.dupe(u8, "log-policy"),
        .name = try allocator.dupe(u8, "log-policy"),
        .enabled = true,
        .target = .{ .log = LogTarget{
            .match = .empty,
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    defer log_policy.deinit(allocator);

    // Create a metric policy
    var metric_policy: Policy = .{
        .id = try allocator.dupe(u8, "metric-policy"),
        .name = try allocator.dupe(u8, "metric-policy"),
        .enabled = true,
        .target = .{ .metric = MetricTarget{
            .match = .empty,
            .keep = true,
        } },
    };
    defer metric_policy.deinit(allocator);

    // Create a policy with no target
    var no_target_policy = try createTestPolicy(allocator, "no-target");
    defer freeTestPolicy(allocator, &no_target_policy);

    // Add all policies
    try registry.updatePolicies(&.{ log_policy, metric_policy, no_target_policy }, "file-provider", .file);

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);

    // Should have 3 policies total
    try testing.expectEqual(@as(usize, 3), snapshot.?.policies.len);

    // Should have 1 log policy indexed
    try testing.expectEqual(@as(usize, 1), snapshot.?.log_target_indices.len);

    // Should have 1 metric policy indexed
    try testing.expectEqual(@as(usize, 1), snapshot.?.metric_target_indices.len);

    // Verify the log policy is correct
    const log_policy_idx = snapshot.?.log_target_indices[0];
    try testing.expectEqualStrings("log-policy", snapshot.?.policies[log_policy_idx].name);

    // Verify the metric policy is correct
    const metric_policy_idx = snapshot.?.metric_target_indices[0];
    try testing.expectEqualStrings("metric-policy", snapshot.?.policies[metric_policy_idx].name);
}

test "PolicySnapshot: iterateMetricTargetPolicies iterates only metric policies" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create two metric policies
    var metric_policy1: Policy = .{
        .id = try allocator.dupe(u8, "metric-1"),
        .name = try allocator.dupe(u8, "metric-1"),
        .enabled = true,
        .target = .{ .metric = MetricTarget{
            .match = .empty,
            .keep = true,
        } },
    };
    defer metric_policy1.deinit(allocator);

    var metric_policy2: Policy = .{
        .id = try allocator.dupe(u8, "metric-2"),
        .name = try allocator.dupe(u8, "metric-2"),
        .enabled = true,
        .target = .{ .metric = MetricTarget{
            .match = .empty,
            .keep = false,
        } },
    };
    defer metric_policy2.deinit(allocator);

    // Create a log policy (should not be in metric iteration)
    var log_policy: Policy = .{
        .id = try allocator.dupe(u8, "log-policy"),
        .name = try allocator.dupe(u8, "log-policy"),
        .enabled = true,
        .target = .{ .log = LogTarget{
            .match = .empty,
            .keep = try allocator.dupe(u8, "all"),
        } },
    };
    defer log_policy.deinit(allocator);

    try registry.updatePolicies(&.{ metric_policy1, log_policy, metric_policy2 }, "file-provider", .file);

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);

    // Iterate metric policies
    var iter = snapshot.?.iterateMetricTargetPolicies();
    var count: usize = 0;
    var found_metric1 = false;
    var found_metric2 = false;

    while (iter.next()) |policy| {
        count += 1;
        try testing.expect(policy.target != null);

        if (std.mem.eql(u8, policy.name, "metric-1")) {
            found_metric1 = true;
        } else if (std.mem.eql(u8, policy.name, "metric-2")) {
            found_metric2 = true;
        }
    }

    try testing.expectEqual(@as(usize, 2), count);
    try testing.expect(found_metric1);
    try testing.expect(found_metric2);
}
