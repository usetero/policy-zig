//! Policy Engine - Hyperscan-based policy evaluation
//!
//! This module provides efficient policy evaluation using an inverted index
//! of Hyperscan databases. Instead of iterating through policies and checking
//! matchers, we:
//!
//! 1. Iterate through matcher keys (MatchCase, attribute_key)
//! 2. Scan field values against pre-compiled Hyperscan databases
//! 3. Aggregate match counts per policy using O(1) array operations
//! 4. Select the highest priority policy where all matchers matched
//!
//! ## Policy Stages
//!
//! Policies now contain both filter and transform stages:
//! 1. **Filter Stage**: Determines keep/drop based on `keep` field
//! 2. **Transform Stage**: Applies modifications (redact, remove, rename, add)
//!
//! The engine evaluates the filter stage first. If the decision is to drop,
//! evaluation stops early. Otherwise, matched policies are returned for
//! transform processing.
//!
//! ## Performance Characteristics
//!
//! - O(k * n) where k = number of unique matcher keys, n = input text length
//! - O(1) per-pattern match aggregation using numeric policy indices
//! - Independent of the number of policies or patterns per key
//! - Lock-free reads from atomic snapshot pointer

const std = @import("std");
const proto = @import("proto");
const matcher_index = @import("./matcher_index.zig");
const policy_mod = @import("./root.zig");
const policy_types = @import("./types.zig");
const log_transform = @import("./log_transform.zig");
const rate_limiter_mod = @import("./rate_limiter.zig");

const o11y = @import("observability");
const NoopEventBus = o11y.NoopEventBus;
const EventBus = o11y.EventBus;

const LogMatcher = proto.policy.LogMatcher;

const KeepValue = matcher_index.KeepValue;
const PolicyIndex = matcher_index.PolicyIndex;
const PolicyInfo = matcher_index.PolicyInfo;
const max_policies = matcher_index.max_policies;
const RateLimiter = rate_limiter_mod.RateLimiter;

const MatcherDatabase = matcher_index.MatcherDatabase;
pub const PolicyRegistry = policy_mod.Registry;
pub const PolicySnapshot = policy_mod.Snapshot;

// Re-export types for callers
pub const FieldRef = policy_types.FieldRef;
pub const MetricFieldRef = policy_types.MetricFieldRef;
pub const TraceFieldRef = policy_types.TraceFieldRef;
pub const LogAccessor = policy_types.LogAccessor;
pub const MetricAccessor = policy_types.MetricAccessor;
pub const TraceAccessor = policy_types.TraceAccessor;
pub const TypedValue = policy_types.TypedValue;
pub const TelemetryType = policy_types.TelemetryType;

// Proto types
const Policy = proto.policy.Policy;
const LogTarget = proto.policy.LogTarget;
const MetricTarget = proto.policy.MetricTarget;
const TraceTarget = proto.policy.TraceTarget;

/// Maximum number of pattern matches to track per scan
pub const max_matches_per_scan: usize = 256;

/// Helper to extract the log target from a policy (handles target union)
pub fn getLogTarget(policy: *const Policy) ?*const LogTarget {
    const target_ptr = &(policy.target orelse return null);
    return switch (target_ptr.*) {
        .log => |*log| log,
        .metric, .trace => null,
    };
}

/// Helper to extract the metric target from a policy (handles target union)
pub fn getMetricTarget(policy: *const Policy) ?*const MetricTarget {
    const target_ptr = &(policy.target orelse return null);
    return switch (target_ptr.*) {
        .metric => |*metric| metric,
        .log, .trace => null,
    };
}

/// Helper to extract the trace target from a policy (handles target union)
pub fn getTraceTarget(policy: *const Policy) ?*const TraceTarget {
    const target_ptr = &(policy.target orelse return null);
    return switch (target_ptr.*) {
        .trace => |*trace| trace,
        .log, .metric => null,
    };
}

// =============================================================================
// FilterDecision - Result of filter stage evaluation
// =============================================================================

/// Decision from the filter stage of policy evaluation
pub const FilterDecision = enum {
    /// Keep the telemetry (explicitly matched a keep policy)
    keep,
    /// Drop the telemetry (matched a drop policy)
    drop,
    /// No policy matched - default behavior (keep)
    unset,

    /// Returns true if telemetry should continue to next stage
    pub fn shouldContinue(self: FilterDecision) bool {
        return self != .drop;
    }
};

// =============================================================================
// PolicyResult - Complete evaluation result
// =============================================================================

/// Result of policy evaluation containing filter decision and matched policies
pub const PolicyResult = struct {
    /// The filter decision (keep/drop/unset)
    decision: FilterDecision,
    /// IDs of policies that matched (for transform stage lookup)
    /// Only populated when decision is keep or unset
    matched_policy_ids: []const []const u8,
    /// Whether any transformations were applied to the telemetry
    /// Callers should use this to determine if re-encoding is needed
    was_transformed: bool = false,

    /// Empty result for dropped telemetry
    pub const dropped: PolicyResult = .{
        .decision = .drop,
        .matched_policy_ids = &.{},
        .was_transformed = false,
    };

    /// Default result when no policies match
    pub const unmatched: PolicyResult = .{
        .decision = .unset,
        .matched_policy_ids = &.{},
        .was_transformed = false,
    };
};

// =============================================================================
// Comptime Type Helpers - Select types based on telemetry type
// =============================================================================

/// Returns the field reference type for the given telemetry type
fn FieldRefType(comptime T: TelemetryType) type {
    return switch (T) {
        .log => FieldRef,
        .metric => MetricFieldRef,
        .trace => TraceFieldRef,
    };
}

/// Returns the accessor struct type for the given telemetry type.
fn AccessorType(comptime T: TelemetryType) type {
    return switch (T) {
        .log => LogAccessor,
        .metric => MetricAccessor,
        .trace => TraceAccessor,
    };
}

/// True for the OTLP identifier `bytes` fields (trace_id/span_id/parent_span_id)
/// that are carried as raw bytes in memory — matching the binary wire path — but
/// written as lowercase-hex literals by policy authors. The string matchers
/// (exact/contains/regex) therefore compare against a hex rendering of these
/// fields; numeric/binary matchers (`equals` on `.bytes`) keep comparing raw.
/// Mirrors the JSON codec's `hex_bytes_fields` set, matched by proto field name.
fn isHexBytesField(comptime T: TelemetryType, field_ref: FieldRefType(T)) bool {
    return switch (T) {
        .trace => switch (field_ref) {
            .trace_field => |tf| switch (tf) {
                .TRACE_FIELD_TRACE_ID, .TRACE_FIELD_SPAN_ID, .TRACE_FIELD_PARENT_SPAN_ID => true,
                else => false,
            },
            else => false,
        },
        .log => switch (field_ref) {
            .log_field => |lf| switch (lf) {
                .LOG_FIELD_TRACE_ID, .LOG_FIELD_SPAN_ID => true,
                else => false,
            },
            else => false,
        },
        .metric => false,
    };
}

/// trace_id is 16 bytes, span_id 8 — 32 covers both with headroom.
const max_hex_id_bytes = 32;

/// Render raw id bytes as lowercase hex into `buf`. Returns the rendered slice,
/// or the raw bytes unchanged when they don't fit (degrade, never overflow).
fn hexRenderId(bytes: []const u8, buf: []u8) []const u8 {
    if (bytes.len * 2 > buf.len) return bytes;
    const hex = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        buf[i * 2] = hex[b >> 4];
        buf[i * 2 + 1] = hex[b & 0x0f];
    }
    return buf[0 .. bytes.len * 2];
}

/// Runtime inputs to `PolicyEngine.evaluate`.
///
/// `scratch` is consumed by regex-redact transforms (logs) for substitution
/// output. It must outlive any accessor-retained references to the substituted
/// bytes — typically a per-record arena owned by the caller. When `null`,
/// regex-redact rules degrade to no-ops.
///
/// The accessor itself is a comptime parameter to `evaluate` (not a field
/// here): callers pass a pointer to a module-scope `const` accessor value,
/// and the engine reads the accessor's optional primitive fields at
/// comptime. Transforms whose required primitive (set / delete / move) is
/// null on this accessor are eliminated by the compiler — no runtime branch,
/// no code emitted for the unwired path. A single PolicySnapshot can still
/// serve multiple consumers: each consumer's evaluate site passes its own
/// (comptime) accessor, and the engine instantiates one specialized path
/// per accessor.
pub const EvaluateOptions = struct {
    scratch: ?std.mem.Allocator = null,
    /// Io for the io-dependent decision paths: rate-limiter timestamps
    /// (`per_second`/`per_minute` policies) and regex-redact mutex
    /// serialization. Only consulted when such policies fire; a null `io`
    /// degrades those paths gracefully (rate limit defaults to keep, regex
    /// redact no-ops) exactly like a null `scratch`.
    io: ?std.Io = null,
};

// =============================================================================
// Observability Events
// =============================================================================

const EvaluateEmpty = struct {};
const EvaluateStart = struct { matcher_key_count: usize, policy_count: usize };
const MatcherKeyFieldNotPresent = struct {
    telemetry_type: TelemetryType,
    field: MatcherFieldRef,
};
const MatcherKeyFieldValue = struct {
    telemetry_type: TelemetryType,
    field: MatcherFieldRef,
    value: []const u8,
};
const MatcherFieldRef = union(TelemetryType) {
    log: FieldRef,
    metric: MetricFieldRef,
    trace: TraceFieldRef,
};
const MatcherKeyNoDatabase = struct {};
const ScanResult = struct { positive_count: usize, negated_count: usize };
const PolicyFullMatch = struct { policy_index: PolicyIndex, policy_id: []const u8 };
const PolicyNegationFailed = struct { policy_index: PolicyIndex };
const EvaluateResult = struct { decision: FilterDecision, matched_count: usize };
const TransformApplied = struct {
    policy_id: []const u8,
    removes: usize,
    redacts: usize,
    renames: usize,
    adds: usize,
};

// =============================================================================
// PolicyEngine - Main evaluation engine
// =============================================================================

/// Policy engine that evaluates telemetry against policies using Hyperscan.
/// Uses an inverted index for O(k*n) evaluation regardless of policy count.
///
/// The engine runs two stages:
/// 1. Filter stage: Determines keep/drop decision
/// 2. Transform stage: Returns matched policies for modification (caller handles)
pub const PolicyEngine = struct {
    /// Event bus for observability
    bus: *EventBus,
    /// Policy registry for getting snapshots and recording stats/errors
    registry: *PolicyRegistry,

    pub fn init(bus: *EventBus, registry: *PolicyRegistry) PolicyEngine {
        return .{
            .bus = bus,
            .registry = registry,
        };
    }

    /// Evaluate telemetry against all policies in the current snapshot.
    ///
    /// Returns a PolicyResult containing:
    /// - The filter decision (keep/drop/unset)
    /// - List of matched policy IDs (for transform stage lookup)
    ///
    /// A policy "fully matches" when:
    /// - All positive matchers have their patterns found in the field value
    /// - No negated matchers have their patterns found in the field value
    ///
    /// Thread-safe: uses only stack-allocated buffers for match aggregation.
    /// Automatically gets the current snapshot from the registry.
    ///
    /// The `policy_id_buf` parameter is used to store matched policy IDs.
    /// Caller provides the buffer to avoid allocation.
    ///
    /// If `field_mutator` is provided, transforms from matched policies will be applied.
    /// Pass null to skip transform application.
    ///
    /// If `byte_counter` is provided, bytes before/after each transform will be measured
    /// and recorded in policy stats. Pass null to skip byte tracking.
    ///
    /// Full policy evaluation with filter decision, matched policy IDs, and optional transforms.
    /// Returns PolicyResult containing the filter decision and list of matched policy IDs.
    /// If field_mutator is provided, transforms are applied to matched policies.
    /// Result of scanning all matcher keys against field values
    const ScanState = struct {
        match_counts: [max_matches_per_scan]u16,
        active_policies: [max_matches_per_scan]PolicyIndex,
        is_active: [max_matches_per_scan]bool,
        active_count: usize,
    };

    /// Result of finding matching policies from scan state
    const MatchState = struct {
        matched_indices: [max_matches_per_scan]PolicyIndex,
        matched_policies: [max_matches_per_scan]*const PolicyInfo,
        matched_decisions: [max_matches_per_scan]FilterDecision,
        matched_count: usize,
        decision: FilterDecision,
        /// Whether a trace sampling threshold was written back via mutator
        was_trace_sampled: bool = false,
    };

    pub fn evaluate(
        self: *const PolicyEngine,
        comptime T: TelemetryType,
        comptime accessor: *const AccessorType(T),
        ctx: *anyopaque,
        policy_id_buf: [][]const u8,
        options: EvaluateOptions,
    ) PolicyResult {
        // Get current snapshot from registry (lock-free)
        const snapshot = self.registry.getSnapshot() orelse {
            const event: EvaluateEmpty = .{};
            self.bus.debug(event);
            return .unmatched;
        };

        // Select the appropriate index based on telemetry type (compile-time dispatch)
        const index = switch (T) {
            .log => &snapshot.log_index,
            .metric => &snapshot.metric_index,
            .trace => &snapshot.trace_index,
        };

        if (index.isEmpty()) {
            const event: EvaluateEmpty = .{};
            self.bus.debug(event);
            return .unmatched;
        }

        const start_event: EvaluateStart = .{
            .matcher_key_count = index.getMatcherKeys().len,
            .policy_count = index.getPolicyCount(),
        };
        self.bus.debug(start_event);

        // Phase 1: Scan all matcher keys and compute match counts
        var scan_state: ScanState = undefined;
        self.scanMatcherKeys(T, accessor, ctx, index, &scan_state);

        // Phase 2: Find matching policies and determine decision
        var match_state: MatchState = undefined;
        self.findMatchingPolicies(T, accessor, options.io, ctx, index, &scan_state, policy_id_buf, &match_state);

        const result_event: EvaluateResult = .{
            .decision = match_state.decision,
            .matched_count = match_state.matched_count,
        };
        self.bus.debug(result_event);

        // Record hit/miss stats using lock-free atomics
        self.recordMatchedPolicyStats(snapshot, &match_state);

        if (match_state.decision == .drop) {
            return .dropped;
        }

        // Phase 3: Apply transforms (log only) and record stats
        var was_transformed = match_state.was_trace_sampled;
        if (T == .log) {
            for (0..match_state.matched_count) |i| {
                const policy_index = match_state.matched_indices[i];
                const result = self.applyLogTransforms(
                    accessor,
                    options.io,
                    ctx,
                    snapshot,
                    policy_index,
                    policy_id_buf[i],
                    options.scratch,
                );
                if (result.totalApplied() > 0) {
                    was_transformed = true;
                    if (snapshot.getStats(match_state.matched_policies[i].stats_index)) |stats| {
                        stats.addTransform(@intCast(result.totalApplied()));
                    }
                }
            }
        }

        return .{
            .decision = match_state.decision,
            .matched_policy_ids = policy_id_buf[0..match_state.matched_count],
            .was_transformed = was_transformed,
        };
    }

    /// Scan all matcher keys and compute match counts for each policy.
    /// Returns state needed for determining which policies matched.
    inline fn scanMatcherKeys(
        self: *const PolicyEngine,
        comptime T: TelemetryType,
        comptime accessor: *const AccessorType(T),
        ctx: *anyopaque,
        index: *const matcher_index.MatcherIndexType(T),
        state: *ScanState,
    ) void {
        state.* = .{
            .match_counts = undefined,
            .active_policies = undefined,
            .is_active = undefined,
            .active_count = 0,
        };
        @memset(&state.match_counts, 0);
        @memset(&state.is_active, false);

        // Initialize match counts for policies with negated patterns
        // No telemetry type filtering needed - index only contains policies of type T
        for (index.getPoliciesWithNegation()) |policy_index| {
            const policy_info = index.getPolicyByIndex(policy_index) orelse continue;
            state.match_counts[policy_index] = policy_info.negated_count;
            if (!state.is_active[policy_index]) {
                state.is_active[policy_index] = true;
                state.active_policies[state.active_count] = policy_index;
                state.active_count += 1;
            }
        }

        var result_buf: [max_matches_per_scan]u32 = undefined;

        // Iterate type-specific matcher keys - no runtime type filtering needed
        for (index.getMatcherKeys()) |matcher_key| {
            const field_ref = matcher_key.field;

            // Apply exists-bucket entries first: their truth depends on field
            // presence regardless of underlying value type, so they consult
            // accessor.callExists rather than scanning value bytes.
            //
            // Counting mirrors the Hyperscan path:
            //  - positive (negate=false): +1 when present (pattern matched).
            //  - negated  (negate=true):  the negated-init pass pre-seeded +1;
            //    decrement when present (pattern matched, negation failed),
            //    leave alone when absent (negation succeeded).
            if (matcher_key.exists_entries.len > 0) {
                const is_present = accessor.callExists(ctx, field_ref);
                for (matcher_key.exists_entries) |entry| {
                    if (is_present) {
                        if (entry.negate) {
                            state.match_counts[entry.policy_index] -= 1;
                        } else {
                            state.match_counts[entry.policy_index] += 1;
                        }
                    }
                    if (!state.is_active[entry.policy_index]) {
                        state.is_active[entry.policy_index] = true;
                        state.active_policies[state.active_count] = entry.policy_index;
                        state.active_count += 1;
                    }
                }
            }

            // Skip the value-match path entirely for exists-only keys —
            // they have no Hyperscan DB and don't read the field value.
            if (!matcher_key.has_value_db) continue;

            // String matchers consume the `.string` variant. Identifier
            // fields arrive as `.bytes` and are hex-rendered before matching
            // (policies write them as hex literals). Other variants are not
            // string-matchable and skip the scan like an absent field.
            var id_hex_buf: [max_hex_id_bytes * 2]u8 = undefined;
            const value = blk: {
                if (accessor.typed_value(ctx, field_ref)) |tv| switch (tv) {
                    .string => |s| break :blk s,
                    .bytes => |b| if (isHexBytesField(T, field_ref)) break :blk hexRenderId(b, &id_hex_buf),
                    else => {},
                };
                if (self.bus.isEnabled(.debug)) {
                    const event: MatcherKeyFieldNotPresent = .{
                        .telemetry_type = T,
                        .field = switch (T) {
                            .log => .{ .log = field_ref },
                            .metric => .{ .metric = field_ref },
                            .trace => .{ .trace = field_ref },
                        },
                    };
                    self.bus.debug(event);
                }
                continue;
            };

            if (self.bus.isEnabled(.debug)) {
                const event: MatcherKeyFieldValue = .{
                    .telemetry_type = T,
                    .field = switch (T) {
                        .log => .{ .log = field_ref },
                        .metric => .{ .metric = field_ref },
                        .trace => .{ .trace = field_ref },
                    },
                    .value = if (value.len > 100) value[0..100] else value,
                };
                self.bus.debug(event);
            }

            // has_value_db guarantees the cached db pointer is non-null.
            const db = matcher_key.db.?;

            // Scan positive patterns - increment match counts
            const positive_result = db.scanPositive(value, &result_buf);
            for (positive_result.matches()) |pattern_id| {
                if (pattern_id < db.positive_patterns.len) {
                    const meta = db.positive_patterns[pattern_id];
                    state.match_counts[meta.policy_index] += 1;
                    if (!state.is_active[meta.policy_index]) {
                        state.is_active[meta.policy_index] = true;
                        state.active_policies[state.active_count] = meta.policy_index;
                        state.active_count += 1;
                    }
                }
            }

            // Scan negated patterns - decrement match counts
            const negated_result = db.scanNegated(value, &result_buf);
            for (negated_result.matches()) |pattern_id| {
                if (pattern_id < db.negated_patterns.len) {
                    const meta = db.negated_patterns[pattern_id];
                    state.match_counts[meta.policy_index] -= 1;
                    if (!state.is_active[meta.policy_index]) {
                        state.is_active[meta.policy_index] = true;
                        state.active_policies[state.active_count] = meta.policy_index;
                        state.active_count += 1;
                    }
                    if (self.bus.isEnabled(.debug)) {
                        const event: PolicyNegationFailed = .{
                            .policy_index = meta.policy_index,
                        };
                        self.bus.debug(event);
                    }
                }
            }

            if (self.bus.isEnabled(.debug)) {
                const event: ScanResult = .{
                    .positive_count = positive_result.count,
                    .negated_count = negated_result.count,
                };
                self.bus.debug(event);
            }
        }

        // Typed checks (v1.5.0): evaluate equals/gt/gte/lt/lte against typed field
        // values. These bypass Hyperscan entirely and are evaluated here after the
        // scan loop. Counting follows the same convention as the scan loop:
        //  - positive: +1 when the typed comparison fires
        //  - negated:  the negated-init pass pre-seeded +1; decrement when the
        //    comparison fires (negation failed), leave alone when it doesn't
        //    (negation succeeded).
        for (index.getTypedChecks()) |check| {
            const typed_val = accessor.typed_value(ctx, check.field_ref);

            const fired = check.matcher.evaluate(typed_val);

            if (check.negate) {
                if (fired) {
                    state.match_counts[check.policy_index] -= 1;
                }
            } else if (fired) {
                state.match_counts[check.policy_index] += 1;
            }

            if (!state.is_active[check.policy_index]) {
                state.is_active[check.policy_index] = true;
                state.active_policies[state.active_count] = check.policy_index;
                state.active_count += 1;
            }
        }

        // Sort active policies by index so iteration order = alphanumeric policy ID order.
        // Policy indices are assigned from an ID-sorted policies_slice in createSnapshot.
        // This sorts only the active set (typically 3-5 elements), not all policies.
        // note: insertion sort — active set is small (typically 3-5, a few
        // dozen worst case); beats std block sort's constant overhead here.
        // If active_count ever grows large, switch back to std.mem.sort (O(n log n)).
        std.sort.insertion(PolicyIndex, state.active_policies[0..state.active_count], {}, std.sort.asc(PolicyIndex));
    }

    /// Get raw bytes for probabilistic sampling.
    ///
    /// The sampler expects raw bytes: `.bytes` values are used directly
    /// (identifiers, no hex-encoded strings), `.string` values as their byte
    /// content. Other variants cannot seed randomness and return null.
    ///
    /// - Traces: `TRACE_FIELD_TRACE_ID` raw bytes (16 bytes per OTel spec).
    /// - Logs with sample_key: sample key field value as raw bytes.
    /// - Otherwise: null (falls through to non-percentage keep handling).
    inline fn getSamplingInput(
        comptime T: TelemetryType,
        comptime accessor: *const AccessorType(T),
        ctx: *anyopaque,
        policy_info: *const PolicyInfo,
    ) ?[]const u8 {
        const field_ref: FieldRefType(T) = switch (T) {
            .trace => .{ .trace_field = .TRACE_FIELD_TRACE_ID },
            .log => blk: {
                const sample_key = policy_info.sample_key orelse return null;
                break :blk FieldRef.fromSampleKeyField(sample_key.field) orelse return null;
            },
            .metric => return null,
        };
        const tv = accessor.typed_value(ctx, field_ref) orelse return null;
        return switch (tv) {
            .bytes => |b| b,
            .string => |s| s,
            else => null,
        };
    }

    /// Find all matching policies, apply sampling/rate limiting, and determine final decision.
    /// Drop always beats keep: if any policy returns drop, final decision is drop.
    ///
    /// For trace telemetry with probabilistic sampling, reads tracestate via
    /// the trace accessor and writes the sampling threshold back through
    /// `accessor.set`. The threshold hex value is written to
    /// TRACE_FIELD_TRACE_STATE; the host is responsible for merging it into
    /// the actual W3C tracestate header as `ot=th:VALUE`.
    inline fn findMatchingPolicies(
        self: *const PolicyEngine,
        comptime T: TelemetryType,
        comptime accessor: *const AccessorType(T),
        io: ?std.Io,
        ctx: *anyopaque,
        index: *const matcher_index.MatcherIndexType(T),
        scan_state: *const ScanState,
        policy_id_buf: [][]const u8,
        state: *MatchState,
    ) void {
        state.* = .{
            .matched_indices = undefined,
            .matched_policies = undefined,
            .matched_decisions = undefined,
            .matched_count = 0,
            .decision = .unset,
        };

        // Iterate active policies in index order (= alphanumeric ID order from sorted snapshot).
        // This guarantees transforms are applied in spec-required alphanumeric order.
        for (scan_state.active_policies[0..scan_state.active_count]) |policy_index| {
            const policy_info = index.getPolicyByIndex(policy_index) orelse continue;

            if (!policy_info.enabled) continue;

            if (scan_state.match_counts[policy_index] == policy_info.required_match_count) {
                if (self.bus.isEnabled(.debug)) {
                    const event: PolicyFullMatch = .{
                        .policy_index = policy_info.index,
                        .policy_id = policy_info.id,
                    };
                    self.bus.debug(event);
                }

                // Apply sampling/rate limiting to get this policy's decision.
                // Skip rate limiter token consumption if record is already dropped
                // by a more restrictive policy — dropped records should not consume
                // rate limit budget.
                const decision = blk: {
                    if (state.decision == .drop) {
                        switch (policy_info.keep) {
                            .per_second, .per_minute => break :blk FilterDecision.drop,
                            else => {},
                        }
                    }
                    if (policy_info.sampler) |s| {
                        const input = getSamplingInput(T, accessor, ctx, policy_info) orelse "";

                        if (T == .trace) {
                            // Trace sampling: read tracestate, run full sample(), write threshold back
                            const ts_ref: FieldRefType(T) = .{ .trace_field = .TRACE_FIELD_TRACE_STATE };
                            const tracestate = ts: {
                                const tv = accessor.typed_value(ctx, ts_ref) orelse break :ts "";
                                break :ts if (tv == .string) tv.string else "";
                            };
                            const sr = s.sample(input, tracestate);

                            if (sr.keep) {
                                if (sr.new_threshold) |th| {
                                    // `set` is optional on TraceAccessor: when
                                    // the consumer doesn't wire threshold
                                    // writeback, this whole branch is
                                    // comptime-eliminated (accessor is comptime,
                                    // so `accessor.set` is a comptime optional
                                    // and the if becomes a comptime if).
                                    if (accessor.set) |set_fn| {
                                        set_fn(ctx, .{ .trace_field = .TRACE_FIELD_TRACE_STATE }, th);
                                        state.was_trace_sampled = true;
                                    }
                                }
                            }

                            break :blk if (sr.keep) FilterDecision.keep else FilterDecision.drop;
                        }

                        // Non-trace (log): with no sample_key (or a missing/empty
                        // key value) the spec requires an independent random
                        // decision per record, so empty input takes the random
                        // path instead of failing closed.
                        if (input.len == 0) {
                            break :blk if (s.shouldKeepRandom(io)) FilterDecision.keep else FilterDecision.drop;
                        }
                        break :blk if (s.shouldKeep(input)) FilterDecision.keep else FilterDecision.drop;
                    }
                    break :blk applyKeepValue(io, policy_info);
                };

                if (state.matched_count < policy_id_buf.len) {
                    policy_id_buf[state.matched_count] = policy_info.id;
                    state.matched_indices[state.matched_count] = policy_index;
                    state.matched_policies[state.matched_count] = policy_info;
                    state.matched_decisions[state.matched_count] = decision;
                    state.matched_count += 1;
                }

                // Update final decision: drop beats keep, keep beats unset
                if (decision == .drop) {
                    state.decision = .drop;
                } else if (decision == .keep and state.decision == .unset) {
                    state.decision = .keep;
                }
            }
        }
    }

    /// Apply transforms to log context for a matched policy.
    /// Returns the transform result for stats recording.
    inline fn applyLogTransforms(
        self: *const PolicyEngine,
        comptime accessor: *const LogAccessor,
        io: ?std.Io,
        ctx: *anyopaque,
        snapshot: *const PolicySnapshot,
        policy_index: PolicyIndex,
        policy_id: []const u8,
        scratch: ?std.mem.Allocator,
    ) log_transform.TransformResult {
        const policy = snapshot.getPolicy(policy_index) orelse return .{};
        const log_target = getLogTarget(policy) orelse return .{};
        const transform = log_target.transform orelse return .{};

        const compiled_redacts: []const log_transform.CompiledRedact = blk: {
            const info = snapshot.log_index.getPolicyByIndex(policy_index) orelse break :blk &.{};
            break :blk info.compiled_redacts;
        };

        const result = log_transform.applyTransforms(
            accessor,
            &transform,
            ctx,
            .{
                .compiled_redacts = compiled_redacts,
                .scratch = scratch,
                .io = io,
            },
        );

        if (result.totalApplied() > 0) {
            const event: TransformApplied = .{
                .policy_id = policy_id,
                .removes = result.removes_applied,
                .redacts = result.redacts_applied,
                .renames = result.renames_applied,
                .adds = result.adds_applied,
            };
            self.bus.debug(event);
        }

        return result;
    }

    /// Record stats for all matched policies using lock-free atomics.
    ///
    /// Per spec:
    /// - Record kept: all matching policies record a hit.
    /// - Record dropped: the single most restrictive matching policy records a hit,
    ///   all other matching policies record a miss. When multiple policies share the
    ///   same restrictiveness, the first encountered wins (consistent with Go).
    ///
    /// Restrictiveness order: none > percentage/per_second/per_minute > all
    inline fn recordMatchedPolicyStats(
        self: *const PolicyEngine,
        snapshot: *const PolicySnapshot,
        match_state: *const MatchState,
    ) void {
        _ = self;
        if (match_state.matched_count == 0) return;

        if (match_state.decision != .drop) {
            // Record kept (or unset): all matching policies get a hit
            for (0..match_state.matched_count) |i| {
                if (snapshot.getStats(match_state.matched_policies[i].stats_index)) |stats| {
                    stats.addHit();
                }
            }
            return;
        }

        // Record dropped: find the single most restrictive policy (first encountered wins ties).
        // Uses KeepValue.restrictiveness(): none(0) > rate(1) > pct(2) > all(3)
        var best_index: usize = 0;
        var best_restrictiveness: u8 = match_state.matched_policies[0].keep.restrictiveness();
        for (1..match_state.matched_count) |i| {
            const level = match_state.matched_policies[i].keep.restrictiveness();
            if (level < best_restrictiveness) {
                best_restrictiveness = level;
                best_index = i;
            }
        }

        for (0..match_state.matched_count) |i| {
            if (snapshot.getStats(match_state.matched_policies[i].stats_index)) |stats| {
                if (i == best_index) {
                    stats.addHit();
                } else {
                    stats.addMiss();
                }
            }
        }
    }

    /// Apply policy's keep value for non-percentage policies.
    /// Percentage sampling is handled by ProbabilisticSampler in findMatchingPolicies.
    fn applyKeepValue(io: ?std.Io, policy_info: *const PolicyInfo) FilterDecision {
        return switch (policy_info.keep) {
            .none => .drop,
            .all => .keep,
            .percentage => .keep, // Should not reach here; handled by ProbabilisticSampler
            .per_second, .per_minute => {
                if (policy_info.rate_limiter) |rl| {
                    // Without io we cannot read the clock to rate-limit; default
                    // to keep (same as "no rate limiter configured").
                    const real_io = io orelse return .keep;
                    return if (rl.shouldKeep(real_io)) .keep else .drop;
                }
                return .keep; // No rate limiter configured, default to keep
            },
        };
    }
};

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;
const SourceType = policy_mod.SourceType;
const LogField = proto.policy.LogField;
const TraceField = proto.policy.TraceField;
const TraceMatcher = proto.policy.TraceMatcher;
const TraceSamplingConfig = proto.policy.TraceSamplingConfig;
const SamplingMode = proto.policy.SamplingMode;
const AttributePath = proto.policy.AttributePath;

/// Helper to create AttributePath for tests
fn testMakeAttrPath(allocator: std.mem.Allocator, key: []const u8) !AttributePath {
    var attr_path: AttributePath = .{};
    try attr_path.path.append(allocator, try allocator.dupe(u8, key));
    return attr_path;
}

/// Test context for unit tests - simple struct with known fields
const TestLogContext = struct {
    level: ?[]const u8 = null,
    message: ?[]const u8 = null,
    service: ?[]const u8 = null,
    ddtags: ?[]const u8 = null,
    env: ?[]const u8 = null,
    trace_id: ?[]const u8 = null,
    resource_schema_url: ?[]const u8 = null,
    scope_schema_url: ?[]const u8 = null,

    fn fieldAccessor(ctx_ptr: *const anyopaque, field: FieldRef) ?[]const u8 {
        const self: *const TestLogContext = @ptrCast(@alignCast(ctx_ptr));
        return switch (field) {
            .log_field => |lf| switch (lf) {
                .LOG_FIELD_BODY => self.message,
                .LOG_FIELD_SEVERITY_TEXT => self.level,
                .LOG_FIELD_RESOURCE_SCHEMA_URL => self.resource_schema_url,
                .LOG_FIELD_SCOPE_SCHEMA_URL => self.scope_schema_url,
                else => null,
            },
            .log_attribute => |attr_path| {
                const key = if (attr_path.path.items.len > 0) attr_path.path.items[0] else return null;
                if (std.mem.eql(u8, key, "service")) return self.service;
                if (std.mem.eql(u8, key, "ddtags")) return self.ddtags;
                if (std.mem.eql(u8, key, "message")) return self.message;
                if (std.mem.eql(u8, key, "env")) return self.env;
                if (std.mem.eql(u8, key, "trace_id")) return self.trace_id;
                return null;
            },
            .resource_attribute, .scope_attribute => null,
        };
    }

    fn typedAccessor(ctx_ptr: *const anyopaque, field: FieldRef) ?TypedValue {
        return .{ .string = fieldAccessor(ctx_ptr, field) orelse return null };
    }

    pub const accessor: LogAccessor = .{ .typed_value = typedAccessor };
};

fn evalTestLog(
    engine: *const PolicyEngine,
    ctx: *TestLogContext,
    policy_id_buf: [][]const u8,
) PolicyResult {
    return engine.evaluate(.log, &TestLogContext.accessor, ctx, policy_id_buf, .{
        .io = std.Options.debug_io,
    });
}

test "PolicyEngine: empty registry returns unset" {
    const allocator = testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    var test_log: TestLogContext = .{ .message = "hello" };
    var policy_id_buf: [16][]const u8 = undefined;

    const result = evalTestLog(&engine, &test_log, &policy_id_buf);

    try testing.expectEqual(FilterDecision.unset, result.decision);
    try testing.expectEqual(@as(usize, 0), result.matched_policy_ids.len);
}

test "PolicyEngine: single policy drop match" {
    const allocator = testing.allocator;

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-errors"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    // Matching log should be dropped
    var error_log: TestLogContext = .{ .message = "an error occurred" };
    var policy_id_buf: [16][]const u8 = undefined;

    const result = evalTestLog(&engine, &error_log, &policy_id_buf);
    try testing.expectEqual(FilterDecision.drop, result.decision);
    // Dropped results don't include policy IDs (no transform needed)
    try testing.expectEqual(@as(usize, 0), result.matched_policy_ids.len);

    // Non-matching log should be unset (no policy matched)
    var info_log: TestLogContext = .{ .message = "all good" };
    const result2 = evalTestLog(&engine, &info_log, &policy_id_buf);
    try testing.expectEqual(FilterDecision.unset, result2.decision);
}

test "PolicyEngine: single policy keep match returns policy ID" {
    const allocator = testing.allocator;

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "keep-errors"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "all"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    // Matching log should be kept with policy ID returned
    var error_log: TestLogContext = .{ .message = "an error occurred" };
    var policy_id_buf: [16][]const u8 = undefined;

    const result = evalTestLog(&engine, &error_log, &policy_id_buf);

    try testing.expectEqual(FilterDecision.keep, result.decision);
    try testing.expectEqual(@as(usize, 1), result.matched_policy_ids.len);
    try testing.expectEqualStrings("policy-1", result.matched_policy_ids[0]);
}

test "PolicyEngine: multiple matchers AND logic" {
    const allocator = testing.allocator;

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-payment-errors"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    // Two matchers - both must match
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_attribute = try testMakeAttrPath(allocator, "service") },
        .match = .{ .regex = try allocator.dupe(u8, "payment") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Both match - dropped
    var payment_error: TestLogContext = .{ .message = "an error occurred", .service = "payment-api" };
    try testing.expectEqual(FilterDecision.drop, evalTestLog(&engine, &payment_error, &policy_id_buf).decision);

    // Only message matches - unset
    var other_error: TestLogContext = .{ .message = "an error occurred", .service = "auth-api" };
    try testing.expectEqual(FilterDecision.unset, evalTestLog(&engine, &other_error, &policy_id_buf).decision);

    // Only service matches - unset
    var payment_info: TestLogContext = .{ .message = "request completed", .service = "payment-api" };
    try testing.expectEqual(FilterDecision.unset, evalTestLog(&engine, &payment_info, &policy_id_buf).decision);
}

test "PolicyEngine: negated matcher" {
    const allocator = testing.allocator;

    // Drop logs that do NOT contain "important"
    var policy: Policy = .{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-non-important"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "important") },
        .negate = true,
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Non-important log should be dropped (negate: pattern NOT found = success)
    var boring: TestLogContext = .{ .message = "just a regular log" };
    try testing.expectEqual(FilterDecision.drop, evalTestLog(&engine, &boring, &policy_id_buf).decision);

    // Important log should be unset (negate: pattern found = failure, no match)
    var important: TestLogContext = .{ .message = "this is important data" };
    try testing.expectEqual(FilterDecision.unset, evalTestLog(&engine, &important, &policy_id_buf).decision);
}

test "PolicyEngine: mixed negated and non-negated matchers" {
    const allocator = testing.allocator;

    // Drop errors that are NOT from production
    var policy: Policy = .{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-non-prod-errors"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    // Must contain "error"
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    // Must NOT be from production
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_attribute = try testMakeAttrPath(allocator, "env") },
        .match = .{ .regex = try allocator.dupe(u8, "prod") },
        .negate = true,
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Error from staging - dropped (error matches, prod not found = both conditions satisfied)
    var staging_error: TestLogContext = .{ .message = "an error occurred", .env = "staging" };
    try testing.expectEqual(FilterDecision.drop, evalTestLog(&engine, &staging_error, &policy_id_buf).decision);

    // Error from production - unset (error matches, but prod IS found = negation failed)
    var prod_error: TestLogContext = .{ .message = "an error occurred", .env = "production" };
    try testing.expectEqual(FilterDecision.unset, evalTestLog(&engine, &prod_error, &policy_id_buf).decision);

    // Non-error from staging - unset (error doesn't match)
    var staging_info: TestLogContext = .{ .message = "all good", .env = "staging" };
    try testing.expectEqual(FilterDecision.unset, evalTestLog(&engine, &staging_info, &policy_id_buf).decision);
}

test "PolicyEngine: most restrictive wins - drop beats keep" {
    const allocator = testing.allocator;

    // Policy that keeps errors
    var keep_policy: Policy = .{
        .id = try allocator.dupe(u8, "keep-errors"),
        .name = try allocator.dupe(u8, "keep-errors"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "all"),
        } },
    };
    try keep_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer keep_policy.deinit(allocator);

    // Policy that drops errors from payment service (more specific AND more restrictive)
    var drop_policy: Policy = .{
        .id = try allocator.dupe(u8, "drop-payment-errors"),
        .name = try allocator.dupe(u8, "drop-payment-errors"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try drop_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    try drop_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_attribute = try testMakeAttrPath(allocator, "service") },
        .match = .{ .regex = try allocator.dupe(u8, "payment") },
    });
    defer drop_policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{ keep_policy, drop_policy }, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Error from payment - both policies match, most restrictive (DROP) wins
    var payment_error: TestLogContext = .{ .message = "an error occurred", .service = "payment-api" };
    try testing.expectEqual(FilterDecision.drop, evalTestLog(&engine, &payment_error, &policy_id_buf).decision);

    // Error from auth - only keep_policy matches (KEEP)
    var auth_error: TestLogContext = .{ .message = "an error occurred", .service = "auth-api" };
    const result = evalTestLog(&engine, &auth_error, &policy_id_buf);
    try testing.expectEqual(FilterDecision.keep, result.decision);
    try testing.expectEqual(@as(usize, 1), result.matched_policy_ids.len);
}

test "PolicyEngine: disabled policies are skipped" {
    const allocator = testing.allocator;

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "disabled-drop"),
        .enabled = false, // Disabled!
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Would match but policy is disabled - unset
    var error_log: TestLogContext = .{ .message = "an error occurred" };
    try testing.expectEqual(FilterDecision.unset, evalTestLog(&engine, &error_log, &policy_id_buf).decision);
}

test "PolicyEngine: regex pattern matching" {
    const allocator = testing.allocator;

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-error-pattern"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    // Regex pattern: matches "error" or "Error" case-insensitive with (?i)
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "^.*rror") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Various error formats should match
    var error1: TestLogContext = .{ .message = "an error occurred" };
    try testing.expectEqual(FilterDecision.drop, evalTestLog(&engine, &error1, &policy_id_buf).decision);

    var error2: TestLogContext = .{ .message = "Error: something went wrong" };
    try testing.expectEqual(FilterDecision.drop, evalTestLog(&engine, &error2, &policy_id_buf).decision);

    // Non-matching should be unset
    var info: TestLogContext = .{ .message = "everything is fine" };
    try testing.expectEqual(FilterDecision.unset, evalTestLog(&engine, &info, &policy_id_buf).decision);
}

test "PolicyEngine: missing field with negated matcher succeeds" {
    const allocator = testing.allocator;

    // Drop logs where service attribute does NOT contain "critical"
    var policy: Policy = .{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-non-critical"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_attribute = try testMakeAttrPath(allocator, "service") },
        .match = .{ .regex = try allocator.dupe(u8, "^critical-s.*$") },
        .negate = true,
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // No service attribute = pattern cannot be found = negation succeeds = dropped
    var no_service: TestLogContext = .{ .message = "hello" };
    try testing.expectEqual(FilterDecision.drop, evalTestLog(&engine, &no_service, &policy_id_buf).decision);

    // Service without "critical" = negation succeeds = dropped
    var non_critical: TestLogContext = .{ .message = "hello", .service = "normal-service" };
    try testing.expectEqual(FilterDecision.drop, evalTestLog(&engine, &non_critical, &policy_id_buf).decision);

    // Service with "critical" = negation fails = unset
    var critical: TestLogContext = .{ .message = "hello", .service = "critical-service" };
    try testing.expectEqual(FilterDecision.unset, evalTestLog(&engine, &critical, &policy_id_buf).decision);
}

test "PolicyEngine: multiple policies with different matcher keys" {
    const allocator = testing.allocator;

    // Policy 1: Drop based on log_body
    var policy1: Policy = .{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-errors"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try policy1.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer policy1.deinit(allocator);

    // Policy 2: Drop based on log_attribute
    var policy2: Policy = .{
        .id = try allocator.dupe(u8, "policy-2"),
        .name = try allocator.dupe(u8, "drop-debug-service"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try policy2.target.?.log.match.append(allocator, .{
        .field = .{ .log_attribute = try testMakeAttrPath(allocator, "service") },
        .match = .{ .regex = try allocator.dupe(u8, "debug") },
    });
    defer policy2.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{ policy1, policy2 }, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Matches policy1
    var error_log: TestLogContext = .{ .message = "an error occurred", .service = "payment" };
    try testing.expectEqual(FilterDecision.drop, evalTestLog(&engine, &error_log, &policy_id_buf).decision);

    // Matches policy2
    var debug_log: TestLogContext = .{ .message = "all good", .service = "debug-service" };
    try testing.expectEqual(FilterDecision.drop, evalTestLog(&engine, &debug_log, &policy_id_buf).decision);

    // Matches neither
    var normal_log: TestLogContext = .{ .message = "all good", .service = "payment" };
    try testing.expectEqual(FilterDecision.unset, evalTestLog(&engine, &normal_log, &policy_id_buf).decision);
}

test "PolicyEngine: evaluate with null mutator" {
    const allocator = testing.allocator;

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-errors"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    // Test evaluate with null mutator returns full PolicyResult
    var error_log: TestLogContext = .{ .message = "an error occurred" };
    var policy_id_buf: [max_policies][]const u8 = undefined;
    try testing.expectEqual(FilterDecision.drop, evalTestLog(&engine, &error_log, &policy_id_buf).decision);

    var info_log: TestLogContext = .{ .message = "all good" };
    try testing.expectEqual(FilterDecision.unset, evalTestLog(&engine, &info_log, &policy_id_buf).decision);
}

test "FilterDecision: shouldContinue" {
    try testing.expect(FilterDecision.keep.shouldContinue());
    try testing.expect(FilterDecision.unset.shouldContinue());
    try testing.expect(!FilterDecision.drop.shouldContinue());
}

// =============================================================================
// Edge case tests for active policy tracking optimization
// =============================================================================

test "PolicyEngine: all policies positive only - none start active" {
    // Edge case: No policies have negated patterns, so policies_with_negation is empty.
    // Policies should only become active when positive patterns match.
    const allocator = testing.allocator;

    var policy1: Policy = .{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-errors"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try policy1.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer policy1.deinit(allocator);

    var policy2: Policy = .{
        .id = try allocator.dupe(u8, "policy-2"),
        .name = try allocator.dupe(u8, "drop-warning"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try policy2.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "warning") },
    });
    defer policy2.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{ policy1, policy2 }, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // No match - no policies become active
    var normal: TestLogContext = .{ .message = "all good" };
    try testing.expectEqual(FilterDecision.unset, evalTestLog(&engine, &normal, &policy_id_buf).decision);

    // Match policy1 only
    var error_log: TestLogContext = .{ .message = "error occurred" };
    try testing.expectEqual(FilterDecision.drop, evalTestLog(&engine, &error_log, &policy_id_buf).decision);

    // Match policy2 only
    var warning_log: TestLogContext = .{ .message = "warning issued" };
    try testing.expectEqual(FilterDecision.drop, evalTestLog(&engine, &warning_log, &policy_id_buf).decision);
}

test "PolicyEngine: all policies negated only - all start active" {
    // Edge case: All policies have only negated patterns.
    // All policies start active and match if their negated patterns don't match.
    const allocator = testing.allocator;

    var policy1: Policy = .{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-non-important"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try policy1.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "important") },
        .negate = true,
    });
    defer policy1.deinit(allocator);

    var policy2: Policy = .{
        .id = try allocator.dupe(u8, "policy-2"),
        .name = try allocator.dupe(u8, "drop-non-critical"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try policy2.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "critical") },
        .negate = true,
    });
    defer policy2.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{ policy1, policy2 }, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Neither "important" nor "critical" - both policies match
    var boring: TestLogContext = .{ .message = "just a normal log" };
    try testing.expectEqual(FilterDecision.drop, evalTestLog(&engine, &boring, &policy_id_buf).decision);

    // Contains "important" - policy1 fails, policy2 still matches
    var important: TestLogContext = .{ .message = "important data here" };
    try testing.expectEqual(FilterDecision.drop, evalTestLog(&engine, &important, &policy_id_buf).decision);

    // Contains "critical" - policy1 still matches, policy2 fails
    var critical: TestLogContext = .{ .message = "critical issue" };
    try testing.expectEqual(FilterDecision.drop, evalTestLog(&engine, &critical, &policy_id_buf).decision);

    // Contains both - both policies fail
    var both: TestLogContext = .{ .message = "important and critical" };
    try testing.expectEqual(FilterDecision.unset, evalTestLog(&engine, &both, &policy_id_buf).decision);
}

test "PolicyEngine: mix of positive-only and negated policies" {
    // Edge case: Some policies have negated patterns (start active), others don't.
    // Verifies both paths work correctly together.
    const allocator = testing.allocator;

    // Policy with only positive pattern
    var positive_policy: Policy = .{
        .id = try allocator.dupe(u8, "positive-policy"),
        .name = try allocator.dupe(u8, "drop-errors"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try positive_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer positive_policy.deinit(allocator);

    // Policy with only negated pattern
    var negated_policy: Policy = .{
        .id = try allocator.dupe(u8, "negated-policy"),
        .name = try allocator.dupe(u8, "drop-non-debug"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try negated_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "debug") },
        .negate = true,
    });
    defer negated_policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{ positive_policy, negated_policy }, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // No "error", no "debug" - negated policy matches (drops)
    var normal: TestLogContext = .{ .message = "normal log" };
    try testing.expectEqual(FilterDecision.drop, evalTestLog(&engine, &normal, &policy_id_buf).decision);

    // Contains "error", no "debug" - both policies match
    var error_log: TestLogContext = .{ .message = "error occurred" };
    try testing.expectEqual(FilterDecision.drop, evalTestLog(&engine, &error_log, &policy_id_buf).decision);

    // Contains "debug" - negated policy fails, positive policy doesn't match
    var debug_log: TestLogContext = .{ .message = "debug info" };
    try testing.expectEqual(FilterDecision.unset, evalTestLog(&engine, &debug_log, &policy_id_buf).decision);

    // Contains both "error" and "debug" - positive matches, negated fails
    var error_debug: TestLogContext = .{ .message = "error in debug mode" };
    try testing.expectEqual(FilterDecision.drop, evalTestLog(&engine, &error_debug, &policy_id_buf).decision);
}

test "PolicyEngine: multiple negated patterns same policy" {
    // Edge case: Policy with multiple negated patterns - all must "pass" (not match)
    const allocator = testing.allocator;

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-non-special"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    // Must NOT contain "skip" AND must NOT contain "ignore"
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "skip") },
        .negate = true,
    });
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "ignore") },
        .negate = true,
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Neither word - both negations pass - policy matches
    var normal: TestLogContext = .{ .message = "normal message" };
    try testing.expectEqual(FilterDecision.drop, evalTestLog(&engine, &normal, &policy_id_buf).decision);

    // Contains "skip" - first negation fails - policy doesn't match
    var skip: TestLogContext = .{ .message = "skip this one" };
    try testing.expectEqual(FilterDecision.unset, evalTestLog(&engine, &skip, &policy_id_buf).decision);

    // Contains "ignore" - second negation fails - policy doesn't match
    var ignore: TestLogContext = .{ .message = "ignore this" };
    try testing.expectEqual(FilterDecision.unset, evalTestLog(&engine, &ignore, &policy_id_buf).decision);

    // Contains both - both negations fail - policy doesn't match
    var both: TestLogContext = .{ .message = "skip and ignore" };
    try testing.expectEqual(FilterDecision.unset, evalTestLog(&engine, &both, &policy_id_buf).decision);
}

test "PolicyEngine: policy becomes active via positive then fails via negated" {
    // Edge case: Policy has both positive and negated patterns.
    // Positive matches first (becomes active), then negated also matches (fails).
    const allocator = testing.allocator;

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-errors-not-debug"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    // Must contain "error" AND must NOT contain "debug"
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "debug") },
        .negate = true,
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Has "error", no "debug" - positive matches, negation passes - policy matches
    var error_only: TestLogContext = .{ .message = "error occurred" };
    try testing.expectEqual(FilterDecision.drop, evalTestLog(&engine, &error_only, &policy_id_buf).decision);

    // Has both "error" and "debug" - positive matches but negation fails
    // required_match_count = 2 (1 positive + 1 negated)
    // match_counts starts at 1 (negated_count)
    // positive match: +1 -> 2
    // negated match: -1 -> 1
    // Final: 1 != 2 - policy doesn't match
    var error_debug: TestLogContext = .{ .message = "debug error message" };
    try testing.expectEqual(FilterDecision.unset, evalTestLog(&engine, &error_debug, &policy_id_buf).decision);

    // Has "debug" but no "error" - positive doesn't match, negation fails
    // match_counts starts at 1, negated match: -1 -> 0, final: 0 != 2
    var debug_only: TestLogContext = .{ .message = "debug info" };
    try testing.expectEqual(FilterDecision.unset, evalTestLog(&engine, &debug_only, &policy_id_buf).decision);

    // Has neither - positive doesn't match, negation passes
    // match_counts stays at 1 (negated_count), final: 1 != 2
    var neither: TestLogContext = .{ .message = "normal log" };
    try testing.expectEqual(FilterDecision.unset, evalTestLog(&engine, &neither, &policy_id_buf).decision);
}

// =============================================================================
// Tests for evaluate() with transforms
// =============================================================================

/// Mutable test context that supports both FieldAccessor and FieldMutator
const MutableTestLogContext = struct {
    level: ?[]const u8 = null,
    message: ?[]const u8 = null,
    service: ?[]const u8 = null,
    ddtags: ?[]const u8 = null,
    env: ?[]const u8 = null,

    // Dynamic attributes stored in a hash map
    attributes: std.StringHashMap([]const u8),
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator) MutableTestLogContext {
        return .{
            .attributes = std.StringHashMap([]const u8).init(allocator),
            .allocator = allocator,
        };
    }

    fn deinit(self: *MutableTestLogContext) void {
        defer self.* = undefined;

        var it = self.attributes.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.attributes.deinit();
    }

    fn setAttribute(self: *MutableTestLogContext, key: []const u8, value: []const u8) !void {
        const value_copy = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(value_copy);

        const gop = try self.attributes.getOrPut(key);
        if (gop.found_existing) {
            self.allocator.free(gop.value_ptr.*);
            gop.value_ptr.* = value_copy;
        } else {
            gop.key_ptr.* = try self.allocator.dupe(u8, key);
            gop.value_ptr.* = value_copy;
        }
    }

    fn removeAttribute(self: *MutableTestLogContext, key: []const u8) bool {
        if (self.attributes.fetchRemove(key)) |removed| {
            self.allocator.free(removed.key);
            self.allocator.free(removed.value);
            return true;
        }
        return false;
    }

    pub fn fieldAccessor(ctx_ptr: *const anyopaque, field: FieldRef) ?[]const u8 {
        const self: *const MutableTestLogContext = @ptrCast(@alignCast(ctx_ptr));
        return switch (field) {
            .log_field => |lf| switch (lf) {
                .LOG_FIELD_BODY => self.message,
                .LOG_FIELD_SEVERITY_TEXT => self.level,
                else => null,
            },
            .log_attribute => |attr_path| {
                const key = if (attr_path.path.items.len > 0) attr_path.path.items[0] else return null;
                // Check fixed fields first
                if (std.mem.eql(u8, key, "service")) return self.service;
                if (std.mem.eql(u8, key, "ddtags")) return self.ddtags;
                if (std.mem.eql(u8, key, "message")) return self.message;
                if (std.mem.eql(u8, key, "env")) return self.env;
                // Check dynamic attributes
                return self.attributes.get(key);
            },
            .resource_attribute, .scope_attribute => null,
        };
    }

    fn attrKey(field: FieldRef) ?[]const u8 {
        return switch (field) {
            .log_attribute => |p| if (p.path.items.len > 0) p.path.items[0] else null,
            else => null,
        };
    }

    fn accessorDelete(ctx_ptr: *anyopaque, field: FieldRef) bool {
        const self: *MutableTestLogContext = @ptrCast(@alignCast(ctx_ptr));
        const key = attrKey(field) orelse return false;
        if (std.mem.eql(u8, key, "service")) {
            if (self.service != null) {
                self.service = null;
                return true;
            }
            return false;
        }
        if (std.mem.eql(u8, key, "env")) {
            if (self.env != null) {
                self.env = null;
                return true;
            }
            return false;
        }
        return self.removeAttribute(key);
    }

    fn accessorSet(ctx_ptr: *anyopaque, field: FieldRef, value: []const u8) void {
        const self: *MutableTestLogContext = @ptrCast(@alignCast(ctx_ptr));
        const key = attrKey(field) orelse return;
        if (std.mem.eql(u8, key, "service")) {
            self.service = value;
            return;
        }
        if (std.mem.eql(u8, key, "env")) {
            self.env = value;
            return;
        }
        self.setAttribute(key, value) catch return;
    }

    fn accessorMove(ctx_ptr: *anyopaque, from: FieldRef, to: []const u8) void {
        const self: *MutableTestLogContext = @ptrCast(@alignCast(ctx_ptr));
        const from_key = attrKey(from) orelse return;
        var value: ?[]const u8 = null;
        if (std.mem.eql(u8, from_key, "service")) {
            value = self.service;
            if (value != null) self.service = null;
        } else if (std.mem.eql(u8, from_key, "env")) {
            value = self.env;
            if (value != null) self.env = null;
        } else if (self.attributes.get(from_key)) |v| {
            value = v;
            _ = self.removeAttribute(from_key);
        }
        if (value) |v| self.setAttribute(to, v) catch return;
    }

    fn typedAccessor(ctx_ptr: *const anyopaque, field: FieldRef) ?TypedValue {
        return .{ .string = fieldAccessor(ctx_ptr, field) orelse return null };
    }

    pub const accessor: LogAccessor = .{
        .typed_value = typedAccessor,
        .set = accessorSet,
        .delete = accessorDelete,
        .move = accessorMove,
    };
};

fn evalMutableLog(
    engine: *const PolicyEngine,
    ctx: *MutableTestLogContext,
    policy_id_buf: [][]const u8,
) PolicyResult {
    return engine.evaluate(.log, &MutableTestLogContext.accessor, ctx, policy_id_buf, .{
        .io = std.Options.debug_io,
    });
}

fn evalMutableLogScratch(
    engine: *const PolicyEngine,
    scratch: std.mem.Allocator,
    ctx: *MutableTestLogContext,
    policy_id_buf: [][]const u8,
) PolicyResult {
    return engine.evaluate(.log, &MutableTestLogContext.accessor, ctx, policy_id_buf, .{
        .scratch = scratch,
        .io = std.Options.debug_io,
    });
}

// =============================================================================
// TypedLogContext - log context that exposes typed attribute values
// =============================================================================

/// A log record whose attributes are typed scalars (int/double/bool/string).
/// Used by typed matcher tests to verify equals/gt/gte/lt/lte evaluation.
const TypedAttrValue = union(enum) {
    string: []const u8,
    int: i64,
    double: f64,
    bool: bool,
};

const TypedLogContext = struct {
    attrs: std.StringHashMap(TypedAttrValue),
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator) TypedLogContext {
        return .{
            .attrs = std.StringHashMap(TypedAttrValue).init(allocator),
            .allocator = allocator,
        };
    }

    fn deinit(self: *TypedLogContext) void {
        defer self.* = undefined;
        self.attrs.deinit();
    }

    fn withInt(self: *TypedLogContext, key: []const u8, v: i64) !*TypedLogContext {
        try self.attrs.put(key, .{ .int = v });
        return self;
    }

    fn withDouble(self: *TypedLogContext, key: []const u8, v: f64) !*TypedLogContext {
        try self.attrs.put(key, .{ .double = v });
        return self;
    }

    fn withBool(self: *TypedLogContext, key: []const u8, v: bool) !*TypedLogContext {
        try self.attrs.put(key, .{ .bool = v });
        return self;
    }

    fn withString(self: *TypedLogContext, key: []const u8, v: []const u8) !*TypedLogContext {
        try self.attrs.put(key, .{ .string = v });
        return self;
    }

    fn attrKey(field: FieldRef) ?[]const u8 {
        return switch (field) {
            .log_attribute => |p| if (p.path.items.len > 0) p.path.items[0] else null,
            else => null,
        };
    }

    fn fieldTypedValue(ctx_ptr: *const anyopaque, field: FieldRef) ?TypedValue {
        const self: *const TypedLogContext = @ptrCast(@alignCast(ctx_ptr));
        const key = attrKey(field) orelse return null;
        return switch (self.attrs.get(key) orelse return null) {
            .string => |s| TypedValue{ .string = s },
            .int => |i| TypedValue{ .int = i },
            .double => |d| TypedValue{ .double = d },
            .bool => |b| TypedValue{ .bool = b },
        };
    }

    pub const accessor: LogAccessor = .{
        .typed_value = fieldTypedValue,
    };
};

fn evalTypedLog(
    engine: *const PolicyEngine,
    ctx: *TypedLogContext,
    policy_id_buf: [][]const u8,
) PolicyResult {
    return engine.evaluate(.log, &TypedLogContext.accessor, ctx, policy_id_buf, .{
        .io = std.Options.debug_io,
    });
}

// =============================================================================
// Typed matcher engine tests (v1.5.0)
// =============================================================================

fn makeLogTypedPolicy(
    allocator: std.mem.Allocator,
    id: []const u8,
    attr_key: []const u8,
    match: proto.policy.LogMatcher.match_union,
    keep: []const u8,
) !Policy {
    var attr_path: proto.policy.AttributePath = .{};
    try attr_path.path.append(allocator, try allocator.dupe(u8, attr_key));

    var policy: Policy = .{
        .id = try allocator.dupe(u8, id),
        .name = try allocator.dupe(u8, id),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, keep),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_attribute = attr_path },
        .match = match,
    });
    return policy;
}

test "typed: equals int match and miss" {
    const allocator = testing.allocator;

    const nv: proto.policy.Value = .{ .value = .{ .int_value = 200 } };
    var policy = try makeLogTypedPolicy(allocator, "drop-200", "status", .{ .equals = nv }, "none");
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    var ctx = TypedLogContext.init(allocator);
    defer ctx.deinit();

    _ = try ctx.withInt("status", 200);
    try testing.expectEqual(FilterDecision.drop, evalTypedLog(&engine, &ctx, &policy_id_buf).decision);

    var ctx2 = TypedLogContext.init(allocator);
    defer ctx2.deinit();
    _ = try ctx2.withInt("status", 404);
    try testing.expectEqual(FilterDecision.unset, evalTypedLog(&engine, &ctx2, &policy_id_buf).decision);
}

test "typed: equals bool match and miss" {
    const allocator = testing.allocator;

    const bv: proto.policy.Value = .{ .value = .{ .bool_value = true } };
    var policy = try makeLogTypedPolicy(allocator, "drop-cache-hits", "cache.hit", .{ .equals = bv }, "none");
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    var ctx_hit = TypedLogContext.init(allocator);
    defer ctx_hit.deinit();
    _ = try ctx_hit.withBool("cache.hit", true);
    try testing.expectEqual(FilterDecision.drop, evalTypedLog(&engine, &ctx_hit, &policy_id_buf).decision);

    var ctx_miss = TypedLogContext.init(allocator);
    defer ctx_miss.deinit();
    _ = try ctx_miss.withBool("cache.hit", false);
    try testing.expectEqual(FilterDecision.unset, evalTypedLog(&engine, &ctx_miss, &policy_id_buf).decision);
}

test "typed: gte int match and miss" {
    const allocator = testing.allocator;

    const nv: proto.policy.NumericValue = .{ .value = .{ .int_value = 500 } };
    var policy = try makeLogTypedPolicy(allocator, "drop-errors", "status", .{ .gte = nv }, "none");
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    var ctx500 = TypedLogContext.init(allocator);
    defer ctx500.deinit();
    _ = try ctx500.withInt("status", 500);
    try testing.expectEqual(FilterDecision.drop, evalTypedLog(&engine, &ctx500, &policy_id_buf).decision);

    var ctx503 = TypedLogContext.init(allocator);
    defer ctx503.deinit();
    _ = try ctx503.withInt("status", 503);
    try testing.expectEqual(FilterDecision.drop, evalTypedLog(&engine, &ctx503, &policy_id_buf).decision);

    var ctx499 = TypedLogContext.init(allocator);
    defer ctx499.deinit();
    _ = try ctx499.withInt("status", 499);
    try testing.expectEqual(FilterDecision.unset, evalTypedLog(&engine, &ctx499, &policy_id_buf).decision);
}

test "typed: lt double match and miss" {
    const allocator = testing.allocator;

    const nv: proto.policy.NumericValue = .{ .value = .{ .double_value = 0.1 } };
    var policy = try makeLogTypedPolicy(allocator, "drop-fast", "duration_s", .{ .lt = nv }, "none");
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    var ctx_fast = TypedLogContext.init(allocator);
    defer ctx_fast.deinit();
    _ = try ctx_fast.withDouble("duration_s", 0.05);
    try testing.expectEqual(FilterDecision.drop, evalTypedLog(&engine, &ctx_fast, &policy_id_buf).decision);

    var ctx_slow = TypedLogContext.init(allocator);
    defer ctx_slow.deinit();
    _ = try ctx_slow.withDouble("duration_s", 0.1);
    try testing.expectEqual(FilterDecision.unset, evalTypedLog(&engine, &ctx_slow, &policy_id_buf).decision);
}

test "typed: range AND logic (gte 200 AND lt 400)" {
    const allocator = testing.allocator;

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "drop-success"),
        .name = try allocator.dupe(u8, "drop-success"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    {
        var attr: proto.policy.AttributePath = .{};
        try attr.path.append(allocator, try allocator.dupe(u8, "status"));
        try policy.target.?.log.match.append(allocator, .{
            .field = .{ .log_attribute = attr },
            .match = .{ .gte = .{ .value = .{ .int_value = 200 } } },
        });
    }
    {
        var attr: proto.policy.AttributePath = .{};
        try attr.path.append(allocator, try allocator.dupe(u8, "status"));
        try policy.target.?.log.match.append(allocator, .{
            .field = .{ .log_attribute = attr },
            .match = .{ .lt = .{ .value = .{ .int_value = 400 } } },
        });
    }
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    var ctx200 = TypedLogContext.init(allocator);
    defer ctx200.deinit();
    _ = try ctx200.withInt("status", 200);
    try testing.expectEqual(FilterDecision.drop, evalTypedLog(&engine, &ctx200, &policy_id_buf).decision);

    var ctx301 = TypedLogContext.init(allocator);
    defer ctx301.deinit();
    _ = try ctx301.withInt("status", 301);
    try testing.expectEqual(FilterDecision.drop, evalTypedLog(&engine, &ctx301, &policy_id_buf).decision);

    var ctx400 = TypedLogContext.init(allocator);
    defer ctx400.deinit();
    _ = try ctx400.withInt("status", 400);
    try testing.expectEqual(FilterDecision.unset, evalTypedLog(&engine, &ctx400, &policy_id_buf).decision);

    var ctx500 = TypedLogContext.init(allocator);
    defer ctx500.deinit();
    _ = try ctx500.withInt("status", 500);
    try testing.expectEqual(FilterDecision.unset, evalTypedLog(&engine, &ctx500, &policy_id_buf).decision);
}

test "typed: type mismatch is non-match" {
    const allocator = testing.allocator;

    // int matcher, string field value → non-match
    const nv: proto.policy.Value = .{ .value = .{ .int_value = 200 } };
    var policy = try makeLogTypedPolicy(allocator, "drop-200", "status", .{ .equals = nv }, "none");
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    var ctx = TypedLogContext.init(allocator);
    defer ctx.deinit();
    _ = try ctx.withString("status", "200");
    try testing.expectEqual(FilterDecision.unset, evalTypedLog(&engine, &ctx, &policy_id_buf).decision);
}

test "typed: numeric cross-domain int equals double" {
    const allocator = testing.allocator;

    // int_value: 5 should match a double field with value 5.0
    const nv: proto.policy.Value = .{ .value = .{ .int_value = 5 } };
    var policy = try makeLogTypedPolicy(allocator, "match-five", "x", .{ .equals = nv }, "all");
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    var ctx = TypedLogContext.init(allocator);
    defer ctx.deinit();
    _ = try ctx.withDouble("x", 5.0);
    try testing.expectEqual(FilterDecision.keep, evalTypedLog(&engine, &ctx, &policy_id_buf).decision);
}

test "typed: negated equals" {
    const allocator = testing.allocator;

    var attr_path: proto.policy.AttributePath = .{};
    try attr_path.path.append(allocator, try allocator.dupe(u8, "status"));

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "drop-non-200"),
        .name = try allocator.dupe(u8, "drop-non-200"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_attribute = attr_path },
        .match = .{ .equals = .{ .value = .{ .int_value = 200 } } },
        .negate = true,
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // status=200: negated equals fires (200==200) → policy disqualified → no match
    var ctx200 = TypedLogContext.init(allocator);
    defer ctx200.deinit();
    _ = try ctx200.withInt("status", 200);
    try testing.expectEqual(FilterDecision.unset, evalTypedLog(&engine, &ctx200, &policy_id_buf).decision);

    // status=500: negated equals does not fire (500≠200) → policy matches → drop
    var ctx500 = TypedLogContext.init(allocator);
    defer ctx500.deinit();
    _ = try ctx500.withInt("status", 500);
    try testing.expectEqual(FilterDecision.drop, evalTypedLog(&engine, &ctx500, &policy_id_buf).decision);
}

test "typed: equals string_value matches like exact (v1.6.0)" {
    const allocator = testing.allocator;

    const sv: proto.policy.Value = .{ .value = .{ .string_value = try allocator.dupe(u8, "checkout-api") } };
    var policy = try makeLogTypedPolicy(allocator, "drop-checkout", "service.name", .{ .equals = sv }, "none");
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    var ctx = TypedLogContext.init(allocator);
    defer ctx.deinit();
    _ = try ctx.withString("service.name", "checkout-api");
    try testing.expectEqual(FilterDecision.drop, evalTypedLog(&engine, &ctx, &policy_id_buf).decision);

    // Prefix is not equality
    var ctx2 = TypedLogContext.init(allocator);
    defer ctx2.deinit();
    _ = try ctx2.withString("service.name", "checkout-api-v2");
    try testing.expectEqual(FilterDecision.unset, evalTypedLog(&engine, &ctx2, &policy_id_buf).decision);

    // Different case does not match without case_insensitive
    var ctx3 = TypedLogContext.init(allocator);
    defer ctx3.deinit();
    _ = try ctx3.withString("service.name", "CHECKOUT-API");
    try testing.expectEqual(FilterDecision.unset, evalTypedLog(&engine, &ctx3, &policy_id_buf).decision);
}

test "typed: equals string_value with case_insensitive (v1.6.0)" {
    const allocator = testing.allocator;

    var attr_path: proto.policy.AttributePath = .{};
    try attr_path.path.append(allocator, try allocator.dupe(u8, "env"));

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "drop-prod"),
        .name = try allocator.dupe(u8, "drop-prod"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_attribute = attr_path },
        .match = .{ .equals = .{ .value = .{ .string_value = try allocator.dupe(u8, "production") } } },
        .case_insensitive = true,
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    var ctx = TypedLogContext.init(allocator);
    defer ctx.deinit();
    _ = try ctx.withString("env", "PRODUCTION");
    try testing.expectEqual(FilterDecision.drop, evalTypedLog(&engine, &ctx, &policy_id_buf).decision);
}

test "evaluate: policy with keep=all and no transform" {
    const allocator = testing.allocator;

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "keep-policy"),
        .name = try allocator.dupe(u8, "keep-errors"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "all"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    var ctx = MutableTestLogContext.init(allocator);
    defer ctx.deinit();
    ctx.message = "an error occurred";
    ctx.service = "payment-api";

    var policy_id_buf: [16][]const u8 = undefined;
    const result = evalMutableLog(&engine, &ctx, &policy_id_buf);

    try testing.expectEqual(FilterDecision.keep, result.decision);
    try testing.expectEqual(@as(usize, 1), result.matched_policy_ids.len);
    try testing.expectEqualStrings("keep-policy", result.matched_policy_ids[0]);
    // No transform, so context unchanged
    try testing.expectEqualStrings("payment-api", ctx.service.?);
}

test "evaluate: policy with keep=all and remove transform" {
    const allocator = testing.allocator;

    var transform: proto.policy.LogTransform = .{};
    try transform.remove.append(allocator, .{
        .field = .{ .log_attribute = try testMakeAttrPath(allocator, "env") },
    });

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "transform-policy"),
        .name = try allocator.dupe(u8, "remove-env"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "all"),
            .transform = transform,
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    var ctx = MutableTestLogContext.init(allocator);
    defer ctx.deinit();
    ctx.message = "an error occurred";
    ctx.service = "payment-api";
    ctx.env = "production";

    var policy_id_buf: [16][]const u8 = undefined;
    const result = evalMutableLog(&engine, &ctx, &policy_id_buf);

    try testing.expectEqual(FilterDecision.keep, result.decision);
    // Transform should have removed 'env'
    try testing.expect(ctx.env == null);
    // Other fields unchanged
    try testing.expectEqualStrings("payment-api", ctx.service.?);
}

test "evaluate: policy with keep=all and redact transform" {
    const allocator = testing.allocator;

    var transform: proto.policy.LogTransform = .{};
    try transform.redact.append(allocator, .{
        .field = .{ .log_attribute = try testMakeAttrPath(allocator, "service") },
        .replacement = try allocator.dupe(u8, "[REDACTED]"),
    });

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "redact-policy"),
        .name = try allocator.dupe(u8, "redact-service"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "all"),
            .transform = transform,
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "sensitive") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    var ctx = MutableTestLogContext.init(allocator);
    defer ctx.deinit();
    ctx.message = "sensitive data here";
    ctx.service = "secret-service";

    var policy_id_buf: [16][]const u8 = undefined;
    const result = evalMutableLog(&engine, &ctx, &policy_id_buf);

    try testing.expectEqual(FilterDecision.keep, result.decision);
    // Transform should have redacted 'service'
    try testing.expectEqualStrings("[REDACTED]", ctx.service.?);
}

test "evaluate: policy with regex-targeted redact transform (v1.4.0)" {
    const allocator = testing.allocator;
    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();

    var transform: proto.policy.LogTransform = .{};
    try transform.redact.append(allocator, .{
        .field = .{ .log_attribute = try testMakeAttrPath(allocator, "url") },
        .replacement = try allocator.dupe(u8, "$1[REDACTED]$2"),
        .regex = try allocator.dupe(u8, "([?&]password=)[^&\\s]+(&session_id=)"),
    });

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "redact-password-query-param"),
        .name = try allocator.dupe(u8, "redact-password-query-param"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "all"),
            .transform = transform,
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_attribute = try testMakeAttrPath(allocator, "url") },
        .match = .{ .regex = try allocator.dupe(u8, "password=") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    var ctx = MutableTestLogContext.init(allocator);
    defer ctx.deinit();
    try ctx.setAttribute("url", "?user=alice&password=secret123&session_id=xyz");

    var policy_id_buf: [16][]const u8 = undefined;
    const result = evalMutableLogScratch(&engine, scratch.allocator(), &ctx, &policy_id_buf);

    try testing.expectEqual(FilterDecision.keep, result.decision);
    try testing.expect(result.was_transformed);
    try testing.expectEqualStrings(
        "?user=alice&password=[REDACTED]&session_id=xyz",
        ctx.attributes.get("url").?,
    );
}

test "evaluate: regex redact with no match leaves field unchanged" {
    const allocator = testing.allocator;
    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();

    var transform: proto.policy.LogTransform = .{};
    try transform.redact.append(allocator, .{
        .field = .{ .log_attribute = try testMakeAttrPath(allocator, "url") },
        .replacement = try allocator.dupe(u8, "X"),
        .regex = try allocator.dupe(u8, "password=\\S+"),
    });

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "p"),
        .name = try allocator.dupe(u8, "p"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "all"),
            .transform = transform,
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_attribute = try testMakeAttrPath(allocator, "url") },
        .match = .{ .exists = true },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    var ctx = MutableTestLogContext.init(allocator);
    defer ctx.deinit();
    try ctx.setAttribute("url", "/no-secrets-here");

    var policy_id_buf: [16][]const u8 = undefined;
    const result = evalMutableLogScratch(&engine, scratch.allocator(), &ctx, &policy_id_buf);

    try testing.expectEqual(FilterDecision.keep, result.decision);
    try testing.expect(!result.was_transformed);
    try testing.expectEqualStrings("/no-secrets-here", ctx.attributes.get("url").?);
}

test "evaluate: policy with keep=all and add transform" {
    const allocator = testing.allocator;

    var transform: proto.policy.LogTransform = .{};
    try transform.add.append(allocator, .{
        .field = .{ .log_attribute = try testMakeAttrPath(allocator, "processed") },
        .value = try allocator.dupe(u8, "true"),
        .upsert = true,
    });

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "add-policy"),
        .name = try allocator.dupe(u8, "add-processed"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "all"),
            .transform = transform,
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    var ctx = MutableTestLogContext.init(allocator);
    defer ctx.deinit();
    ctx.message = "an error occurred";

    var policy_id_buf: [16][]const u8 = undefined;
    const result = evalMutableLog(&engine, &ctx, &policy_id_buf);

    try testing.expectEqual(FilterDecision.keep, result.decision);
    // Transform should have added 'processed'
    try testing.expectEqualStrings("true", ctx.attributes.get("processed").?);
}

test "evaluate: policy with no keep (drop) skips transform" {
    const allocator = testing.allocator;

    var transform: proto.policy.LogTransform = .{};
    try transform.remove.append(allocator, .{
        .field = .{ .log_attribute = try testMakeAttrPath(allocator, "env") },
    });

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "drop-policy"),
        .name = try allocator.dupe(u8, "drop-errors"),
        .enabled = true,
        .target = .{
            .log = .{
                .keep = try allocator.dupe(u8, "none"),
                .transform = transform, // Transform should NOT be applied for drops
            },
        },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    var ctx = MutableTestLogContext.init(allocator);
    defer ctx.deinit();
    ctx.message = "an error occurred";
    ctx.env = "production";

    var policy_id_buf: [16][]const u8 = undefined;
    const result = evalMutableLog(&engine, &ctx, &policy_id_buf);

    try testing.expectEqual(FilterDecision.drop, result.decision);
    // Transform should NOT have been applied (log is dropped)
    try testing.expectEqualStrings("production", ctx.env.?);
}

test "evaluate: multiple policies with different transforms" {
    const allocator = testing.allocator;

    // Policy 1: matches "error", adds tag
    var transform1: proto.policy.LogTransform = .{};
    try transform1.add.append(allocator, .{
        .field = .{ .log_attribute = try testMakeAttrPath(allocator, "error_tag") },
        .value = try allocator.dupe(u8, "true"),
        .upsert = true,
    });

    var policy1: Policy = .{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "tag-errors"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "all"),
            .transform = transform1,
        } },
    };
    try policy1.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });

    // Policy 2: matches "payment", removes env
    var transform2: proto.policy.LogTransform = .{};
    try transform2.remove.append(allocator, .{
        .field = .{ .log_attribute = try testMakeAttrPath(allocator, "env") },
    });

    var policy2: Policy = .{
        .id = try allocator.dupe(u8, "policy-2"),
        .name = try allocator.dupe(u8, "clean-payment"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "all"),
            .transform = transform2,
        } },
    };
    try policy2.target.?.log.match.append(allocator, .{
        .field = .{ .log_attribute = try testMakeAttrPath(allocator, "service") },
        .match = .{ .regex = try allocator.dupe(u8, "payment") },
    });

    defer policy1.deinit(allocator);
    defer policy2.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{ policy1, policy2 }, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    // Log matches BOTH policies
    var ctx = MutableTestLogContext.init(allocator);
    defer ctx.deinit();
    ctx.message = "payment error occurred";
    ctx.service = "payment-api";
    ctx.env = "production";

    var policy_id_buf: [16][]const u8 = undefined;
    const result = evalMutableLog(&engine, &ctx, &policy_id_buf);

    try testing.expectEqual(FilterDecision.keep, result.decision);
    try testing.expectEqual(@as(usize, 2), result.matched_policy_ids.len);

    // Both transforms should have been applied
    try testing.expectEqualStrings("true", ctx.attributes.get("error_tag").?);
    try testing.expect(ctx.env == null);
}

test "evaluate: policy with unset keep applies transform" {
    const allocator = testing.allocator;

    var transform: proto.policy.LogTransform = .{};
    try transform.add.append(allocator, .{
        .field = .{ .log_attribute = try testMakeAttrPath(allocator, "tagged") },
        .value = try allocator.dupe(u8, "yes"),
        .upsert = true,
    });

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "unset-policy"),
        .name = try allocator.dupe(u8, "tag-only"),
        .enabled = true,
        .target = .{
            .log = .{
                // keep is null (unset) - should still apply transforms
                .transform = transform,
            },
        },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "info") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    var ctx = MutableTestLogContext.init(allocator);
    defer ctx.deinit();
    ctx.message = "info log message";

    var policy_id_buf: [16][]const u8 = undefined;
    const result = evalMutableLog(&engine, &ctx, &policy_id_buf);

    // When keep is not specified, it defaults to "all" which means keep
    try testing.expectEqual(FilterDecision.keep, result.decision);
    try testing.expectEqual(@as(usize, 1), result.matched_policy_ids.len);
    try testing.expectEqualStrings("yes", ctx.attributes.get("tagged").?);
}

// The previous "null mutator skips transforms" test exercised a code path
// that no longer exists: passing a null field_mutator to evaluate() to opt
// out of transforms. In the accessor-template model, a read-only consumer
// signals its capability set by wiring only `value` on LogAccessor; any
// policy with a transform is rejected at snapshot-compile time.

test "evaluate: policy without transform field" {
    const allocator = testing.allocator;

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "no-transform"),
        .name = try allocator.dupe(u8, "just-keep"),
        .enabled = true,
        .target = .{
            .log = .{
                .keep = try allocator.dupe(u8, "all"),
                // No transform field
            },
        },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    var ctx = MutableTestLogContext.init(allocator);
    defer ctx.deinit();
    ctx.message = "an error occurred";
    ctx.env = "production";

    var policy_id_buf: [16][]const u8 = undefined;
    const result = evalMutableLog(&engine, &ctx, &policy_id_buf);

    try testing.expectEqual(FilterDecision.keep, result.decision);
    // No transform, env unchanged
    try testing.expectEqualStrings("production", ctx.env.?);
}

test "evaluate: mixed keep and drop policies - only keep applies transforms" {
    const allocator = testing.allocator;

    // Policy 1: drop errors (no transform should apply)
    var drop_transform: proto.policy.LogTransform = .{};
    try drop_transform.add.append(allocator, .{
        .field = .{ .log_attribute = try testMakeAttrPath(allocator, "dropped") },
        .value = try allocator.dupe(u8, "should-not-appear"),
        .upsert = true,
    });

    var drop_policy: Policy = .{
        .id = try allocator.dupe(u8, "drop-policy"),
        .name = try allocator.dupe(u8, "drop-debug"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
            .transform = drop_transform,
        } },
    };
    try drop_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "debug") },
    });

    // Policy 2: keep errors with transform
    var keep_transform: proto.policy.LogTransform = .{};
    try keep_transform.add.append(allocator, .{
        .field = .{ .log_attribute = try testMakeAttrPath(allocator, "kept") },
        .value = try allocator.dupe(u8, "yes"),
        .upsert = true,
    });

    var keep_policy: Policy = .{
        .id = try allocator.dupe(u8, "keep-policy"),
        .name = try allocator.dupe(u8, "keep-errors"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "all"),
            .transform = keep_transform,
        } },
    };
    try keep_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });

    defer drop_policy.deinit(allocator);
    defer keep_policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{ drop_policy, keep_policy }, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    // Test 1: Log matches only drop policy
    {
        var ctx = MutableTestLogContext.init(allocator);
        defer ctx.deinit();
        ctx.message = "debug message";

        var policy_id_buf: [16][]const u8 = undefined;
        const result = evalMutableLog(&engine, &ctx, &policy_id_buf);

        try testing.expectEqual(FilterDecision.drop, result.decision);
        // Transform should NOT be applied for drop
        try testing.expect(ctx.attributes.get("dropped") == null);
    }

    // Test 2: Log matches only keep policy
    {
        var ctx = MutableTestLogContext.init(allocator);
        defer ctx.deinit();
        ctx.message = "error occurred";

        var policy_id_buf: [16][]const u8 = undefined;
        const result = evalMutableLog(&engine, &ctx, &policy_id_buf);

        try testing.expectEqual(FilterDecision.keep, result.decision);
        // Transform should be applied for keep
        try testing.expectEqualStrings("yes", ctx.attributes.get("kept").?);
    }
}

// =============================================================================
// Stats Recording Tests
// =============================================================================

test "PolicyEngine stats: single winner among equally-restrictive DROP policies" {
    const allocator = testing.allocator;

    // Two DROP policies that both match
    var drop_policy1: Policy = .{
        .id = try allocator.dupe(u8, "drop-1"),
        .name = try allocator.dupe(u8, "drop-errors"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try drop_policy1.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer drop_policy1.deinit(allocator);

    var drop_policy2: Policy = .{
        .id = try allocator.dupe(u8, "drop-2"),
        .name = try allocator.dupe(u8, "drop-critical"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try drop_policy2.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "critical") },
    });
    defer drop_policy2.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{ drop_policy1, drop_policy2 }, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    // Log matches both DROP policies
    var test_log: TestLogContext = .{ .message = "critical error occurred" };
    var policy_id_buf: [16][]const u8 = undefined;
    const result = evalTestLog(&engine, &test_log, &policy_id_buf);

    try testing.expectEqual(FilterDecision.drop, result.decision);

    // Single-winner: only one of the equally-restrictive policies gets a hit
    const snapshot = registry.getSnapshot().?;

    const stats0 = snapshot.getStats(0).?;
    const stats1 = snapshot.getStats(1).?;
    const total_hits = stats0.hits.load(.monotonic) + stats1.hits.load(.monotonic);
    const total_misses = stats0.misses.load(.monotonic) + stats1.misses.load(.monotonic);
    try testing.expectEqual(@as(i64, 1), total_hits);
    try testing.expectEqual(@as(i64, 1), total_misses);
}

test "PolicyEngine stats: all KEEP policies get hits" {
    const allocator = testing.allocator;

    // Two KEEP policies that both match
    var keep_policy1: Policy = .{
        .id = try allocator.dupe(u8, "keep-1"),
        .name = try allocator.dupe(u8, "keep-errors"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "all") } },
    };
    try keep_policy1.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer keep_policy1.deinit(allocator);

    var keep_policy2: Policy = .{
        .id = try allocator.dupe(u8, "keep-2"),
        .name = try allocator.dupe(u8, "keep-critical"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "all") } },
    };
    try keep_policy2.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "critical") },
    });
    defer keep_policy2.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{ keep_policy1, keep_policy2 }, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    // Log matches both KEEP policies
    var test_log: TestLogContext = .{ .message = "critical error occurred" };
    var policy_id_buf: [16][]const u8 = undefined;
    const result = evalTestLog(&engine, &test_log, &policy_id_buf);

    try testing.expectEqual(FilterDecision.keep, result.decision);

    // Both policies should get hits via lock-free atomic stats on snapshot
    const snapshot = registry.getSnapshot().?;

    // Policy 0 (keep-1) should have 1 hit
    const stats0 = snapshot.getStats(0).?;
    try testing.expectEqual(@as(i64, 1), stats0.hits.load(.monotonic));
    try testing.expectEqual(@as(i64, 0), stats0.misses.load(.monotonic));

    // Policy 1 (keep-2) should have 1 hit
    const stats1 = snapshot.getStats(1).?;
    try testing.expectEqual(@as(i64, 1), stats1.hits.load(.monotonic));
    try testing.expectEqual(@as(i64, 0), stats1.misses.load(.monotonic));
}

test "PolicyEngine stats: mixed KEEP and DROP - DROP gets hits, KEEP gets misses" {
    const allocator = testing.allocator;

    // One KEEP and one DROP policy that both match
    var keep_policy: Policy = .{
        .id = try allocator.dupe(u8, "keep-policy"),
        .name = try allocator.dupe(u8, "keep-errors"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "all") } },
    };
    try keep_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer keep_policy.deinit(allocator);

    var drop_policy: Policy = .{
        .id = try allocator.dupe(u8, "drop-policy"),
        .name = try allocator.dupe(u8, "drop-critical"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try drop_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "critical") },
    });
    defer drop_policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{ keep_policy, drop_policy }, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    // Log matches both policies (KEEP and DROP)
    var test_log: TestLogContext = .{ .message = "critical error occurred" };
    var policy_id_buf: [16][]const u8 = undefined;
    const result = evalTestLog(&engine, &test_log, &policy_id_buf);

    // DROP wins (most restrictive)
    try testing.expectEqual(FilterDecision.drop, result.decision);

    // Both policies should have stats recorded via lock-free atomics
    // After sorting by ID: "drop-policy" is index 0, "keep-policy" is index 1
    const snapshot = registry.getSnapshot().?;

    // DROP policy (index 0 after sort) gets hit
    const drop_stats = snapshot.getStats(0).?;
    try testing.expectEqual(@as(i64, 1), drop_stats.hits.load(.monotonic));
    try testing.expectEqual(@as(i64, 0), drop_stats.misses.load(.monotonic));

    // KEEP policy (index 1 after sort) gets miss
    const keep_stats = snapshot.getStats(1).?;
    try testing.expectEqual(@as(i64, 0), keep_stats.hits.load(.monotonic));
    try testing.expectEqual(@as(i64, 1), keep_stats.misses.load(.monotonic));
}

test "PolicyEngine stats: single policy match gets hit" {
    const allocator = testing.allocator;

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "single-policy"),
        .name = try allocator.dupe(u8, "drop-errors"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    var test_log: TestLogContext = .{ .message = "an error occurred" };
    var policy_id_buf: [16][]const u8 = undefined;
    _ = evalTestLog(&engine, &test_log, &policy_id_buf);

    // Single policy should get a hit via lock-free atomic stats
    const snapshot = registry.getSnapshot().?;
    const stats = snapshot.getStats(0).?;
    try testing.expectEqual(@as(i64, 1), stats.hits.load(.monotonic));
    try testing.expectEqual(@as(i64, 0), stats.misses.load(.monotonic));
}

test "PolicyEngine stats: multiple KEEPs and DROPs - single DROP winner, KEEPs get misses" {
    const allocator = testing.allocator;

    // Two KEEP policies
    var keep_policy1: Policy = .{
        .id = try allocator.dupe(u8, "keep-1"),
        .name = try allocator.dupe(u8, "keep-errors"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "all") } },
    };
    try keep_policy1.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer keep_policy1.deinit(allocator);

    var keep_policy2: Policy = .{
        .id = try allocator.dupe(u8, "keep-2"),
        .name = try allocator.dupe(u8, "keep-critical"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "all") } },
    };
    try keep_policy2.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "critical") },
    });
    defer keep_policy2.deinit(allocator);

    // Two DROP policies
    var drop_policy1: Policy = .{
        .id = try allocator.dupe(u8, "drop-1"),
        .name = try allocator.dupe(u8, "drop-warning"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try drop_policy1.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "warning") },
    });
    defer drop_policy1.deinit(allocator);

    var drop_policy2: Policy = .{
        .id = try allocator.dupe(u8, "drop-2"),
        .name = try allocator.dupe(u8, "drop-debug"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try drop_policy2.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "debug") },
    });
    defer drop_policy2.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{ keep_policy1, keep_policy2, drop_policy1, drop_policy2 }, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    // Log matches all 4 policies (2 KEEP, 2 DROP)
    var test_log: TestLogContext = .{ .message = "critical error with warning and debug info" };
    var policy_id_buf: [16][]const u8 = undefined;
    const result = evalTestLog(&engine, &test_log, &policy_id_buf);

    // DROP wins (most restrictive)
    try testing.expectEqual(FilterDecision.drop, result.decision);

    // All 4 policies should have stats recorded via lock-free atomics
    // After sorting by ID: drop-1(0), drop-2(1), keep-1(2), keep-2(3)
    const snapshot = registry.getSnapshot().?;

    // Single-winner among equally-restrictive DROP policies (index 0,1): one hit, one miss
    const drop1_stats = snapshot.getStats(0).?;
    const drop2_stats = snapshot.getStats(1).?;
    const drop_hits = drop1_stats.hits.load(.monotonic) + drop2_stats.hits.load(.monotonic);
    const drop_misses = drop1_stats.misses.load(.monotonic) + drop2_stats.misses.load(.monotonic);
    try testing.expectEqual(@as(i64, 1), drop_hits);
    try testing.expectEqual(@as(i64, 1), drop_misses);

    // Both KEEP policies (index 2,3) get misses (their decision differs from final decision)
    const keep1_stats = snapshot.getStats(2).?;
    try testing.expectEqual(@as(i64, 0), keep1_stats.hits.load(.monotonic));
    try testing.expectEqual(@as(i64, 1), keep1_stats.misses.load(.monotonic));

    const keep2_stats = snapshot.getStats(3).?;
    try testing.expectEqual(@as(i64, 0), keep2_stats.hits.load(.monotonic));
    try testing.expectEqual(@as(i64, 1), keep2_stats.misses.load(.monotonic));
}

test "PolicyEngine stats: no match records no stats" {
    const allocator = testing.allocator;

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "no-match-policy"),
        .name = try allocator.dupe(u8, "drop-errors"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    // Log doesn't match the policy
    var test_log: TestLogContext = .{ .message = "all good here" };
    var policy_id_buf: [16][]const u8 = undefined;
    _ = evalTestLog(&engine, &test_log, &policy_id_buf);

    // No stats should be recorded - policy should have 0 hits and 0 misses
    const snapshot = registry.getSnapshot().?;
    const stats = snapshot.getStats(0).?;
    try testing.expectEqual(@as(i64, 0), stats.hits.load(.monotonic));
    try testing.expectEqual(@as(i64, 0), stats.misses.load(.monotonic));
}

test "PolicyEngine stats: drop with none + percentage - only none gets hit" {
    const allocator = testing.allocator;

    // keep: none is more restrictive than keep: 1%
    var none_policy: Policy = .{
        .id = try allocator.dupe(u8, "drop-none"),
        .name = try allocator.dupe(u8, "drop-none"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try none_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer none_policy.deinit(allocator);

    // 1% will almost certainly drop (and none already forces drop)
    var pct_policy: Policy = .{
        .id = try allocator.dupe(u8, "sample-pct"),
        .name = try allocator.dupe(u8, "sample-pct"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "1%") } },
    };
    try pct_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer pct_policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{ none_policy, pct_policy }, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    var test_log: TestLogContext = .{ .message = "an error occurred" };
    var policy_id_buf: [16][]const u8 = undefined;
    const result = evalTestLog(&engine, &test_log, &policy_id_buf);

    try testing.expectEqual(FilterDecision.drop, result.decision);

    const snapshot = registry.getSnapshot().?;

    // keep: none (index 0) is most restrictive -> hit
    const none_stats = snapshot.getStats(0).?;
    try testing.expectEqual(@as(i64, 1), none_stats.hits.load(.monotonic));
    try testing.expectEqual(@as(i64, 0), none_stats.misses.load(.monotonic));

    // keep: 1% (index 1) is less restrictive -> miss
    const pct_stats = snapshot.getStats(1).?;
    try testing.expectEqual(@as(i64, 0), pct_stats.hits.load(.monotonic));
    try testing.expectEqual(@as(i64, 1), pct_stats.misses.load(.monotonic));
}

test "PolicyEngine stats: drop with percentage + all - percentage gets hit, all gets miss" {
    const allocator = testing.allocator;

    var all_policy: Policy = .{
        .id = try allocator.dupe(u8, "keep-all"),
        .name = try allocator.dupe(u8, "keep-all"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "all") } },
    };
    try all_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer all_policy.deinit(allocator);

    // 0% always drops
    var pct_policy: Policy = .{
        .id = try allocator.dupe(u8, "sample-pct"),
        .name = try allocator.dupe(u8, "sample-pct"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "0%") } },
    };
    try pct_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer pct_policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{ all_policy, pct_policy }, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    var test_log: TestLogContext = .{ .message = "an error occurred" };
    var policy_id_buf: [16][]const u8 = undefined;
    const result = evalTestLog(&engine, &test_log, &policy_id_buf);

    // 0% drops, so final decision is drop
    try testing.expectEqual(FilterDecision.drop, result.decision);

    const snapshot = registry.getSnapshot().?;

    // keep: all (index 0) is least restrictive -> miss
    const all_stats = snapshot.getStats(0).?;
    try testing.expectEqual(@as(i64, 0), all_stats.hits.load(.monotonic));
    try testing.expectEqual(@as(i64, 1), all_stats.misses.load(.monotonic));

    // keep: 0% (index 1) is most restrictive -> hit
    const pct_stats = snapshot.getStats(1).?;
    try testing.expectEqual(@as(i64, 1), pct_stats.hits.load(.monotonic));
    try testing.expectEqual(@as(i64, 0), pct_stats.misses.load(.monotonic));
}

test "PolicyEngine stats: keep with percentage + all - both get hits" {
    const allocator = testing.allocator;

    var all_policy: Policy = .{
        .id = try allocator.dupe(u8, "keep-all"),
        .name = try allocator.dupe(u8, "keep-all"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "all") } },
    };
    try all_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer all_policy.deinit(allocator);

    // 100% always keeps
    var pct_policy: Policy = .{
        .id = try allocator.dupe(u8, "sample-pct"),
        .name = try allocator.dupe(u8, "sample-pct"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "100%") } },
    };
    try pct_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer pct_policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{ all_policy, pct_policy }, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    var test_log: TestLogContext = .{ .message = "an error occurred" };
    var policy_id_buf: [16][]const u8 = undefined;
    const result = evalTestLog(&engine, &test_log, &policy_id_buf);

    // Both keep, so final decision is keep
    try testing.expectEqual(FilterDecision.keep, result.decision);

    const snapshot = registry.getSnapshot().?;

    // Record kept: all matching policies get hits
    const all_stats = snapshot.getStats(0).?;
    try testing.expectEqual(@as(i64, 1), all_stats.hits.load(.monotonic));
    try testing.expectEqual(@as(i64, 0), all_stats.misses.load(.monotonic));

    const pct_stats = snapshot.getStats(1).?;
    try testing.expectEqual(@as(i64, 1), pct_stats.hits.load(.monotonic));
    try testing.expectEqual(@as(i64, 0), pct_stats.misses.load(.monotonic));
}

// =============================================================================
// Metric Policy Tests
// =============================================================================

const MetricField = proto.policy.MetricField;
const MetricMatcher = proto.policy.MetricMatcher;

/// Test context for metric unit tests - simple struct with known fields
const TestMetricContext = struct {
    name: ?[]const u8 = null,
    description: ?[]const u8 = null,
    unit: ?[]const u8 = null,
    scope_name: ?[]const u8 = null,
    scope_version: ?[]const u8 = null,
    resource_schema_url: ?[]const u8 = null,
    scope_schema_url: ?[]const u8 = null,
    datapoint_attributes: ?std.StringHashMap([]const u8) = null,
    resource_attributes: ?std.StringHashMap([]const u8) = null,

    pub fn fieldAccessor(ctx_ptr: *const anyopaque, field: MetricFieldRef) ?[]const u8 {
        const self: *const TestMetricContext = @ptrCast(@alignCast(ctx_ptr));
        return switch (field) {
            .metric_field => |mf| switch (mf) {
                .METRIC_FIELD_NAME => self.name,
                .METRIC_FIELD_DESCRIPTION => self.description,
                .METRIC_FIELD_UNIT => self.unit,
                .METRIC_FIELD_SCOPE_NAME => self.scope_name,
                .METRIC_FIELD_SCOPE_VERSION => self.scope_version,
                .METRIC_FIELD_RESOURCE_SCHEMA_URL => self.resource_schema_url,
                .METRIC_FIELD_SCOPE_SCHEMA_URL => self.scope_schema_url,
                else => null,
            },
            .datapoint_attribute => |attr_path| {
                const key = if (attr_path.path.items.len > 0) attr_path.path.items[0] else return null;
                if (self.datapoint_attributes) |attrs| {
                    return attrs.get(key);
                }
                return null;
            },
            .resource_attribute => |attr_path| {
                const key = if (attr_path.path.items.len > 0) attr_path.path.items[0] else return null;
                if (self.resource_attributes) |attrs| {
                    return attrs.get(key);
                }
                return null;
            },
            .scope_attribute => null,
            .metric_type => null,
            .aggregation_temporality => null,
        };
    }

    fn typedAccessor(ctx_ptr: *const anyopaque, field: MetricFieldRef) ?TypedValue {
        return .{ .string = fieldAccessor(ctx_ptr, field) orelse return null };
    }

    pub const accessor: MetricAccessor = .{ .typed_value = typedAccessor };
};

fn evalMetric(
    engine: *const PolicyEngine,
    ctx: *TestMetricContext,
    policy_id_buf: [][]const u8,
) PolicyResult {
    return engine.evaluate(.metric, &TestMetricContext.accessor, ctx, policy_id_buf, .{
        .io = std.Options.debug_io,
    });
}

test "MetricPolicyEngine: empty registry returns unset" {
    const allocator = testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    var test_metric: TestMetricContext = .{ .name = "http_requests_total" };
    var policy_id_buf: [16][]const u8 = undefined;

    const result = evalMetric(&engine, &test_metric, &policy_id_buf);

    try testing.expectEqual(FilterDecision.unset, result.decision);
    try testing.expectEqual(@as(usize, 0), result.matched_policy_ids.len);
}

test "MetricPolicyEngine: single policy drop match" {
    const allocator = testing.allocator;

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "metric-policy-1"),
        .name = try allocator.dupe(u8, "drop-debug-metrics"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    try policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "debug_.*") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    // Verify the registry has the policy
    const snapshot = registry.getSnapshot().?;
    try testing.expectEqual(@as(usize, 1), snapshot.policies.len);

    // Verify the metric index has the matcher key
    const index = &snapshot.metric_index;
    try testing.expect(!index.isEmpty());
    try testing.expectEqual(@as(usize, 1), index.getDatabaseCount());

    // Verify we can get the database for the metric key
    const db = index.getDatabase(.{ .field = .{ .metric_field = .METRIC_FIELD_NAME } });
    try testing.expect(db != null);

    // Test that scanning works directly
    var result_buf: [256]u32 = undefined;
    const scan_result = db.?.scanPositive("debug_memory_usage", &result_buf);
    try testing.expect(scan_result.count > 0); // Pattern should match

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Matching metric should be dropped
    var debug_metric: TestMetricContext = .{ .name = "debug_memory_usage" };
    const result = evalMetric(&engine, &debug_metric, &policy_id_buf);
    try testing.expectEqual(FilterDecision.drop, result.decision);

    // Non-matching metric should pass
    var normal_metric: TestMetricContext = .{ .name = "http_requests_total" };
    const result2 = evalMetric(&engine, &normal_metric, &policy_id_buf);
    try testing.expectEqual(FilterDecision.unset, result2.decision);
}

test "MetricPolicyEngine: single policy keep match returns policy ID" {
    const allocator = testing.allocator;

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "metric-policy-keep"),
        .name = try allocator.dupe(u8, "keep-important-metrics"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = true,
        } },
    };
    try policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "http_.*") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    var test_metric: TestMetricContext = .{ .name = "http_requests_total" };
    var policy_id_buf: [16][]const u8 = undefined;

    const result = evalMetric(&engine, &test_metric, &policy_id_buf);

    try testing.expectEqual(FilterDecision.keep, result.decision);
    try testing.expectEqual(@as(usize, 1), result.matched_policy_ids.len);
    try testing.expectEqualStrings("metric-policy-keep", result.matched_policy_ids[0]);
}

test "MetricPolicyEngine: multiple matchers AND logic" {
    const allocator = testing.allocator;

    // Policy requires BOTH metric name AND unit to match
    // Use anchored regex patterns to ensure exact matching
    var policy: Policy = .{
        .id = try allocator.dupe(u8, "metric-policy-and"),
        .name = try allocator.dupe(u8, "drop-slow-requests"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    try policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "^request_duration$") },
    });
    try policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_UNIT },
        .match = .{ .regex = try allocator.dupe(u8, "^seconds$") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Both match - should drop
    var both_match: TestMetricContext = .{ .name = "request_duration", .unit = "seconds" };
    const result1 = evalMetric(&engine, &both_match, &policy_id_buf);
    try testing.expectEqual(FilterDecision.drop, result1.decision);

    // Only name matches - should pass (unit "milliseconds" doesn't match "^seconds$")
    var name_only: TestMetricContext = .{ .name = "request_duration", .unit = "milliseconds" };
    const result2 = evalMetric(&engine, &name_only, &policy_id_buf);
    try testing.expectEqual(FilterDecision.unset, result2.decision);

    // Only unit matches - should pass (name "response_size" doesn't match "^request_duration$")
    var unit_only: TestMetricContext = .{ .name = "response_size", .unit = "seconds" };
    const result3 = evalMetric(&engine, &unit_only, &policy_id_buf);
    try testing.expectEqual(FilterDecision.unset, result3.decision);
}

test "MetricPolicyEngine: negated matcher" {
    const allocator = testing.allocator;

    // Keep metrics that do NOT have "internal" in the name
    var policy: Policy = .{
        .id = try allocator.dupe(u8, "metric-policy-negate"),
        .name = try allocator.dupe(u8, "drop-internal-metrics"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    try policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "internal_.*") },
        .negate = true,
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Internal metric matches pattern, negation fails -> policy doesn't match -> passes
    var internal_metric: TestMetricContext = .{ .name = "internal_queue_size" };
    const result1 = evalMetric(&engine, &internal_metric, &policy_id_buf);
    try testing.expectEqual(FilterDecision.unset, result1.decision);

    // Non-internal metric doesn't match pattern, negation succeeds -> policy matches -> drops
    var public_metric: TestMetricContext = .{ .name = "http_requests_total" };
    const result2 = evalMetric(&engine, &public_metric, &policy_id_buf);
    try testing.expectEqual(FilterDecision.drop, result2.decision);
}

test "MetricPolicyEngine: datapoint attribute matching" {
    const allocator = testing.allocator;

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "metric-policy-dp-attr"),
        .name = try allocator.dupe(u8, "drop-error-status"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    try policy.target.?.metric.match.append(allocator, .{
        .field = .{ .datapoint_attribute = try testMakeAttrPath(allocator, "status_code") },
        .match = .{ .regex = try allocator.dupe(u8, "5[0-9][0-9]") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Metric with 500 status should be dropped
    var dp_attrs = std.StringHashMap([]const u8).init(allocator);
    defer dp_attrs.deinit();
    try dp_attrs.put("status_code", "503");

    var error_metric: TestMetricContext = .{
        .name = "http_response",
        .datapoint_attributes = dp_attrs,
    };
    const result1 = evalMetric(&engine, &error_metric, &policy_id_buf);
    try testing.expectEqual(FilterDecision.drop, result1.decision);

    // Metric with 200 status should pass
    var ok_attrs = std.StringHashMap([]const u8).init(allocator);
    defer ok_attrs.deinit();
    try ok_attrs.put("status_code", "200");

    var ok_metric: TestMetricContext = .{
        .name = "http_response",
        .datapoint_attributes = ok_attrs,
    };
    const result2 = evalMetric(&engine, &ok_metric, &policy_id_buf);
    try testing.expectEqual(FilterDecision.unset, result2.decision);
}

test "MetricPolicyEngine: resource attribute matching" {
    const allocator = testing.allocator;

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "metric-policy-res-attr"),
        .name = try allocator.dupe(u8, "drop-test-env"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    try policy.target.?.metric.match.append(allocator, .{
        .field = .{ .resource_attribute = try testMakeAttrPath(allocator, "deployment.environment") },
        .match = .{ .regex = try allocator.dupe(u8, "test|staging") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Metric from test environment should be dropped
    var test_attrs = std.StringHashMap([]const u8).init(allocator);
    defer test_attrs.deinit();
    try test_attrs.put("deployment.environment", "test");

    var test_metric: TestMetricContext = .{
        .name = "http_requests_total",
        .resource_attributes = test_attrs,
    };
    const result1 = evalMetric(&engine, &test_metric, &policy_id_buf);
    try testing.expectEqual(FilterDecision.drop, result1.decision);

    // Metric from production environment should pass
    var prod_attrs = std.StringHashMap([]const u8).init(allocator);
    defer prod_attrs.deinit();
    try prod_attrs.put("deployment.environment", "production");

    var prod_metric: TestMetricContext = .{
        .name = "http_requests_total",
        .resource_attributes = prod_attrs,
    };
    const result2 = evalMetric(&engine, &prod_metric, &policy_id_buf);
    try testing.expectEqual(FilterDecision.unset, result2.decision);
}

test "MetricPolicyEngine: log policies don't affect metrics" {
    const allocator = testing.allocator;

    // Create a log policy that would match if applied to metrics
    var log_policy: Policy = .{
        .id = try allocator.dupe(u8, "log-policy-only"),
        .name = try allocator.dupe(u8, "drop-error-logs"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try log_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer log_policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{log_policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Metric evaluation should not be affected by log policies
    var test_metric: TestMetricContext = .{ .name = "error_count" };
    const result = evalMetric(&engine, &test_metric, &policy_id_buf);

    try testing.expectEqual(FilterDecision.unset, result.decision);
    try testing.expectEqual(@as(usize, 0), result.matched_policy_ids.len);
}

test "MetricPolicyEngine: metric policies don't affect logs" {
    const allocator = testing.allocator;

    // Create a metric policy
    var metric_policy: Policy = .{
        .id = try allocator.dupe(u8, "metric-policy-only"),
        .name = try allocator.dupe(u8, "drop-debug-metrics"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    try metric_policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "debug_.*") },
    });
    defer metric_policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{metric_policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Log evaluation should not be affected by metric policies
    var test_log: TestLogContext = .{ .message = "debug_info: something happened" };
    const result = evalTestLog(&engine, &test_log, &policy_id_buf);

    try testing.expectEqual(FilterDecision.unset, result.decision);
    try testing.expectEqual(@as(usize, 0), result.matched_policy_ids.len);
}

test "MetricPolicyEngine: most restrictive wins - drop beats keep" {
    const allocator = testing.allocator;

    // Keep policy for all http metrics
    var keep_policy: Policy = .{
        .id = try allocator.dupe(u8, "metric-keep-http"),
        .name = try allocator.dupe(u8, "keep-http-metrics"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = true,
        } },
    };
    try keep_policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "http_.*") },
    });
    defer keep_policy.deinit(allocator);

    // Drop policy for error metrics
    var drop_policy: Policy = .{
        .id = try allocator.dupe(u8, "metric-drop-errors"),
        .name = try allocator.dupe(u8, "drop-error-metrics"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    try drop_policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "http_errors") },
    });
    defer drop_policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{ keep_policy, drop_policy }, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // http_errors matches both policies - drop should win
    var error_metric: TestMetricContext = .{ .name = "http_errors" };
    const result1 = evalMetric(&engine, &error_metric, &policy_id_buf);
    try testing.expectEqual(FilterDecision.drop, result1.decision);

    // http_requests matches only keep policy
    var requests_metric: TestMetricContext = .{ .name = "http_requests_total" };
    const result2 = evalMetric(&engine, &requests_metric, &policy_id_buf);
    try testing.expectEqual(FilterDecision.keep, result2.decision);
}

test "MetricPolicyEngine: disabled policies are skipped" {
    const allocator = testing.allocator;

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "metric-policy-disabled"),
        .name = try allocator.dupe(u8, "disabled-drop-policy"),
        .enabled = false, // Disabled!
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    try policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, ".+") }, // Match any non-empty name
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Even though the pattern matches, the disabled policy should be skipped
    var test_metric: TestMetricContext = .{ .name = "any_metric_name" };
    const result = evalMetric(&engine, &test_metric, &policy_id_buf);

    try testing.expectEqual(FilterDecision.unset, result.decision);
}

test "MetricPolicyEngine: mixed log and metric policies" {
    const allocator = testing.allocator;

    // Metric drop policy
    var metric_policy: Policy = .{
        .id = try allocator.dupe(u8, "metric-drop"),
        .name = try allocator.dupe(u8, "drop-debug-metrics"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    try metric_policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "debug_.*") },
    });
    defer metric_policy.deinit(allocator);

    // Log drop policy
    var log_policy: Policy = .{
        .id = try allocator.dupe(u8, "log-drop"),
        .name = try allocator.dupe(u8, "drop-debug-logs"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try log_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "DEBUG:.*") },
    });
    defer log_policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{ metric_policy, log_policy }, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Debug metric should be dropped by metric policy
    var debug_metric: TestMetricContext = .{ .name = "debug_memory" };
    const result1 = evalMetric(&engine, &debug_metric, &policy_id_buf);
    try testing.expectEqual(FilterDecision.drop, result1.decision);

    // Debug log should be dropped by log policy
    var debug_log: TestLogContext = .{ .message = "DEBUG: test message" };
    const result2 = evalTestLog(&engine, &debug_log, &policy_id_buf);
    try testing.expectEqual(FilterDecision.drop, result2.decision);

    // Non-debug metric should pass
    var normal_metric: TestMetricContext = .{ .name = "http_requests" };
    const result3 = evalMetric(&engine, &normal_metric, &policy_id_buf);
    try testing.expectEqual(FilterDecision.unset, result3.decision);

    // Non-debug log should pass
    var normal_log: TestLogContext = .{ .message = "INFO: test message" };
    const result4 = evalTestLog(&engine, &normal_log, &policy_id_buf);
    try testing.expectEqual(FilterDecision.unset, result4.decision);
}

test "MetricPolicyEngine: regex pattern matching" {
    const allocator = testing.allocator;

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "metric-regex"),
        .name = try allocator.dupe(u8, "drop-by-regex"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    // Match any metric starting with "internal_" or ending with "_debug"
    try policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "(^internal_|_debug$)") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Matches: starts with internal_
    var m1: TestMetricContext = .{ .name = "internal_queue_size" };
    try testing.expectEqual(FilterDecision.drop, evalMetric(&engine, &m1, &policy_id_buf).decision);

    // Matches: ends with _debug
    var m2: TestMetricContext = .{ .name = "http_latency_debug" };
    try testing.expectEqual(FilterDecision.drop, evalMetric(&engine, &m2, &policy_id_buf).decision);

    // Does not match
    var m3: TestMetricContext = .{ .name = "http_requests_total" };
    try testing.expectEqual(FilterDecision.unset, evalMetric(&engine, &m3, &policy_id_buf).decision);
}

test "MetricPolicyEngine: stats recording for matched policies" {
    const allocator = testing.allocator;

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "metric-stats-test"),
        .name = try allocator.dupe(u8, "drop-test-metrics"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    try policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "test_.*") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Matching metric - should record stats
    var test_metric: TestMetricContext = .{ .name = "test_counter" };
    const result = evalMetric(&engine, &test_metric, &policy_id_buf);
    try testing.expectEqual(FilterDecision.drop, result.decision);

    // Verify stats were recorded via lock-free atomics
    const snapshot = registry.getSnapshot().?;
    const stats = snapshot.getStats(0).?;
    try testing.expectEqual(@as(i64, 1), stats.hits.load(.monotonic));
    try testing.expectEqual(@as(i64, 0), stats.misses.load(.monotonic));
}

// =============================================================================
// Sampling and Rate Limiting Tests
// =============================================================================

test "PolicyEngine: percentage sampling - 0% drops all" {
    const allocator = testing.allocator;

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "sample-0-percent"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "0%"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "test") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // 0% sampling should drop all matching logs
    var test_log: TestLogContext = .{ .message = "test message" };
    const result = evalTestLog(&engine, &test_log, &policy_id_buf);
    try testing.expectEqual(FilterDecision.drop, result.decision);
}

test "PolicyEngine: percentage sampling - 100% keeps all" {
    const allocator = testing.allocator;

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "sample-100-percent"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "100%"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "test") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // 100% sampling should keep all matching logs
    var test_log: TestLogContext = .{ .message = "test message" };
    const result = evalTestLog(&engine, &test_log, &policy_id_buf);
    try testing.expectEqual(FilterDecision.keep, result.decision);
}

// Note: deterministic percentage sampling requires a sample_key (see the
// "sample_key provides deterministic sampling" test). Without one, the spec
// (v1.6.0) requires an independent random decision per record — covered by
// "percentage sampling without sample_key is independent random".

test "PolicyEngine: rate limiting - respects limit" {
    const allocator = testing.allocator;

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "rate-limit-5-per-second"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "5/s"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "test") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // First 5 should be kept
    var kept_count: u32 = 0;
    for (0..10) |_| {
        var test_log: TestLogContext = .{ .message = "test message" };
        const result = evalTestLog(&engine, &test_log, &policy_id_buf);
        if (result.decision == .keep) {
            kept_count += 1;
        }
    }

    // Should keep exactly 5 (rate limit)
    try testing.expectEqual(@as(u32, 5), kept_count);
}

test "PolicyEngine: rate limiting per minute" {
    const allocator = testing.allocator;

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "rate-limit-3-per-minute"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "3/m"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "test") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // First 3 should be kept
    var kept_count: u32 = 0;
    for (0..10) |_| {
        var test_log: TestLogContext = .{ .message = "test message" };
        const result = evalTestLog(&engine, &test_log, &policy_id_buf);
        if (result.decision == .keep) {
            kept_count += 1;
        }
    }

    // Should keep exactly 3 (rate limit per minute)
    try testing.expectEqual(@as(u32, 3), kept_count);
}

test "PolicyEngine: rate limiting with zero limit drops all" {
    const allocator = testing.allocator;

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "rate-limit-0"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "0/s"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "test") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // 0/s rate limit should drop all
    var test_log: TestLogContext = .{ .message = "test message" };
    const result = evalTestLog(&engine, &test_log, &policy_id_buf);
    try testing.expectEqual(FilterDecision.drop, result.decision);
}

test "PolicyEngine: sampling does not affect non-matching logs" {
    const allocator = testing.allocator;

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "sample-policy"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "50%"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "specific_pattern") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Non-matching log should return unset (not affected by sampling)
    var test_log: TestLogContext = .{ .message = "different message" };
    const result = evalTestLog(&engine, &test_log, &policy_id_buf);
    try testing.expectEqual(FilterDecision.unset, result.decision);
}

test "PolicyEngine: more matching policies than policy_id_buf capacity" {
    // When more policies match than fit in policy_id_buf, the engine should:
    // 1. Still compute the correct final decision (including from policies beyond buffer)
    // 2. Only return as many policy IDs as fit in the buffer
    // 3. Not crash or have undefined behavior
    const allocator = testing.allocator;

    // Create 5 KEEP policies that all match, but we'll only provide a buffer for 2
    var policies: [5]Policy = undefined;
    for (&policies, 0..) |*p, i| {
        var id_buf: [16]u8 = undefined;
        const id = std.fmt.bufPrint(&id_buf, "policy-{d}", .{i}) catch unreachable;

        p.* = Policy{
            .id = try allocator.dupe(u8, id),
            .name = try allocator.dupe(u8, id),
            .enabled = true,
            .target = .{ .log = .{
                .keep = try allocator.dupe(u8, "all"),
            } },
        };
        // All policies match on "test" in body
        try p.target.?.log.match.append(allocator, .{
            .field = .{ .log_field = .LOG_FIELD_BODY },
            .match = .{ .regex = try allocator.dupe(u8, "test") },
        });
    }
    defer for (&policies) |*p| p.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&policies, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    // Buffer only fits 2 policy IDs, but 5 policies will match
    var small_policy_id_buf: [2][]const u8 = undefined;

    var test_log: TestLogContext = .{ .message = "test message" };
    const result = evalTestLog(&engine, &test_log, &small_policy_id_buf);

    // Decision should be KEEP (all 5 policies want to keep)
    try testing.expectEqual(FilterDecision.keep, result.decision);

    // Only 2 policy IDs returned (buffer capacity), even though 5 matched
    try testing.expectEqual(@as(usize, 2), result.matched_policy_ids.len);
}

test "PolicyEngine: exists=false matches when field is missing or empty" {
    const allocator = testing.allocator;

    // Drop logs where trace_id does NOT exist (exists: false)
    var policy: Policy = .{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-missing-trace"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_attribute = try testMakeAttrPath(allocator, "trace_id") },
        .match = .{ .exists = false },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // No trace_id attribute = field missing = exists:false matches = dropped
    var no_trace: TestLogContext = .{ .message = "log without trace" };
    try testing.expectEqual(FilterDecision.drop, evalTestLog(&engine, &no_trace, &policy_id_buf).decision);

    // Has trace_id = field exists = exists:false does NOT match = unset
    var with_trace: TestLogContext = .{ .message = "log with trace", .trace_id = "abc123" };
    try testing.expectEqual(FilterDecision.unset, evalTestLog(&engine, &with_trace, &policy_id_buf).decision);
}

test "PolicyEngine: exists=false with negate=true matches when field exists" {
    const allocator = testing.allocator;

    // Drop logs where trace_id DOES exist (exists: false + negate: true = double negation)
    var policy: Policy = .{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-with-trace"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_attribute = try testMakeAttrPath(allocator, "trace_id") },
        .match = .{ .exists = false },
        .negate = true,
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Has trace_id = field exists = exists:false+negate:true matches = dropped
    var with_trace: TestLogContext = .{ .message = "log with trace", .trace_id = "abc123" };
    try testing.expectEqual(FilterDecision.drop, evalTestLog(&engine, &with_trace, &policy_id_buf).decision);

    // No trace_id = field missing = exists:false+negate:true does NOT match = unset
    var no_trace: TestLogContext = .{ .message = "log without trace" };
    try testing.expectEqual(FilterDecision.unset, evalTestLog(&engine, &no_trace, &policy_id_buf).decision);
}

test "PolicyEngine: sample_key provides deterministic sampling" {
    const allocator = testing.allocator;

    // Policy with 50% sampling using trace_id as sample_key
    var policy: Policy = .{
        .id = try allocator.dupe(u8, "sample-policy"),
        .name = try allocator.dupe(u8, "sample-by-trace"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "50%"),
            .sample_key = .{ .field = .{ .log_attribute = try testMakeAttrPath(allocator, "trace_id") } },
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "^.*") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Same trace_id should always get the same decision
    var log1: TestLogContext = .{ .message = "log one", .trace_id = "trace-abc-123" };
    const decision1 = evalTestLog(&engine, &log1, &policy_id_buf).decision;

    var log2: TestLogContext = .{ .message = "log two", .trace_id = "trace-abc-123" };
    const decision2 = evalTestLog(&engine, &log2, &policy_id_buf).decision;

    var log3: TestLogContext = .{ .message = "log three", .trace_id = "trace-abc-123" };
    const decision3 = evalTestLog(&engine, &log3, &policy_id_buf).decision;

    // All logs with same trace_id get same decision
    try testing.expectEqual(decision1, decision2);
    try testing.expectEqual(decision2, decision3);

    // Different trace_id may get different decision (though not guaranteed with only 2 values)
    // But the decision for each trace_id is consistent
    var log4: TestLogContext = .{ .message = "log four", .trace_id = "trace-xyz-789" };
    const decision4a = evalTestLog(&engine, &log4, &policy_id_buf).decision;
    const decision4b = evalTestLog(&engine, &log4, &policy_id_buf).decision;
    try testing.expectEqual(decision4a, decision4b);
}

test "PolicyEngine: sample_key with log_field" {
    const allocator = testing.allocator;

    // Policy with 50% sampling using body as sample_key
    var policy: Policy = .{
        .id = try allocator.dupe(u8, "sample-by-body"),
        .name = try allocator.dupe(u8, "sample-by-body"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "50%"),
            .sample_key = .{ .field = .{ .log_field = .LOG_FIELD_BODY } },
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "^.*") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Same message body should always get the same decision
    var log1: TestLogContext = .{ .message = "exact same message" };
    const decision1 = evalTestLog(&engine, &log1, &policy_id_buf).decision;

    var log2: TestLogContext = .{ .message = "exact same message" };
    const decision2 = evalTestLog(&engine, &log2, &policy_id_buf).decision;

    try testing.expectEqual(decision1, decision2);
}

test "PolicyEngine: sample_key missing field falls back to default" {
    const allocator = testing.allocator;

    // Policy with sample_key pointing to a field that doesn't exist
    var policy: Policy = .{
        .id = try allocator.dupe(u8, "sample-missing-key"),
        .name = try allocator.dupe(u8, "sample-missing-key"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "50%"),
            .sample_key = .{ .field = .{ .log_attribute = try testMakeAttrPath(allocator, "nonexistent_field") } },
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "^.*") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Missing key value falls back to the independent random default
    var log1: TestLogContext = .{ .message = "test message" };
    const result = evalTestLog(&engine, &log1, &policy_id_buf);

    // Should get a decision (either keep or drop, randomly)
    try testing.expect(result.decision == .keep or result.decision == .drop);
}

test "PolicyEngine: percentage sampling without sample_key is independent random (v1.6.0)" {
    const allocator = testing.allocator;

    // 50% log sampling with no sample_key: each record must get an
    // independent random decision — previously this failed closed and
    // dropped everything.
    var policy: Policy = .{
        .id = try allocator.dupe(u8, "sample-unkeyed"),
        .name = try allocator.dupe(u8, "sample-unkeyed"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "50%"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "^.*") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    var kept: u32 = 0;
    const total: u32 = 2000;
    for (0..total) |_| {
        var log: TestLogContext = .{ .message = "same message every time" };
        if (evalTestLog(&engine, &log, &policy_id_buf).decision == .keep) kept += 1;
    }

    // Identical records must not all get the same decision, and the split
    // should be roughly 50% (wide bounds keep this test deterministic enough).
    const ratio = @as(f64, @floatFromInt(kept)) / @as(f64, @floatFromInt(total));
    try testing.expect(ratio > 0.4 and ratio < 0.6);
}

test "PolicyEngine: log resource_schema_url matching" {
    const allocator = testing.allocator;

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "drop-old-schema"),
        .name = try allocator.dupe(u8, "Drop old schema logs"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_RESOURCE_SCHEMA_URL },
        .match = .{ .exact = try allocator.dupe(u8, "https://old.schema/v1") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    var old_log: TestLogContext = .{ .message = "test", .resource_schema_url = "https://old.schema/v1" };
    const result = evalTestLog(&engine, &old_log, &policy_id_buf);
    try testing.expectEqual(FilterDecision.drop, result.decision);

    var new_log: TestLogContext = .{ .message = "test", .resource_schema_url = "https://new.schema/v2" };
    const result2 = evalTestLog(&engine, &new_log, &policy_id_buf);
    try testing.expectEqual(FilterDecision.unset, result2.decision);
}

test "PolicyEngine: log scope_schema_url matching" {
    const allocator = testing.allocator;

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "drop-scope-schema"),
        .name = try allocator.dupe(u8, "Drop scope schema logs"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_SCOPE_SCHEMA_URL },
        .match = .{ .exact = try allocator.dupe(u8, "https://scope.schema/v1") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    var match_log: TestLogContext = .{ .message = "test", .scope_schema_url = "https://scope.schema/v1" };
    const result = evalTestLog(&engine, &match_log, &policy_id_buf);
    try testing.expectEqual(FilterDecision.drop, result.decision);

    var no_match_log: TestLogContext = .{ .message = "test", .scope_schema_url = "https://other.schema/v2" };
    const result2 = evalTestLog(&engine, &no_match_log, &policy_id_buf);
    try testing.expectEqual(FilterDecision.unset, result2.decision);
}

test "MetricPolicyEngine: resource_schema_url matching" {
    const allocator = testing.allocator;

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "drop-old-metric-schema"),
        .name = try allocator.dupe(u8, "Drop old schema metrics"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    try policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_RESOURCE_SCHEMA_URL },
        .match = .{ .exact = try allocator.dupe(u8, "https://old.schema/v1") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    var old_metric: TestMetricContext = .{ .name = "cpu", .resource_schema_url = "https://old.schema/v1" };
    const result = evalMetric(&engine, &old_metric, &policy_id_buf);
    try testing.expectEqual(FilterDecision.drop, result.decision);

    var new_metric: TestMetricContext = .{ .name = "cpu", .resource_schema_url = "https://new.schema/v2" };
    const result2 = evalMetric(&engine, &new_metric, &policy_id_buf);
    try testing.expectEqual(FilterDecision.unset, result2.decision);
}

test "MetricPolicyEngine: scope_schema_url matching" {
    const allocator = testing.allocator;

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "drop-scope-schema-metric"),
        .name = try allocator.dupe(u8, "Drop scope schema metrics"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    try policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_SCOPE_SCHEMA_URL },
        .match = .{ .exact = try allocator.dupe(u8, "https://scope.schema/v1") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    var match_metric: TestMetricContext = .{ .name = "cpu", .scope_schema_url = "https://scope.schema/v1" };
    const result = evalMetric(&engine, &match_metric, &policy_id_buf);
    try testing.expectEqual(FilterDecision.drop, result.decision);

    var no_match: TestMetricContext = .{ .name = "cpu", .scope_schema_url = "https://other/v2" };
    const result2 = evalMetric(&engine, &no_match, &policy_id_buf);
    try testing.expectEqual(FilterDecision.unset, result2.decision);
}

test "MetricPolicyEngine: scope_version matching" {
    const allocator = testing.allocator;

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "drop-old-scope-version"),
        .name = try allocator.dupe(u8, "Drop old scope version metrics"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    try policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_SCOPE_VERSION },
        .match = .{ .exact = try allocator.dupe(u8, "1.0.0") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    var old_metric: TestMetricContext = .{ .name = "cpu", .scope_version = "1.0.0" };
    const result = evalMetric(&engine, &old_metric, &policy_id_buf);
    try testing.expectEqual(FilterDecision.drop, result.decision);

    var new_metric: TestMetricContext = .{ .name = "cpu", .scope_version = "2.0.0" };
    const result2 = evalMetric(&engine, &new_metric, &policy_id_buf);
    try testing.expectEqual(FilterDecision.unset, result2.decision);
}

// =============================================================================
// Trace Sampling Tests
// =============================================================================

/// Test context for trace policy evaluation tests
const TestTraceContext = struct {
    name: ?[]const u8 = null,
    /// Raw bytes (16) or null. The `typed_value` accessor returns this as
    /// `TypedValue.bytes` so the sampler gets raw bytes directly.
    trace_id: ?[]const u8 = null,
    span_id: ?[]const u8 = null,
    trace_state: ?[]const u8 = null,

    /// Last value written via the mutator (captured for test assertions)
    last_mutate_field: ?TraceField = null,
    last_mutate_value: ?[]const u8 = null,
    mutate_count: usize = 0,

    pub fn typedFieldAccessor(ctx_ptr: *const anyopaque, field: TraceFieldRef) ?TypedValue {
        const self: *const TestTraceContext = @ptrCast(@alignCast(ctx_ptr));
        return switch (field) {
            .trace_field => |tf| switch (tf) {
                .TRACE_FIELD_NAME => .{ .string = self.name orelse return null },
                .TRACE_FIELD_SPAN_ID => .{ .string = self.span_id orelse return null },
                .TRACE_FIELD_TRACE_STATE => .{ .string = self.trace_state orelse return null },
                // trace_id is raw bytes: the engine hex-renders it for string
                // matchers and hands the raw bytes to the sampler.
                .TRACE_FIELD_TRACE_ID => .{ .bytes = self.trace_id orelse return null },
                else => null,
            },
            else => null,
        };
    }

    pub fn accessorSet(ctx_ptr: *anyopaque, field: TraceFieldRef, value: []const u8) void {
        const self: *TestTraceContext = @ptrCast(@alignCast(ctx_ptr));
        switch (field) {
            .trace_field => |tf| {
                self.last_mutate_field = tf;
            },
            else => {},
        }
        self.last_mutate_value = value;
        self.mutate_count += 1;
    }

    pub const accessor: TraceAccessor = .{
        .typed_value = typedFieldAccessor,
        .set = accessorSet,
    };
};

fn evalTrace(
    engine: *const PolicyEngine,
    ctx: *TestTraceContext,
    policy_id_buf: [][]const u8,
) PolicyResult {
    return engine.evaluate(.trace, &TestTraceContext.accessor, ctx, policy_id_buf, .{
        .io = std.Options.debug_io,
    });
}

test "PolicyEngine: trace sampling writes threshold via mutator" {
    const allocator = testing.allocator;

    // Create a trace policy with 50% sampling
    var policy: Policy = .{
        .id = try allocator.dupe(u8, "trace-sample-50"),
        .name = try allocator.dupe(u8, "sample-50"),
        .enabled = true,
        .target = .{ .trace = .{
            .keep = .{ .percentage = 50.0 },
        } },
    };
    try policy.target.?.trace.match.append(allocator, .{
        .field = .{ .trace_field = .TRACE_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, ".+") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Use a trace ID whose last 7 bytes produce R >= threshold (will be kept)
    // 50% threshold = 2^55 = 0x80000000000000
    // We need R >= 0x80000000000000, so last 7 bytes should be >= 0x80000000000000
    // Use 0xFF bytes for the last 7 bytes to guarantee keep
    var ctx: TestTraceContext = .{
        .name = "test-span",
        .trace_id = &[16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    };

    const result = evalTrace(&engine, &ctx, &policy_id_buf);
    try testing.expectEqual(FilterDecision.keep, result.decision);
    try testing.expect(result.was_transformed);
    try testing.expectEqual(@as(usize, 1), ctx.mutate_count);
    try testing.expectEqual(TraceField.TRACE_FIELD_TRACE_STATE, ctx.last_mutate_field.?);
    // The threshold value should be non-null (the hex encoding of the 50% threshold)
    try testing.expect(ctx.last_mutate_value != null);
}

test "PolicyEngine: trace sampling drop does not write threshold" {
    const allocator = testing.allocator;

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "trace-sample-50"),
        .name = try allocator.dupe(u8, "sample-50"),
        .enabled = true,
        .target = .{ .trace = .{
            .keep = .{ .percentage = 50.0 },
        } },
    };
    try policy.target.?.trace.match.append(allocator, .{
        .field = .{ .trace_field = .TRACE_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, ".+") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Use a trace ID whose last 7 bytes produce R < threshold (will be dropped)
    // 50% threshold = 2^55 = 0x80000000000000
    // Last 7 bytes = all zeros → R = 0 < threshold → drop
    var ctx: TestTraceContext = .{
        .name = "test-span",
        .trace_id = &[16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    };

    const result = evalTrace(&engine, &ctx, &policy_id_buf);
    try testing.expectEqual(FilterDecision.drop, result.decision);
    try testing.expectEqual(@as(usize, 0), ctx.mutate_count);
}

// Context whose `typed_value(trace_id)` returns the raw 16 bytes (the
// canonical in-memory form for both wire paths). Exercises the engine's hex
// rendering of identifier bytes before string matching.
const TestHexTraceContext = struct {
    trace_id: ?[]const u8 = null,

    pub fn typedFieldAccessor(ctx_ptr: *const anyopaque, field: TraceFieldRef) ?TypedValue {
        const self: *const TestHexTraceContext = @ptrCast(@alignCast(ctx_ptr));
        return switch (field) {
            .trace_field => |tf| switch (tf) {
                .TRACE_FIELD_TRACE_ID => .{ .bytes = self.trace_id orelse return null },
                else => null,
            },
            else => null,
        };
    }

    pub fn noopSet(_: *anyopaque, _: TraceFieldRef, _: []const u8) void {}

    pub const accessor: TraceAccessor = .{ .typed_value = typedFieldAccessor, .set = noopSet };
};

test "PolicyEngine: string matcher on trace_id renders raw bytes as hex" {
    const allocator = testing.allocator;

    // 16 raw bytes; the lowercase-hex form is the literal a policy author writes.
    const raw_id = [16]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
    const hex_id = "aabbccdd000102030405060708090a0b";

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "trace-id-exact"),
        .name = try allocator.dupe(u8, "id-exact"),
        .enabled = true,
        .target = .{ .trace = .{
            .keep = .{ .percentage = 100.0 },
        } },
    };
    try policy.target.?.trace.match.append(allocator, .{
        .field = .{ .trace_field = .TRACE_FIELD_TRACE_ID },
        .match = .{ .exact = try allocator.dupe(u8, hex_id) },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Matching raw bytes → hex render matches the literal → policy fires.
    var hit: TestHexTraceContext = .{ .trace_id = &raw_id };
    const r_hit = engine.evaluate(.trace, &TestHexTraceContext.accessor, &hit, &policy_id_buf, .{
        .io = std.Options.debug_io,
    });
    try testing.expectEqual(@as(usize, 1), r_hit.matched_policy_ids.len);

    // Different bytes → different hex → no match.
    const other_id = [16]u8{ 0x11, 0x22, 0x33, 0x44, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
    var miss: TestHexTraceContext = .{ .trace_id = &other_id };
    const r_miss = engine.evaluate(.trace, &TestHexTraceContext.accessor, &miss, &policy_id_buf, .{
        .io = std.Options.debug_io,
    });
    try testing.expectEqual(@as(usize, 0), r_miss.matched_policy_ids.len);
}

// The previous "trace sampling without mutator" test exercised an opt-out
// of tracestate writeback by passing null `field_mutator`. The new model
// derives writeback capability from the accessor itself: a consumer that
// doesn't want writeback simply doesn't wire `TraceAccessor.set`, and any
// trace policy with a sampler is rejected at snapshot-compile time.

test "PolicyEngine: trace proportional sampling reads incoming tracestate" {
    const allocator = testing.allocator;

    // Create a trace policy with 50% proportional sampling
    var policy: Policy = .{
        .id = try allocator.dupe(u8, "trace-proportional"),
        .name = try allocator.dupe(u8, "proportional-50"),
        .enabled = true,
        .target = .{ .trace = .{
            .keep = .{
                .percentage = 50.0,
                .mode = .SAMPLING_MODE_PROPORTIONAL,
            },
        } },
    };
    try policy.target.?.trace.match.append(allocator, .{
        .field = .{ .trace_field = .TRACE_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, ".+") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Incoming tracestate with 50% threshold (th:8) means already sampled at 50%.
    // Proportional 50% of 50% = 25% effective.
    // Product threshold = rejection_threshold(0.25) = (1-0.25)*2^56 = 0xC0000000000000
    // R = 0xFFFFFFFFFFFFFF (max) → R >= product threshold → keep
    var ctx: TestTraceContext = .{
        .name = "test-span",
        .trace_id = &[16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
        .trace_state = "ot=th:8",
    };

    const result = evalTrace(&engine, &ctx, &policy_id_buf);
    try testing.expectEqual(FilterDecision.keep, result.decision);
    try testing.expect(result.was_transformed);
    try testing.expectEqual(@as(usize, 1), ctx.mutate_count);
    // The written threshold should reflect the product (not the raw 50% threshold)
    try testing.expect(ctx.last_mutate_value != null);
}

test "PolicyEngine: trace sampling 0% drops all" {
    const allocator = testing.allocator;

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "trace-sample-0"),
        .name = try allocator.dupe(u8, "sample-0"),
        .enabled = true,
        .target = .{ .trace = .{
            .keep = .{ .percentage = 0.0 },
        } },
    };
    try policy.target.?.trace.match.append(allocator, .{
        .field = .{ .trace_field = .TRACE_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, ".+") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Even with high R, 0% should always drop
    var ctx: TestTraceContext = .{
        .name = "test-span",
        .trace_id = &[16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    };

    const result = evalTrace(&engine, &ctx, &policy_id_buf);
    try testing.expectEqual(FilterDecision.drop, result.decision);
    try testing.expectEqual(@as(usize, 0), ctx.mutate_count);
}

test "PolicyEngine: trace sampling fail_closed=true drops span with no trace ID" {
    const allocator = testing.allocator;

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "trace-fail-closed"),
        .name = try allocator.dupe(u8, "fail-closed"),
        .enabled = true,
        .target = .{ .trace = .{
            .keep = .{
                .percentage = 50.0,
                .fail_closed = true,
            },
        } },
    };
    try policy.target.?.trace.match.append(allocator, .{
        .field = .{ .trace_field = .TRACE_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, ".+") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // No trace ID → can't derive randomness → fail_closed=true → drop
    var ctx: TestTraceContext = .{
        .name = "test-span",
    };

    const result = evalTrace(&engine, &ctx, &policy_id_buf);
    try testing.expectEqual(FilterDecision.drop, result.decision);
}

test "PolicyEngine: trace sampling fail_closed=false keeps span with no trace ID" {
    const allocator = testing.allocator;

    var policy: Policy = .{
        .id = try allocator.dupe(u8, "trace-fail-open"),
        .name = try allocator.dupe(u8, "fail-open"),
        .enabled = true,
        .target = .{ .trace = .{
            .keep = .{
                .percentage = 50.0,
                .fail_closed = false,
            },
        } },
    };
    try policy.target.?.trace.match.append(allocator, .{
        .field = .{ .trace_field = .TRACE_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, ".+") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // No trace ID → can't derive randomness → fail_closed=false → keep
    var ctx: TestTraceContext = .{
        .name = "test-span",
    };

    const result = evalTrace(&engine, &ctx, &policy_id_buf);
    try testing.expectEqual(FilterDecision.keep, result.decision);
}

// =============================================================================
// Mixed Signal Type Stats Tests
// =============================================================================

test "PolicyEngine: mixed signal policies scope stats to own signal type" {
    const allocator = testing.allocator;

    // Policy 0: log policy — drop logs matching "error"
    var log_policy: Policy = .{
        .id = try allocator.dupe(u8, "drop-error-logs"),
        .name = try allocator.dupe(u8, "drop-error-logs"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try log_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer log_policy.deinit(allocator);

    // Policy 1: metric policy — drop metrics named "internal.*"
    var metric_policy: Policy = .{
        .id = try allocator.dupe(u8, "drop-internal-metrics"),
        .name = try allocator.dupe(u8, "drop-internal-metrics"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    try metric_policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .starts_with = try allocator.dupe(u8, "internal.") },
    });
    defer metric_policy.deinit(allocator);

    // Policy 2: trace policy — drop spans containing "health"
    var trace_policy: Policy = .{
        .id = try allocator.dupe(u8, "drop-health-spans"),
        .name = try allocator.dupe(u8, "drop-health-spans"),
        .enabled = true,
        .target = .{ .trace = .{
            .keep = .{ .percentage = 0.0 },
        } },
    };
    try trace_policy.target.?.trace.match.append(allocator, .{
        .field = .{ .trace_field = .TRACE_FIELD_NAME },
        .match = .{ .contains = try allocator.dupe(u8, "health") },
    });
    defer trace_policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Register all three policies together (indices 0, 1, 2 in global stats)
    try registry.updatePolicies(&.{ log_policy, metric_policy, trace_policy }, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // --- Evaluate a matching LOG ---
    var log_ctx: TestLogContext = .{ .message = "an error occurred" };
    _ = evalTestLog(&engine, &log_ctx, &policy_id_buf);

    // --- Evaluate a matching METRIC ---
    var metric_ctx: TestMetricContext = .{ .name = "internal.debug.counter" };
    _ = evalMetric(&engine, &metric_ctx, &policy_id_buf);

    // --- Evaluate a matching TRACE ---
    var trace_ctx: TestTraceContext = .{
        .name = "GET /health/ready",
        .trace_id = &[16]u8{
            0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF,
        },
    };
    _ = evalTrace(&engine, &trace_ctx, &policy_id_buf);

    // --- Verify stats ---
    const snapshot = registry.getSnapshot().?;

    // Policy 0 (drop-error-logs): should have exactly 1 hit from the log eval
    const log_stats = snapshot.getStats(0).?;
    try testing.expectEqual(@as(i64, 1), log_stats.hits.load(.monotonic));

    // Policy 1 (drop-internal-metrics): should have exactly 1 hit from the metric eval
    const metric_stats = snapshot.getStats(1).?;
    try testing.expectEqual(@as(i64, 1), metric_stats.hits.load(.monotonic));

    // Policy 2 (drop-health-spans): should have exactly 1 hit from the trace eval
    const trace_stats = snapshot.getStats(2).?;
    try testing.expectEqual(@as(i64, 1), trace_stats.hits.load(.monotonic));
}
