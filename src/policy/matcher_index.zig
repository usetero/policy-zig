//! Matcher Index - Inverted index for efficient policy matching
//!
//! This module compiles policies into Hyperscan databases indexed by MatcherKey.
//! At evaluation time, we scan each field value against its corresponding database
//! and aggregate matches to determine which policies fully match.
//!
//! ## Architecture
//!
//! 1. **LogMatcherIndex / MetricMatcherIndex**: Type-specific indices for each telemetry type
//! 2. **MatcherDatabase**: Compiled Hyperscan DBs for one MatcherKey (positive + negated)
//! 3. **IndexBuilder(T)**: Generic builder for constructing type-specific indices
//!
//! ## Performance Optimizations
//!
//! - **Compile-time dispatch**: No runtime telemetry type filtering
//! - **Numeric policy indices**: O(1) array lookups instead of string hash lookups
//! - **Separate positive/negated databases**: Clean separation, no per-pattern negate flag
//! - **Dense policy array**: Cache-friendly iteration over matched policies

const std = @import("std");
const proto = @import("proto");
const hyperscan = @import("./hyperscan.zig");
const policy_types = @import("./types.zig");
const probabilistic_sampler_mod = @import("./probabilistic_sampler.zig");
const rate_limiter_mod = @import("./rate_limiter.zig");
const redact_mod = @import("./redact.zig");
const log_transform = @import("./log_transform.zig");
const o11y = @import("observability");
const EventBus = o11y.EventBus;
const NoopEventBus = o11y.NoopEventBus;

const ProbabilisticSampler = probabilistic_sampler_mod.ProbabilisticSampler;
const RateLimiter = rate_limiter_mod.RateLimiter;

const FieldRef = policy_types.FieldRef;
const MetricFieldRef = policy_types.MetricFieldRef;
const TraceFieldRef = policy_types.TraceFieldRef;
pub const TelemetryType = policy_types.TelemetryType;

const Policy = proto.policy.Policy;
const LogMatcher = proto.policy.LogMatcher;
const MatchType = LogMatcher._match_case;
const LogTarget = proto.policy.LogTarget;
const LogField = proto.policy.LogField;
const MetricMatcher = proto.policy.MetricMatcher;
const MetricTarget = proto.policy.MetricTarget;
const MetricField = proto.policy.MetricField;
const TraceMatcher = proto.policy.TraceMatcher;
const TraceTarget = proto.policy.TraceTarget;
const TraceField = proto.policy.TraceField;
const AttributePath = proto.policy.AttributePath;
const LogSampleKey = proto.policy.LogSampleKey;

// =============================================================================
// Observability Events
// =============================================================================

const MatcherIndexBuildStarted = struct { policy_count: usize, telemetry_type: TelemetryType };
const MatcherIndexBuildCompleted = struct { database_count: usize, matcher_key_count: usize, policy_count: usize };
const ScanMatched = struct { pattern_count: usize, value_len: usize, value_preview: []const u8, is_negated: bool };
const ScanMatchDetail = struct { pattern_id: u32, policy_index: PolicyIndex };
const ScanError = struct { err: []const u8 };
const ProcessingPolicy = struct { id: []const u8, name: []const u8, enabled: bool, index: PolicyIndex, telemetry_type: TelemetryType };
const SkippingPolicyWrongType = struct { id: []const u8 };
const PolicyMatcherCount = struct { id: []const u8, matcher_count: usize };
const MatcherNullField = struct { matcher_idx: usize };
const MatcherNullMatch = struct { matcher_idx: usize };
const MatcherEmptyRegex = struct { matcher_idx: usize };
const MatcherDetail = struct { matcher_idx: usize, regex: []const u8, negate: bool };
// v1.5.0: typed matchers (equals/gt/gte/lt/lte) are parsed but not yet
// evaluated by the engine — they produce no Hyperscan patterns and never
// match. The engine will gain typed comparison in the next PR.
const TypedMatcherSkipped = struct { matcher_idx: usize };
const PolicyStored = struct { id: []const u8, index: PolicyIndex, required_matches: u16, negated_count: u16 };

// =============================================================================
// Policy Index - Numeric identifier for O(1) lookups
// =============================================================================

/// Numeric policy index for efficient array-based lookups at runtime.
pub const PolicyIndex = u16;

/// Maximum number of policies supported
pub const MAX_POLICIES: usize = 8192;

// =============================================================================
// MatcherKey Types - Separate types for log and metric
// =============================================================================

/// Key for indexing Hyperscan databases for log policies.
///
/// `exists_entries` is a per-policy list of exists-matchers on this field;
/// it is not part of the hash/eql contract (only `field` is). Lookups in the
/// `databases` HashMap therefore work with a key constructed via just the
/// field. The engine reads `exists_entries` directly off the entry returned
/// by `getMatcherKeys`.
///
/// `has_value_db` is set at build time when at least one positive or negated
/// value pattern is compiled for this key. Exists-only keys have it false;
/// the engine uses this to skip the `value()` + database lookup that would
/// otherwise be dead work.
pub const LogMatcherKey = struct {
    field: FieldRef,
    exists_entries: []const ExistsEntry = &.{},
    has_value_db: bool = false,

    const Self = @This();

    pub fn hash(self: Self) u64 {
        return hashFieldRef(FieldRef, self.field);
    }

    pub fn eql(a: Self, b: Self) bool {
        return eqlFieldRef(FieldRef, a.field, b.field);
    }
};

/// Key for indexing Hyperscan databases for metric policies.
pub const MetricMatcherKey = struct {
    field: MetricFieldRef,
    exists_entries: []const ExistsEntry = &.{},
    has_value_db: bool = false,

    const Self = @This();

    pub fn hash(self: Self) u64 {
        return hashFieldRef(MetricFieldRef, self.field);
    }

    pub fn eql(a: Self, b: Self) bool {
        return eqlFieldRef(MetricFieldRef, a.field, b.field);
    }
};

/// Generic hash implementation for field refs
fn hashFieldRef(comptime FieldRefT: type, field: FieldRefT) u64 {
    var h = std.hash.Wyhash.init(0);
    switch (field) {
        inline else => |val, tag| {
            h.update(std.mem.asBytes(&tag));
            const T = @TypeOf(val);
            if (T == AttributePath) {
                // Hash AttributePath: each path segment plus separator
                for (val.path.items) |segment| {
                    h.update(segment);
                    h.update(&[_]u8{0}); // null separator between segments
                }
            } else if (T == []const []const u8) {
                // Hash path array: each segment plus separator
                for (val) |segment| {
                    h.update(segment);
                    h.update(&[_]u8{0}); // null separator between segments
                }
            } else if (T == []const u8) {
                h.update(val);
            } else {
                h.update(std.mem.asBytes(&val));
            }
        },
    }
    return h.final();
}

/// Generic equality implementation for field refs
fn eqlFieldRef(comptime FieldRefT: type, a: FieldRefT, b: FieldRefT) bool {
    const tag_a = std.meta.activeTag(a);
    const tag_b = std.meta.activeTag(b);
    if (tag_a != tag_b) return false;

    switch (a) {
        inline else => |val_a, tag| {
            const val_b = @field(b, @tagName(tag));
            const T = @TypeOf(val_a);
            if (T == AttributePath) {
                // Compare AttributePath: same length and all segments equal
                const path_a = val_a.path.items;
                const path_b = val_b.path.items;
                if (path_a.len != path_b.len) return false;
                for (path_a, path_b) |seg_a, seg_b| {
                    if (!std.mem.eql(u8, seg_a, seg_b)) return false;
                }
                return true;
            } else if (T == []const []const u8) {
                // Compare path arrays: same length and all segments equal
                if (val_a.len != val_b.len) return false;
                for (val_a, val_b) |seg_a, seg_b| {
                    if (!std.mem.eql(u8, seg_a, seg_b)) return false;
                }
                return true;
            } else if (T == []const u8) {
                return std.mem.eql(u8, val_a, val_b);
            } else {
                return val_a == val_b;
            }
        },
    }
}

/// Hash context for LogMatcherKey in hash maps
pub const LogMatcherKeyContext = struct {
    pub fn hash(_: LogMatcherKeyContext, key: LogMatcherKey) u64 {
        return key.hash();
    }
    pub fn eql(_: LogMatcherKeyContext, a: LogMatcherKey, b: LogMatcherKey) bool {
        return a.eql(b);
    }
};

/// Hash context for MetricMatcherKey in hash maps
pub const MetricMatcherKeyContext = struct {
    pub fn hash(_: MetricMatcherKeyContext, key: MetricMatcherKey) u64 {
        return key.hash();
    }
    pub fn eql(_: MetricMatcherKeyContext, a: MetricMatcherKey, b: MetricMatcherKey) bool {
        return a.eql(b);
    }
};

/// Key for indexing Hyperscan databases for trace policies.
pub const TraceMatcherKey = struct {
    field: TraceFieldRef,
    exists_entries: []const ExistsEntry = &.{},
    has_value_db: bool = false,

    const Self = @This();

    pub fn hash(self: Self) u64 {
        return hashFieldRef(TraceFieldRef, self.field);
    }

    pub fn eql(a: Self, b: Self) bool {
        return eqlFieldRef(TraceFieldRef, a.field, b.field);
    }
};

/// Hash context for TraceMatcherKey in hash maps
pub const TraceMatcherKeyContext = struct {
    pub fn hash(_: TraceMatcherKeyContext, key: TraceMatcherKey) u64 {
        return key.hash();
    }
    pub fn eql(_: TraceMatcherKeyContext, a: TraceMatcherKey, b: TraceMatcherKey) bool {
        return a.eql(b);
    }
};

// =============================================================================
// KeepValue - Parsed keep configuration
// =============================================================================

/// Rate limit parameters: count per duration window.
pub const RateLimit = struct {
    count: u32,
    duration: u32,
};

/// Parsed keep value from policy.
/// Priority order (most restrictive first): none > rate_limit > percentage > all
pub const KeepValue = union(enum) {
    all,
    none,
    percentage: u8,
    per_second: RateLimit,
    per_minute: RateLimit,

    /// Maximum rate-limit window expressed in the policy unit. The runtime
    /// converts `per_second` to milliseconds (×1_000) and `per_minute` to
    /// milliseconds (×60_000), so the cap is chosen to keep the converted
    /// value well within u32 (max 4_294_967_295).
    ///
    /// - per_second: 1_000_000 → 1_000_000_000 ms (~11.5 days), well under u32 max
    /// - per_minute: 50_000   → 3_000_000_000 ms (~34.7 days), under u32 max
    ///
    /// We cap per_second at 1M and per_minute at 50K — both produce sane
    /// windows; values above either are clamped to the cap.
    pub const MAX_RATE_LIMIT_DURATION_SECONDS: u32 = 1_000_000;
    pub const MAX_RATE_LIMIT_DURATION_MINUTES: u32 = 50_000;

    pub fn parse(s: []const u8) KeepValue {
        if (s.len == 0 or std.mem.eql(u8, s, "all")) return .all;
        if (std.mem.eql(u8, s, "none")) return .none;

        if (s.len >= 2 and s[s.len - 1] == '%') {
            const pct = std.fmt.parseInt(u8, s[0 .. s.len - 1], 10) catch return .all;
            if (pct > 100) return .all;
            return .{ .percentage = pct };
        }

        // Rate limit: "N/s", "N/m", "N/Ds", "N/Dm"
        if (std.mem.indexOfScalar(u8, s, '/')) |slash_pos| {
            if (slash_pos == 0 or slash_pos >= s.len - 1) return .all;
            const count = std.fmt.parseInt(u32, s[0..slash_pos], 10) catch return .all;
            const after_slash = s[slash_pos + 1 ..];
            const unit = after_slash[after_slash.len - 1];
            if (unit != 's' and unit != 'm') return .all;
            const duration_raw: u32 = if (after_slash.len == 1)
                1
            else
                std.fmt.parseInt(u32, after_slash[0 .. after_slash.len - 1], 10) catch return .all;
            if (duration_raw == 0) return .all;

            // Clamp the window so the later ms conversion (×1_000 / ×60_000)
            // can't overflow u32 in storePolicyInfo.
            const max: u32 = if (unit == 's') MAX_RATE_LIMIT_DURATION_SECONDS else MAX_RATE_LIMIT_DURATION_MINUTES;
            const duration = if (duration_raw > max) max else duration_raw;
            const rl = RateLimit{ .count = count, .duration = duration };
            return if (unit == 's') .{ .per_second = rl } else .{ .per_minute = rl };
        }
        return .all;
    }

    pub fn isMoreRestrictiveThan(self: KeepValue, other: KeepValue) bool {
        const self_rank = self.restrictiveness();
        const other_rank = other.restrictiveness();
        if (self_rank != other_rank) return self_rank < other_rank;
        return switch (self) {
            .percentage => |p| switch (other) {
                .percentage => |op| p < op,
                else => false,
            },
            else => false,
        };
    }

    pub fn restrictiveness(self: KeepValue) u8 {
        // Lower rank = more restrictive
        // none: drop everything (most restrictive)
        // rate limit: keep up to N per time unit
        // percentage: keep N% of data
        // all: keep everything (least restrictive)
        return switch (self) {
            .none => 0,
            .per_second, .per_minute => 1,
            .percentage => 2,
            .all => 3,
        };
    }
};

// =============================================================================
// PolicyInfo - Policy metadata for match aggregation
// =============================================================================

/// Policy information needed for match aggregation and action determination.
/// No telemetry_type field - that's implicit in the index type.
pub const PolicyInfo = struct {
    id: []const u8,
    index: PolicyIndex,
    /// Global index into the shared policy_stats array. Differs from `index`
    /// when policies span multiple signal types (log, metric, trace).
    stats_index: PolicyIndex,
    required_match_count: u16,
    negated_count: u16,
    keep: KeepValue,
    enabled: bool,
    /// Rate limiter for per_second/per_minute policies. Null for other keep types.
    /// Pointer because RateLimiter contains atomics that need stable addresses.
    rate_limiter: ?*RateLimiter,
    /// Sample key for deterministic log sampling. When set, the specified field's
    /// value is hashed for consistent sampling decisions (e.g., same trace_id always
    /// gets same decision). Only applicable for log policies with percentage keep.
    sample_key: ?LogSampleKey = null,
    /// OTel-compliant probabilistic sampler. Pre-computed at index build time.
    /// Set for trace and log policies with percentage keep.
    sampler: ?ProbabilisticSampler = null,
    /// Compiled redact rules for log policies, paired with their source rule.
    /// Length matches `LogTransform.redact.items.len`; ordering matches the
    /// rule list. Each entry's `compiled` is non-null only when the source
    /// rule carries a `regex`. Empty slice for non-log policies or log
    /// policies with no redacts.
    compiled_redacts: []log_transform.CompiledRedact = &.{},
};

// =============================================================================
// PatternMeta - Metadata for each pattern in a database
// =============================================================================

const PatternMeta = struct {
    policy_index: PolicyIndex,
};

const PatternCollector = struct {
    policy_index: PolicyIndex,
    pattern: []const u8,
    match_type: MatchType = .regex,
    case_insensitive: bool = false,
};

/// Per-policy entry for an exists matcher on a given field.
/// `negate` already reflects the spec-level combination of `matcher.negate`
/// and `exists` value: the engine treats this as a Hyperscan-style negated
/// pattern (initial seed +1, decrement when condition fires).
pub const ExistsEntry = struct {
    policy_index: PolicyIndex,
    negate: bool,
};

// =============================================================================
// Typed Matcher Types (v1.5.0)
// =============================================================================

/// Compiled non-string scalar for the `equals` matcher.
/// `bytes` owns its memory — freed when the parent index is deinitialized.
pub const CompiledValue = union(enum) {
    bool: bool,
    int: i64,
    double: f64,
    bytes: []const u8,
};

/// Compiled numeric value for `gt`/`gte`/`lt`/`lte` matchers.
pub const CompiledNumericValue = union(enum) {
    int: i64,
    double: f64,
};

/// Compiled form of a typed matcher. The enum tag encodes the operator.
pub const CompiledTypedMatcher = union(enum) {
    equals: CompiledValue,
    gt: CompiledNumericValue,
    gte: CompiledNumericValue,
    lt: CompiledNumericValue,
    lte: CompiledNumericValue,

    /// Evaluate this typed matcher against a field value.
    /// Returns true when the matcher fires (before applying `negate`).
    /// Type mismatch is always a non-match (fail-open, never an error).
    pub fn evaluate(self: CompiledTypedMatcher, field_value: ?policy_types.TypedValue) bool {
        const fv = field_value orelse return false;
        return switch (self) {
            .equals => |expected| switch (expected) {
                .bool => |e| switch (fv) {
                    .bool => |a| e == a,
                    else => false,
                },
                .int => |e| switch (fv) {
                    .int => |a| e == a,
                    .double => |a| @as(f64, @floatFromInt(e)) == a,
                    else => false,
                },
                .double => |e| switch (fv) {
                    .double => |a| e == a,
                    .int => |a| e == @as(f64, @floatFromInt(a)),
                    else => false,
                },
                .bytes => |e| switch (fv) {
                    .bytes => |a| std.mem.eql(u8, e, a),
                    else => false,
                },
            },
            .gt => |t| compareNumeric(fv, t, std.math.Order.gt),
            .gte => |t| compareNumericGte(fv, t),
            .lt => |t| compareNumeric(fv, t, std.math.Order.lt),
            .lte => |t| compareNumericLte(fv, t),
        };
    }
};

fn compareNumeric(fv: policy_types.TypedValue, threshold: CompiledNumericValue, order: std.math.Order) bool {
    const field_f64: f64 = switch (fv) {
        .int => |i| @floatFromInt(i),
        .double => |d| d,
        else => return false,
    };
    const threshold_f64: f64 = switch (threshold) {
        .int => |i| @floatFromInt(i),
        .double => |d| d,
    };
    const cmp = std.math.order(field_f64, threshold_f64);
    return cmp == order;
}

fn compareNumericGte(fv: policy_types.TypedValue, threshold: CompiledNumericValue) bool {
    const field_f64: f64 = switch (fv) {
        .int => |i| @floatFromInt(i),
        .double => |d| d,
        else => return false,
    };
    const threshold_f64: f64 = switch (threshold) {
        .int => |i| @floatFromInt(i),
        .double => |d| d,
    };
    return field_f64 >= threshold_f64;
}

fn compareNumericLte(fv: policy_types.TypedValue, threshold: CompiledNumericValue) bool {
    const field_f64: f64 = switch (fv) {
        .int => |i| @floatFromInt(i),
        .double => |d| d,
        else => return false,
    };
    const threshold_f64: f64 = switch (threshold) {
        .int => |i| @floatFromInt(i),
        .double => |d| d,
    };
    return field_f64 <= threshold_f64;
}

/// A compiled typed check stored in the matcher index.
/// Field type is signal-specific — the index builder instantiates one
/// `CompiledTypedCheck` type per telemetry type via comptime.
pub fn TypedCheckType(comptime T: TelemetryType) type {
    return struct {
        policy_index: PolicyIndex,
        field_ref: FieldRefType(T),
        matcher: CompiledTypedMatcher,
        negate: bool,
    };
}

/// Compile a proto `Value` to a `CompiledValue`.
/// The parser already decoded hex_value → bytes_value, so we only see
/// bool/int/double/bytes at compile time. Returns null on unset or invalid.
fn compileValue(allocator: std.mem.Allocator, v: proto.policy.Value) !?CompiledValue {
    const inner = v.value orelse return null;
    return switch (inner) {
        .bool_value => |b| .{ .bool = b },
        .int_value => |i| .{ .int = i },
        .double_value => |d| .{ .double = d },
        .bytes_value => |b| .{ .bytes = try allocator.dupe(u8, b) },
        // hex_value should have been decoded by the parser; if it reaches here
        // (e.g. via raw protobuf), decode it now.
        .hex_value => |h| blk: {
            if (h.len % 2 != 0) return null;
            const bytes = try allocator.alloc(u8, h.len / 2);
            errdefer allocator.free(bytes);
            for (0..bytes.len) |i| {
                const hi = hexNibble(h[i * 2]) orelse return null;
                const lo = hexNibble(h[i * 2 + 1]) orelse return null;
                bytes[i] = (hi << 4) | lo;
            }
            break :blk .{ .bytes = bytes };
        },
    };
}

fn hexNibble(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

/// Compile a proto `NumericValue`. Returns null when unset.
fn compileNumericValue(v: proto.policy.NumericValue) ?CompiledNumericValue {
    const inner = v.value orelse return null;
    return switch (inner) {
        .int_value => |i| .{ .int = i },
        .double_value => |d| .{ .double = d },
    };
}

// =============================================================================
// ScanResult - Result of scanning a value
// =============================================================================

pub const ScanResult = struct {
    count: usize,
    buf: []u32,

    pub fn matches(self: ScanResult) []const u32 {
        return self.buf[0..self.count];
    }
};

/// Internal context for scanWithCallback that adds O(1) dedup via a seen bitset.
/// Wraps ScanResult so the public API is unchanged.
const ScanContext = struct {
    result: ScanResult,
    seen: [MAX_DEDUP_IDS]bool,

    const MAX_DEDUP_IDS: usize = 256;

    fn init(buf: []u32) ScanContext {
        return .{
            .result = .{ .count = 0, .buf = buf },
            .seen = @splat(false),
        };
    }
};

// =============================================================================
// MatcherDatabase - Compiled Hyperscan DBs for one MatcherKey
// =============================================================================

pub const MatcherDatabase = struct {
    positive_db: ?hyperscan.Database,
    negated_db: ?hyperscan.Database,
    scratch_pool: [SCRATCH_POOL_SIZE]?hyperscan.Scratch,
    scratch_locks: [SCRATCH_POOL_SIZE]std.atomic.Value(bool),
    next_scratch: std.atomic.Value(usize),
    positive_patterns: []const PatternMeta,
    negated_patterns: []const PatternMeta,
    allocator: std.mem.Allocator,
    bus: *EventBus,

    const Self = @This();
    pub const SCRATCH_POOL_SIZE: usize = 8;

    const ScratchHandle = struct {
        scratch: *hyperscan.Scratch,
        slot: usize,
        db: *Self,

        pub fn release(self: ScratchHandle) void {
            self.db.scratch_locks[self.slot].store(false, .release);
        }
    };

    fn acquireScratch(self: *Self) ?ScratchHandle {
        const base = self.next_scratch.fetchAdd(1, .monotonic);
        // Try each slot once
        for (0..SCRATCH_POOL_SIZE) |offset| {
            const slot = (base +% offset) % SCRATCH_POOL_SIZE;
            if (self.scratch_pool[slot] == null) continue;
            if (self.scratch_locks[slot].cmpxchgWeak(false, true, .acquire, .monotonic) == null) {
                return .{
                    .scratch = &self.scratch_pool[slot].?,
                    .slot = slot,
                    .db = self,
                };
            }
        }
        // All slots busy — spin on original slot (extremely rare with 8 slots)
        const slot = base % SCRATCH_POOL_SIZE;
        while (self.scratch_locks[slot].cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
            std.atomic.spinLoopHint();
        }
        if (self.scratch_pool[slot] != null) {
            return .{
                .scratch = &self.scratch_pool[slot].?,
                .slot = slot,
                .db = self,
            };
        }
        return null;
    }

    pub fn scanPositive(self: *Self, value: []const u8, result_buf: []u32) ScanResult {
        return self.scanDb(self.positive_db, self.positive_patterns, value, result_buf, false);
    }

    pub fn scanNegated(self: *Self, value: []const u8, result_buf: []u32) ScanResult {
        return self.scanDb(self.negated_db, self.negated_patterns, value, result_buf, true);
    }

    fn scanDb(self: *Self, db: ?hyperscan.Database, patterns: []const PatternMeta, value: []const u8, result_buf: []u32, is_negated: bool) ScanResult {
        const database = db orelse return ScanResult{ .count = 0, .buf = result_buf };
        const handle = self.acquireScratch() orelse return ScanResult{ .count = 0, .buf = result_buf };
        defer handle.release();

        var ctx = ScanContext.init(result_buf);
        _ = database.scanWithCallback(handle.scratch, value, &ctx, scanCallback) catch |err| {
            self.bus.warn(ScanError{ .err = @errorName(err) });
            return ctx.result;
        };

        if (ctx.result.count > 0 and self.bus.isEnabled(.debug)) {
            self.bus.debug(ScanMatched{
                .pattern_count = ctx.result.count,
                .value_len = value.len,
                .value_preview = if (value.len > 100) value[0..100] else value,
                .is_negated = is_negated,
            });
            for (ctx.result.matches()) |pattern_id| {
                if (pattern_id < patterns.len) {
                    self.bus.debug(ScanMatchDetail{ .pattern_id = pattern_id, .policy_index = patterns[pattern_id].policy_index });
                }
            }
        }
        return ctx.result;
    }

    fn scanCallback(ctx: *ScanContext, match: hyperscan.Match) bool {
        if (ctx.result.count < ctx.result.buf.len) {
            // O(1) dedup via seen bitset — Hyperscan calls back per match position
            if (match.id < ScanContext.MAX_DEDUP_IDS) {
                if (ctx.seen[match.id]) return true;
                ctx.seen[match.id] = true;
            }
            ctx.result.buf[ctx.result.count] = match.id;
            ctx.result.count += 1;
            return true;
        }
        return false;
    }

    pub fn deinit(self: *Self) void {
        for (&self.scratch_pool) |*s| {
            if (s.*) |*scratch| scratch.deinit();
        }
        if (self.positive_db) |*db| db.deinit();
        if (self.negated_db) |*db| db.deinit();
        self.allocator.free(self.positive_patterns);
        self.allocator.free(self.negated_patterns);
    }
};

// =============================================================================
// Comptime Type Helpers
// =============================================================================

/// Returns the MatcherKey type for a given telemetry type
pub fn MatcherKeyType(comptime T: TelemetryType) type {
    return switch (T) {
        .log => LogMatcherKey,
        .metric => MetricMatcherKey,
        .trace => TraceMatcherKey,
    };
}

/// Returns the FieldRef type for a given telemetry type
pub fn FieldRefType(comptime T: TelemetryType) type {
    return switch (T) {
        .log => FieldRef,
        .metric => MetricFieldRef,
        .trace => TraceFieldRef,
    };
}

/// Returns the Matcher type for a given telemetry type
fn MatcherType(comptime T: TelemetryType) type {
    return switch (T) {
        .log => LogMatcher,
        .metric => MetricMatcher,
        .trace => TraceMatcher,
    };
}

/// Returns the Target type for a given telemetry type
fn TargetType(comptime T: TelemetryType) type {
    return switch (T) {
        .log => LogTarget,
        .metric => MetricTarget,
        .trace => TraceTarget,
    };
}

/// Returns the HashContext type for a given telemetry type
fn HashContextType(comptime T: TelemetryType) type {
    return switch (T) {
        .log => LogMatcherKeyContext,
        .metric => MetricMatcherKeyContext,
        .trace => TraceMatcherKeyContext,
    };
}

/// Returns the MatcherIndex type for a given telemetry type
pub fn MatcherIndexType(comptime T: TelemetryType) type {
    return switch (T) {
        .log => LogMatcherIndex,
        .metric => MetricMatcherIndex,
        .trace => TraceMatcherIndex,
    };
}

// =============================================================================
// PatternsPerKey - Collected patterns before compilation
// =============================================================================

const PatternsPerKey = struct {
    positive: std.ArrayListUnmanaged(PatternCollector),
    negated: std.ArrayListUnmanaged(PatternCollector),
    /// Exists-matchers are bucketed separately so the engine can dispatch them
    /// via `accessor.callExists` (presence-regardless-of-type) instead of
    /// scanning the value bytes through Hyperscan.
    exists: std.ArrayListUnmanaged(ExistsEntry),
};

// =============================================================================
// IndexBuilder - Generic builder for type-specific indices
// =============================================================================

fn IndexBuilder(comptime T: TelemetryType) type {
    const MatcherKeyT = MatcherKeyType(T);
    const FieldRefT = FieldRefType(T);
    const MatcherT = MatcherType(T);
    const TargetT = TargetType(T);
    const HashContextT = HashContextType(T);
    const IndexT = MatcherIndexType(T);
    const TypedCheckT = TypedCheckType(T);

    return struct {
        allocator: std.mem.Allocator,
        temp_allocator: std.mem.Allocator,
        bus: *EventBus,
        patterns_by_key: std.HashMap(MatcherKeyT, PatternsPerKey, HashContextT, std.hash_map.default_max_load_percentage),
        policy_info_list: std.ArrayListUnmanaged(PolicyInfo),
        typed_checks_list: std.ArrayListUnmanaged(TypedCheckT),
        path_storage: std.ArrayListUnmanaged([]const []const u8),
        policy_id_storage: std.ArrayListUnmanaged([]const u8),
        policy_index: PolicyIndex,
        current_positive_count: u16,
        current_negated_count: u16,

        const Self = @This();

        fn init(allocator: std.mem.Allocator, temp_allocator: std.mem.Allocator, bus: *EventBus) Self {
            return .{
                .allocator = allocator,
                .temp_allocator = temp_allocator,
                .bus = bus,
                .patterns_by_key = std.HashMap(MatcherKeyT, PatternsPerKey, HashContextT, std.hash_map.default_max_load_percentage).init(temp_allocator),
                .policy_info_list = .empty,
                .typed_checks_list = .empty,
                .path_storage = .empty,
                .policy_id_storage = .empty,
                .policy_index = 0,
                .current_positive_count = 0,
                .current_negated_count = 0,
            };
        }

        fn processPolicy(self: *Self, policy: *const Policy, global_index: PolicyIndex) !void {
            const target = getTarget(policy) orelse {
                self.bus.debug(SkippingPolicyWrongType{ .id = policy.id });
                return;
            };

            self.bus.debug(ProcessingPolicy{
                .id = policy.id,
                .name = policy.name,
                .enabled = policy.enabled,
                .index = self.policy_index,
                .telemetry_type = T,
            });

            self.current_positive_count = 0;
            self.current_negated_count = 0;

            self.bus.debug(PolicyMatcherCount{ .id = policy.id, .matcher_count = target.match.items.len });

            for (target.match.items, 0..) |matcher, matcher_idx| {
                try self.processMatcher(&matcher, matcher_idx);
            }

            const keep_value = parseKeepValue(target);
            try self.storePolicyInfo(policy, target, keep_value, global_index);
        }

        fn getTarget(policy: *const Policy) ?*const TargetT {
            const target_ptr = &(policy.target orelse return null);
            return switch (T) {
                .log => switch (target_ptr.*) {
                    .log => |*log| log,
                    .metric, .trace => null,
                },
                .metric => switch (target_ptr.*) {
                    .metric => |*metric| metric,
                    .log, .trace => null,
                },
                .trace => switch (target_ptr.*) {
                    .trace => |*trace| trace,
                    .log, .metric => null,
                },
            };
        }

        fn parseKeepValue(target: *const TargetT) KeepValue {
            return switch (T) {
                .log => KeepValue.parse(target.keep),
                .metric => if (target.keep) .all else .none,
                .trace => blk: {
                    // Trace uses TraceSamplingConfig with percentage (0-100)
                    // Note: we keep 100% as .percentage (not .all) so the sampler is
                    // created and writes th:0 to tracestate per W3C spec.
                    const keep_config = target.keep orelse break :blk .all;
                    const percentage = keep_config.percentage;
                    if (percentage <= 0.0) break :blk .none;
                    break :blk .{ .percentage = @intFromFloat(@min(100.0, @max(0.0, percentage))) };
                },
            };
        }

        fn processMatcher(self: *Self, matcher: *const MatcherT, matcher_idx: usize) !void {
            const field_ref = getFieldRef(matcher) orelse {
                self.bus.debug(MatcherNullField{ .matcher_idx = matcher_idx });
                return;
            };

            // Enum-type fields (metric_type, aggregation_temporality, span_kind,
            // span_status) carry their value in the field union itself. When the
            // HTTP sync server serializes these via protobuf JSON it may omit the
            // match oneof, so match arrives as null. Treat this as implicit
            // exists=true so the matcher still fires.
            if (matcher.match == null and field_ref.isEnumField()) {
                self.bus.debug(MatcherDetail{
                    .matcher_idx = matcher_idx,
                    .regex = "",
                    .negate = matcher.negate,
                });
                try self.addExists(MatcherKeyT{ .field = field_ref }, matcher.negate, field_ref);
                return;
            }

            const m = matcher.match orelse {
                self.bus.debug(MatcherNullMatch{ .matcher_idx = matcher_idx });
                return;
            };

            // Exists matchers go to the exists bucket — they fire on field
            // presence regardless of underlying value type.
            switch (m) {
                .exists => |exists| {
                    const negate = matcher.negate != !exists;
                    self.bus.debug(MatcherDetail{
                        .matcher_idx = matcher_idx,
                        .regex = "",
                        .negate = negate,
                    });
                    try self.addExists(MatcherKeyT{ .field = field_ref }, negate, field_ref);
                    return;
                },
                else => {},
            }

            // Typed matchers (v1.5.0): compile the value/threshold and append
            // to typed_checks_list. They bypass Hyperscan entirely; the engine
            // evaluates them in a separate loop via the accessor.typed_value
            // primitive. An invalid/unset value is silently dropped (fail-open).
            switch (m) {
                .equals => |v| {
                    const compiled = (try compileValue(self.allocator, v)) orelse {
                        self.bus.debug(TypedMatcherSkipped{ .matcher_idx = matcher_idx });
                        return;
                    };
                    // typed checks count toward required_match_count so the
                    // policy's match threshold is still enforced.
                    if (matcher.negate) {
                        self.current_negated_count += 1;
                    } else {
                        self.current_positive_count += 1;
                    }
                    try self.typed_checks_list.append(self.allocator, .{
                        .policy_index = self.policy_index,
                        .field_ref = field_ref,
                        .matcher = .{ .equals = compiled },
                        .negate = matcher.negate,
                    });
                    return;
                },
                .gt => |v| {
                    const compiled = compileNumericValue(v) orelse {
                        self.bus.debug(TypedMatcherSkipped{ .matcher_idx = matcher_idx });
                        return;
                    };
                    if (matcher.negate) self.current_negated_count += 1 else self.current_positive_count += 1;
                    try self.typed_checks_list.append(self.allocator, .{
                        .policy_index = self.policy_index,
                        .field_ref = field_ref,
                        .matcher = .{ .gt = compiled },
                        .negate = matcher.negate,
                    });
                    return;
                },
                .gte => |v| {
                    const compiled = compileNumericValue(v) orelse {
                        self.bus.debug(TypedMatcherSkipped{ .matcher_idx = matcher_idx });
                        return;
                    };
                    if (matcher.negate) self.current_negated_count += 1 else self.current_positive_count += 1;
                    try self.typed_checks_list.append(self.allocator, .{
                        .policy_index = self.policy_index,
                        .field_ref = field_ref,
                        .matcher = .{ .gte = compiled },
                        .negate = matcher.negate,
                    });
                    return;
                },
                .lt => |v| {
                    const compiled = compileNumericValue(v) orelse {
                        self.bus.debug(TypedMatcherSkipped{ .matcher_idx = matcher_idx });
                        return;
                    };
                    if (matcher.negate) self.current_negated_count += 1 else self.current_positive_count += 1;
                    try self.typed_checks_list.append(self.allocator, .{
                        .policy_index = self.policy_index,
                        .field_ref = field_ref,
                        .matcher = .{ .lt = compiled },
                        .negate = matcher.negate,
                    });
                    return;
                },
                .lte => |v| {
                    const compiled = compileNumericValue(v) orelse {
                        self.bus.debug(TypedMatcherSkipped{ .matcher_idx = matcher_idx });
                        return;
                    };
                    if (matcher.negate) self.current_negated_count += 1 else self.current_positive_count += 1;
                    try self.typed_checks_list.append(self.allocator, .{
                        .policy_index = self.policy_index,
                        .field_ref = field_ref,
                        .matcher = .{ .lte = compiled },
                        .negate = matcher.negate,
                    });
                    return;
                },
                else => {},
            }

            const pattern, const match_type, const negate = switch (m) {
                .regex => |r| .{ r, MatchType.regex, matcher.negate },
                .exact => |e| .{ e, MatchType.exact, matcher.negate },
                .exists => unreachable,
                .starts_with => |s| .{ s, MatchType.starts_with, matcher.negate },
                .ends_with => |s| .{ s, MatchType.ends_with, matcher.negate },
                .contains => |s| .{ s, MatchType.contains, matcher.negate },
                .equals, .gt, .gte, .lt, .lte => unreachable,
            };

            if (pattern.len == 0) {
                self.bus.debug(MatcherEmptyRegex{ .matcher_idx = matcher_idx });
                return;
            }

            self.bus.debug(MatcherDetail{
                .matcher_idx = matcher_idx,
                .regex = pattern,
                .negate = negate,
            });

            const matcher_key = MatcherKeyT{ .field = field_ref };
            try self.addPattern(matcher_key, .{
                .pattern = pattern,
                .match_type = match_type,
                .case_insensitive = matcher.case_insensitive,
            }, negate, field_ref);
        }

        fn getFieldRef(matcher: *const MatcherT) ?FieldRefT {
            return switch (T) {
                .log => FieldRef.fromMatcherField(matcher.field),
                .metric => MetricFieldRef.fromMatcherField(matcher.field),
                .trace => TraceFieldRef.fromMatcherField(matcher.field),
            };
        }

        const PatternInfo = struct { pattern: []const u8, match_type: MatchType, case_insensitive: bool };

        fn addPattern(self: *Self, key: MatcherKeyT, info: PatternInfo, negate: bool, field_ref: FieldRefT) !void {
            if (negate) {
                self.current_negated_count += 1;
            } else {
                self.current_positive_count += 1;
            }

            const gop = try self.patterns_by_key.getOrPut(key);
            if (!gop.found_existing) {
                try self.dupeKeyIfNeeded(gop.key_ptr, field_ref);
                gop.value_ptr.* = .{ .positive = .empty, .negated = .empty, .exists = .empty };
            }

            const collector = PatternCollector{
                .policy_index = self.policy_index,
                .pattern = info.pattern,
                .match_type = info.match_type,
                .case_insensitive = info.case_insensitive,
            };
            if (negate) {
                try gop.value_ptr.negated.append(self.temp_allocator, collector);
            } else {
                try gop.value_ptr.positive.append(self.temp_allocator, collector);
            }
        }

        /// Register an exists matcher on the given key. Exists matchers
        /// contribute to required_match_count (and negated_count when
        /// `negate=true`) but are not compiled into Hyperscan; the engine
        /// dispatches them via `accessor.callExists` at scan time.
        fn addExists(self: *Self, key: MatcherKeyT, negate: bool, field_ref: FieldRefT) !void {
            if (negate) {
                self.current_negated_count += 1;
            } else {
                self.current_positive_count += 1;
            }

            const gop = try self.patterns_by_key.getOrPut(key);
            if (!gop.found_existing) {
                try self.dupeKeyIfNeeded(gop.key_ptr, field_ref);
                gop.value_ptr.* = .{ .positive = .empty, .negated = .empty, .exists = .empty };
            }

            try gop.value_ptr.exists.append(self.temp_allocator, .{
                .policy_index = self.policy_index,
                .negate = negate,
            });
        }

        fn dupeKeyIfNeeded(self: *Self, key_ptr: *MatcherKeyT, field_ref: FieldRefT) !void {
            const path = field_ref.getPath();
            if (path.len == 0) return;

            // Dupe each segment of the path
            const path_copy = try self.allocator.alloc([]const u8, path.len);
            errdefer self.allocator.free(path_copy);

            for (path, 0..) |segment, i| {
                path_copy[i] = try self.allocator.dupe(u8, segment);
            }

            try self.path_storage.append(self.allocator, path_copy);

            // Update the key's field to point to the duped path
            key_ptr.field = dupeFieldRef(FieldRefT, field_ref, path_copy);
        }

        fn dupeFieldRef(comptime FieldRefTT: type, field_ref: FieldRefTT, path_copy: []const []const u8) FieldRefTT {
            // Create an AttributePath with the copied path segments
            // Cast is safe because we own these allocations and they won't be mutated
            const attr_path = AttributePath{ .path = .{ .items = @constCast(path_copy), .capacity = path_copy.len } };

            switch (T) {
                .log => return switch (field_ref) {
                    .log_attribute => .{ .log_attribute = attr_path },
                    .resource_attribute => .{ .resource_attribute = attr_path },
                    .scope_attribute => .{ .scope_attribute = attr_path },
                    .log_field => field_ref,
                },
                .metric => return switch (field_ref) {
                    .datapoint_attribute => .{ .datapoint_attribute = attr_path },
                    .resource_attribute => .{ .resource_attribute = attr_path },
                    .scope_attribute => .{ .scope_attribute = attr_path },
                    .metric_field, .metric_type, .aggregation_temporality => field_ref,
                },
                .trace => return switch (field_ref) {
                    .span_attribute => .{ .span_attribute = attr_path },
                    .resource_attribute => .{ .resource_attribute = attr_path },
                    .scope_attribute => .{ .scope_attribute = attr_path },
                    .event_attribute => .{ .event_attribute = attr_path },
                    // These fields use []const u8, not AttributePath
                    .event_name => .{ .event_name = if (path_copy.len > 0) path_copy[0] else "" },
                    .link_trace_id => .{ .link_trace_id = if (path_copy.len > 0) path_copy[0] else "" },
                    .trace_field, .span_kind, .span_status => field_ref,
                },
            }
        }

        fn storePolicyInfo(self: *Self, policy: *const Policy, target: *const TargetT, keep: KeepValue, global_index: PolicyIndex) !void {
            const policy_id_copy = try self.allocator.dupe(u8, policy.id);
            try self.policy_id_storage.append(self.allocator, policy_id_copy);

            // Create rate limiter for rate limit policies
            const rate_limiter: ?*RateLimiter = switch (keep) {
                .per_second => |rl_params| blk: {
                    const rl = try self.allocator.create(RateLimiter);
                    rl.* = RateLimiter.init(self.bus.io, rl_params.count, rl_params.duration * 1_000);
                    break :blk rl;
                },
                .per_minute => |rl_params| blk: {
                    const rl = try self.allocator.create(RateLimiter);
                    rl.* = RateLimiter.init(self.bus.io, rl_params.count, rl_params.duration * 60_000);
                    break :blk rl;
                },
                else => null,
            };

            // Extract sample_key for log policies
            const sample_key: ?LogSampleKey = if (T == .log) target.sample_key else null;

            // Build probabilistic sampler for percentage-based policies
            const sampler: ?ProbabilisticSampler = switch (keep) {
                .percentage => |pct| if (T == .trace) blk: {
                    // Traces: init from TraceSamplingConfig (has mode, hash_seed, etc.)
                    if (target.keep) |*keep_config| {
                        break :blk ProbabilisticSampler.init(keep_config);
                    }
                    break :blk ProbabilisticSampler.init(null);
                } else ProbabilisticSampler.initFromPercentage(pct),
                else => null,
            };

            // Compile regex-based redact rules for log policies. Delegated
            // to `log_transform.compileRedactRules` so the cleanup path lives
            // in one place; on success this returns a slice of
            // `{rule, compiled}` pairs keyed structurally to the rule list.
            const compiled_redacts: []log_transform.CompiledRedact = if (T == .log) blk: {
                const transform = target.transform orelse break :blk &.{};
                break :blk log_transform.compileRedactRules(self.allocator, &transform) catch |err| {
                    self.bus.warn(MatcherEmptyRegex{ .matcher_idx = 0 });
                    return err;
                };
            } else &.{};
            errdefer log_transform.deinitCompiledRedacts(self.allocator, compiled_redacts);

            try self.policy_info_list.append(self.temp_allocator, .{
                .id = policy_id_copy,
                .index = self.policy_index,
                .stats_index = global_index,
                .required_match_count = self.current_positive_count + self.current_negated_count,
                .negated_count = self.current_negated_count,
                .keep = keep,
                .enabled = policy.enabled,
                .rate_limiter = rate_limiter,
                .sample_key = sample_key,
                .sampler = sampler,
                .compiled_redacts = compiled_redacts,
            });

            self.bus.debug(PolicyStored{
                .id = policy.id,
                .index = self.policy_index,
                .required_matches = self.current_positive_count,
                .negated_count = self.current_negated_count,
            });

            self.policy_index += 1;
        }

        fn finish(self: *Self) !IndexT {
            const policies = try self.allocator.dupe(PolicyInfo, self.policy_info_list.items);

            var negation_indices = std.ArrayListUnmanaged(PolicyIndex).empty;
            for (policies) |p| {
                if (p.negated_count > 0) {
                    try negation_indices.append(self.temp_allocator, p.index);
                }
            }
            const policies_with_negation = try self.allocator.dupe(PolicyIndex, negation_indices.items);

            var databases = std.HashMap(MatcherKeyT, *MatcherDatabase, HashContextT, std.hash_map.default_max_load_percentage).init(self.allocator);
            var keys_list = std.ArrayListUnmanaged(MatcherKeyT).empty;

            var key_it = self.patterns_by_key.iterator();
            while (key_it.next()) |entry| {
                const matcher_key = entry.key_ptr.*;
                const patterns = entry.value_ptr.*;

                // Skip keys that ended up with nothing wired (defensive — the
                // builder only inserts a key when adding a pattern or exists).
                if (patterns.positive.items.len == 0 and
                    patterns.negated.items.len == 0 and
                    patterns.exists.items.len == 0) continue;

                // Only compile a Hyperscan DB when there are value-match
                // patterns. Exists-only keys live in `matcher_keys` without
                // a corresponding database entry.
                const has_value_db = patterns.positive.items.len > 0 or patterns.negated.items.len > 0;
                if (has_value_db) {
                    const db = try compileDatabase(self.allocator, self.bus, patterns.positive.items, patterns.negated.items);
                    try databases.put(matcher_key, db);
                }

                // Materialize exists entries into long-lived storage; the
                // temp_allocator-backed list is dropped at builder end.
                const exists_entries: []const ExistsEntry = if (patterns.exists.items.len == 0)
                    &.{}
                else
                    try self.allocator.dupe(ExistsEntry, patterns.exists.items);

                try keys_list.append(self.temp_allocator, .{
                    .field = matcher_key.field,
                    .exists_entries = exists_entries,
                    .has_value_db = has_value_db,
                });
            }

            const matcher_keys = try self.allocator.dupe(MatcherKeyT, keys_list.items);
            const typed_checks = try self.allocator.dupe(TypedCheckT, self.typed_checks_list.items);
            // Free the builder's backing storage; the items are now in `typed_checks`.
            self.typed_checks_list.deinit(self.allocator);

            return IndexT{
                .allocator = self.allocator,
                .databases = databases,
                .policies = policies,
                .policies_with_negation = policies_with_negation,
                .matcher_keys = matcher_keys,
                .typed_checks = typed_checks,
                .path_storage = self.path_storage,
                .policy_id_storage = self.policy_id_storage,
                .bus = self.bus,
            };
        }
    };
}

// =============================================================================
// LogMatcherIndex - Index for log policies only
// =============================================================================

pub const LogMatcherIndex = struct {
    allocator: std.mem.Allocator,
    databases: std.HashMap(LogMatcherKey, *MatcherDatabase, LogMatcherKeyContext, std.hash_map.default_max_load_percentage),
    policies: []PolicyInfo,
    policies_with_negation: []PolicyIndex,
    matcher_keys: []LogMatcherKey,
    typed_checks: []TypedCheckType(.log),
    path_storage: std.ArrayListUnmanaged([]const []const u8),
    policy_id_storage: std.ArrayListUnmanaged([]const u8),
    bus: *EventBus,

    const Self = @This();

    pub fn build(allocator: std.mem.Allocator, bus: *EventBus, policies_slice: []const Policy) !Self {
        var span = bus.started(.info, MatcherIndexBuildStarted{ .policy_count = policies_slice.len, .telemetry_type = .log });

        if (policies_slice.len > MAX_POLICIES) {
            return error.TooManyPolicies;
        }

        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();

        var builder = IndexBuilder(.log).init(allocator, arena.allocator(), bus);

        for (policies_slice, 0..) |*policy, i| {
            try builder.processPolicy(policy, @intCast(i));
        }

        var index = try builder.finish();

        span.completed(MatcherIndexBuildCompleted{
            .database_count = index.databases.count(),
            .matcher_key_count = index.matcher_keys.len,
            .policy_count = index.policies.len,
        });

        return index;
    }

    pub fn getDatabase(self: *const Self, key: LogMatcherKey) ?*MatcherDatabase {
        return self.databases.get(key);
    }

    pub fn getPolicyByIndex(self: *const Self, index: PolicyIndex) ?PolicyInfo {
        if (index >= self.policies.len) return null;
        return self.policies[index];
    }

    pub fn getPolicy(self: *const Self, id: []const u8) ?PolicyInfo {
        for (self.policies) |info| {
            if (std.mem.eql(u8, info.id, id)) return info;
        }
        return null;
    }

    pub fn getMatcherKeys(self: *const Self) []const LogMatcherKey {
        return self.matcher_keys;
    }

    pub fn getPolicies(self: *const Self) []const PolicyInfo {
        return self.policies;
    }

    pub fn getPoliciesWithNegation(self: *const Self) []const PolicyIndex {
        return self.policies_with_negation;
    }

    pub fn getTypedChecks(self: *const Self) []const TypedCheckType(.log) {
        return self.typed_checks;
    }

    pub fn isEmpty(self: *const Self) bool {
        return self.matcher_keys.len == 0 and self.typed_checks.len == 0;
    }

    pub fn getDatabaseCount(self: *const Self) usize {
        return self.databases.count();
    }

    pub fn getPolicyCount(self: *const Self) usize {
        return self.policies.len;
    }

    pub fn deinit(self: *Self) void {
        var db_it = self.databases.valueIterator();
        while (db_it.next()) |db| {
            db.*.deinit();
            self.allocator.destroy(db.*);
        }
        self.databases.deinit();

        // Free rate limiters and compiled redacts
        for (self.policies) |*policy_info| {
            if (policy_info.rate_limiter) |rl| {
                self.allocator.destroy(rl);
            }
            if (policy_info.compiled_redacts.len > 0) {
                log_transform.deinitCompiledRedacts(self.allocator, policy_info.compiled_redacts);
            }
        }
        self.allocator.free(self.policies);
        self.allocator.free(self.policies_with_negation);
        for (self.matcher_keys) |key| {
            if (key.exists_entries.len > 0) self.allocator.free(key.exists_entries);
        }
        self.allocator.free(self.matcher_keys);

        // Free bytes owned by typed checks
        for (self.typed_checks) |check| {
            if (check.matcher == .equals) {
                if (check.matcher.equals == .bytes) {
                    self.allocator.free(check.matcher.equals.bytes);
                }
            }
        }
        self.allocator.free(self.typed_checks);

        for (self.path_storage.items) |path| {
            for (path) |segment| {
                self.allocator.free(segment);
            }
            self.allocator.free(path);
        }
        self.path_storage.deinit(self.allocator);

        for (self.policy_id_storage.items) |id| {
            self.allocator.free(id);
        }
        self.policy_id_storage.deinit(self.allocator);
    }
};

// =============================================================================
// MetricMatcherIndex - Index for metric policies only
// =============================================================================

pub const MetricMatcherIndex = struct {
    allocator: std.mem.Allocator,
    databases: std.HashMap(MetricMatcherKey, *MatcherDatabase, MetricMatcherKeyContext, std.hash_map.default_max_load_percentage),
    policies: []PolicyInfo,
    policies_with_negation: []PolicyIndex,
    matcher_keys: []MetricMatcherKey,
    typed_checks: []TypedCheckType(.metric),
    path_storage: std.ArrayListUnmanaged([]const []const u8),
    policy_id_storage: std.ArrayListUnmanaged([]const u8),
    bus: *EventBus,

    const Self = @This();

    pub fn build(allocator: std.mem.Allocator, bus: *EventBus, policies_slice: []const Policy) !Self {
        var span = bus.started(.info, MatcherIndexBuildStarted{ .policy_count = policies_slice.len, .telemetry_type = .metric });

        if (policies_slice.len > MAX_POLICIES) {
            return error.TooManyPolicies;
        }

        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();

        var builder = IndexBuilder(.metric).init(allocator, arena.allocator(), bus);

        for (policies_slice, 0..) |*policy, i| {
            try builder.processPolicy(policy, @intCast(i));
        }

        var index = try builder.finish();

        span.completed(MatcherIndexBuildCompleted{
            .database_count = index.databases.count(),
            .matcher_key_count = index.matcher_keys.len,
            .policy_count = index.policies.len,
        });

        return index;
    }

    pub fn getDatabase(self: *const Self, key: MetricMatcherKey) ?*MatcherDatabase {
        return self.databases.get(key);
    }

    pub fn getPolicyByIndex(self: *const Self, index: PolicyIndex) ?PolicyInfo {
        if (index >= self.policies.len) return null;
        return self.policies[index];
    }

    pub fn getPolicy(self: *const Self, id: []const u8) ?PolicyInfo {
        for (self.policies) |info| {
            if (std.mem.eql(u8, info.id, id)) return info;
        }
        return null;
    }

    pub fn getMatcherKeys(self: *const Self) []const MetricMatcherKey {
        return self.matcher_keys;
    }

    pub fn getPolicies(self: *const Self) []const PolicyInfo {
        return self.policies;
    }

    pub fn getPoliciesWithNegation(self: *const Self) []const PolicyIndex {
        return self.policies_with_negation;
    }

    pub fn getTypedChecks(self: *const Self) []const TypedCheckType(.metric) {
        return self.typed_checks;
    }

    pub fn isEmpty(self: *const Self) bool {
        return self.matcher_keys.len == 0 and self.typed_checks.len == 0;
    }

    pub fn getDatabaseCount(self: *const Self) usize {
        return self.databases.count();
    }

    pub fn getPolicyCount(self: *const Self) usize {
        return self.policies.len;
    }

    pub fn deinit(self: *Self) void {
        var db_it = self.databases.valueIterator();
        while (db_it.next()) |db| {
            db.*.deinit();
            self.allocator.destroy(db.*);
        }
        self.databases.deinit();

        for (self.policies) |policy_info| {
            if (policy_info.rate_limiter) |rl| {
                self.allocator.destroy(rl);
            }
        }
        self.allocator.free(self.policies);
        self.allocator.free(self.policies_with_negation);
        for (self.matcher_keys) |key| {
            if (key.exists_entries.len > 0) self.allocator.free(key.exists_entries);
        }
        self.allocator.free(self.matcher_keys);

        for (self.typed_checks) |check| {
            if (check.matcher == .equals) {
                if (check.matcher.equals == .bytes) {
                    self.allocator.free(check.matcher.equals.bytes);
                }
            }
        }
        self.allocator.free(self.typed_checks);

        for (self.path_storage.items) |path| {
            for (path) |segment| {
                self.allocator.free(segment);
            }
            self.allocator.free(path);
        }
        self.path_storage.deinit(self.allocator);

        for (self.policy_id_storage.items) |id| {
            self.allocator.free(id);
        }
        self.policy_id_storage.deinit(self.allocator);
    }
};

// =============================================================================
// TraceMatcherIndex - Index for trace policies only (OTLP traces)
// =============================================================================

pub const TraceMatcherIndex = struct {
    allocator: std.mem.Allocator,
    databases: std.HashMap(TraceMatcherKey, *MatcherDatabase, TraceMatcherKeyContext, std.hash_map.default_max_load_percentage),
    policies: []PolicyInfo,
    policies_with_negation: []PolicyIndex,
    matcher_keys: []TraceMatcherKey,
    typed_checks: []TypedCheckType(.trace),
    path_storage: std.ArrayListUnmanaged([]const []const u8),
    policy_id_storage: std.ArrayListUnmanaged([]const u8),
    bus: *EventBus,

    const Self = @This();

    pub fn build(allocator: std.mem.Allocator, bus: *EventBus, policies_slice: []const Policy) !Self {
        var span = bus.started(.info, MatcherIndexBuildStarted{ .policy_count = policies_slice.len, .telemetry_type = .trace });

        if (policies_slice.len > MAX_POLICIES) {
            return error.TooManyPolicies;
        }

        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();

        var builder = IndexBuilder(.trace).init(allocator, arena.allocator(), bus);

        for (policies_slice, 0..) |*policy, i| {
            try builder.processPolicy(policy, @intCast(i));
        }

        var index = try builder.finish();

        span.completed(MatcherIndexBuildCompleted{
            .database_count = index.databases.count(),
            .matcher_key_count = index.matcher_keys.len,
            .policy_count = index.policies.len,
        });

        return index;
    }

    pub fn getDatabase(self: *const Self, key: TraceMatcherKey) ?*MatcherDatabase {
        return self.databases.get(key);
    }

    pub fn getPolicyByIndex(self: *const Self, index: PolicyIndex) ?PolicyInfo {
        if (index >= self.policies.len) return null;
        return self.policies[index];
    }

    pub fn getPolicy(self: *const Self, id: []const u8) ?PolicyInfo {
        for (self.policies) |info| {
            if (std.mem.eql(u8, info.id, id)) return info;
        }
        return null;
    }

    pub fn getMatcherKeys(self: *const Self) []const TraceMatcherKey {
        return self.matcher_keys;
    }

    pub fn getPolicies(self: *const Self) []const PolicyInfo {
        return self.policies;
    }

    pub fn getPoliciesWithNegation(self: *const Self) []const PolicyIndex {
        return self.policies_with_negation;
    }

    pub fn getTypedChecks(self: *const Self) []const TypedCheckType(.trace) {
        return self.typed_checks;
    }

    pub fn isEmpty(self: *const Self) bool {
        return self.matcher_keys.len == 0 and self.typed_checks.len == 0;
    }

    pub fn getDatabaseCount(self: *const Self) usize {
        return self.databases.count();
    }

    pub fn getPolicyCount(self: *const Self) usize {
        return self.policies.len;
    }

    pub fn deinit(self: *Self) void {
        var db_it = self.databases.valueIterator();
        while (db_it.next()) |db| {
            db.*.deinit();
            self.allocator.destroy(db.*);
        }
        self.databases.deinit();

        for (self.policies) |policy_info| {
            if (policy_info.rate_limiter) |rl| {
                self.allocator.destroy(rl);
            }
        }
        self.allocator.free(self.policies);
        self.allocator.free(self.policies_with_negation);
        for (self.matcher_keys) |key| {
            if (key.exists_entries.len > 0) self.allocator.free(key.exists_entries);
        }
        self.allocator.free(self.matcher_keys);

        for (self.typed_checks) |check| {
            if (check.matcher == .equals) {
                if (check.matcher.equals == .bytes) {
                    self.allocator.free(check.matcher.equals.bytes);
                }
            }
        }
        self.allocator.free(self.typed_checks);

        for (self.path_storage.items) |path| {
            for (path) |segment| {
                self.allocator.free(segment);
            }
            self.allocator.free(path);
        }
        self.path_storage.deinit(self.allocator);

        for (self.policy_id_storage.items) |id| {
            self.allocator.free(id);
        }
        self.policy_id_storage.deinit(self.allocator);
    }
};

// =============================================================================
// Database Compilation
// =============================================================================

fn compileDatabase(
    allocator: std.mem.Allocator,
    bus: *EventBus,
    positive_collectors: []const PatternCollector,
    negated_collectors: []const PatternCollector,
) !*MatcherDatabase {
    var positive_db: ?hyperscan.Database = null;
    var negated_db: ?hyperscan.Database = null;
    var scratch_pool: [MatcherDatabase.SCRATCH_POOL_SIZE]?hyperscan.Scratch = .{null} ** MatcherDatabase.SCRATCH_POOL_SIZE;

    errdefer {
        for (&scratch_pool) |*s| {
            if (s.*) |*scratch| scratch.deinit();
        }
        if (positive_db) |*db| db.deinit();
        if (negated_db) |*db| db.deinit();
    }

    var positive_patterns: []PatternMeta = &.{};
    if (positive_collectors.len > 0) {
        const result = try compilePatterns(allocator, positive_collectors);
        positive_db = result.db;
        positive_patterns = result.meta;
    }

    var negated_patterns: []PatternMeta = &.{};
    if (negated_collectors.len > 0) {
        const result = try compilePatterns(allocator, negated_collectors);
        negated_db = result.db;
        negated_patterns = result.meta;
    }

    if (positive_db) |*db| {
        scratch_pool[0] = try hyperscan.Scratch.init(db);
        if (negated_db) |*ndb| {
            _ = try hyperscan.Scratch.init(ndb);
        }
    } else if (negated_db) |*db| {
        scratch_pool[0] = try hyperscan.Scratch.init(db);
    }

    // Clone scratch into remaining pool slots for concurrent access
    if (scratch_pool[0]) |*base| {
        for (1..MatcherDatabase.SCRATCH_POOL_SIZE) |i| {
            scratch_pool[i] = try base.clone();
        }
    }

    var scratch_locks: [MatcherDatabase.SCRATCH_POOL_SIZE]std.atomic.Value(bool) = undefined;
    for (&scratch_locks) |*lock| lock.* = std.atomic.Value(bool).init(false);

    const matcher_db = try allocator.create(MatcherDatabase);
    matcher_db.* = .{
        .positive_db = positive_db,
        .negated_db = negated_db,
        .scratch_pool = scratch_pool,
        .scratch_locks = scratch_locks,
        .next_scratch = std.atomic.Value(usize).init(0),
        .positive_patterns = positive_patterns,
        .negated_patterns = negated_patterns,
        .allocator = allocator,
        .bus = bus,
    };

    return matcher_db;
}

fn compilePatterns(allocator: std.mem.Allocator, collectors: []const PatternCollector) !struct { db: hyperscan.Database, meta: []PatternMeta } {
    // Calculate buffer size: max len+2 per pattern (for anchors).
    // Exists matchers never enter Hyperscan — they are dispatched separately
    // by the engine via accessor.callExists.
    var buf_size: usize = 0;
    for (collectors) |c| {
        buf_size += switch (c.match_type) {
            .regex, .contains => 0,
            .exact => c.pattern.len + 2,
            .starts_with, .ends_with => c.pattern.len + 1,
            .exists => unreachable,
            .equals, .gt, .gte, .lt, .lte => unreachable, // typed matchers never reach Hyperscan
        };
    }

    // Single allocation for hs_patterns + pattern buffer
    const hs_size = collectors.len * @sizeOf(hyperscan.Pattern);
    const temp = try allocator.alloc(u8, hs_size + buf_size);
    defer allocator.free(temp);

    const hs_patterns: []hyperscan.Pattern = @alignCast(std.mem.bytesAsSlice(hyperscan.Pattern, temp[0..hs_size]));
    var buf = temp[hs_size..];

    const meta = try allocator.alloc(PatternMeta, collectors.len);
    errdefer allocator.free(meta);

    for (collectors, 0..) |c, i| {
        hs_patterns[i] = .{
            .expression = formatPattern(&buf, c.pattern, c.match_type),
            .id = @intCast(i),
            .flags = .{ .caseless = c.case_insensitive, .single_match = true },
        };
        meta[i] = .{ .policy_index = c.policy_index };
    }

    const db = try hyperscan.Database.compileMulti(allocator, hs_patterns, .{});
    return .{ .db = db, .meta = meta };
}

fn formatPattern(buf: *[]u8, pattern: []const u8, match_type: MatchType) []const u8 {
    const anchor_start, const anchor_end = switch (match_type) {
        .regex => return pattern,
        .exact => .{ true, true },
        .starts_with => .{ true, false },
        .ends_with => .{ false, true },
        .contains => return pattern,
        .exists => unreachable, // exists is dispatched outside the Hyperscan path
        .equals, .gt, .gte, .lt, .lte => unreachable, // typed matchers never reach Hyperscan
    };

    const out = std.fmt.bufPrint(buf.*, "{s}{s}{s}", .{
        if (anchor_start) "^" else "",
        pattern,
        if (anchor_end) "$" else "",
    }) catch unreachable;

    buf.* = buf.*[out.len..];
    return out;
}

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;

test "LogMatcherKey: hash and equality" {
    const key1 = LogMatcherKey{ .field = .{ .log_field = .LOG_FIELD_BODY } };
    const key2 = LogMatcherKey{ .field = .{ .log_field = .LOG_FIELD_BODY } };
    const key3 = LogMatcherKey{ .field = .{ .log_field = .LOG_FIELD_SEVERITY_TEXT } };
    const key4 = LogMatcherKey{ .field = .{ .log_attribute = .{ .path = .{ .items = @constCast(&[_][]const u8{"service"}), .capacity = 1 } } } };
    const key5 = LogMatcherKey{ .field = .{ .log_attribute = .{ .path = .{ .items = @constCast(&[_][]const u8{"service"}), .capacity = 1 } } } };
    const key6 = LogMatcherKey{ .field = .{ .log_attribute = .{ .path = .{ .items = @constCast(&[_][]const u8{"env"}), .capacity = 1 } } } };

    try testing.expect(key1.eql(key2));
    try testing.expect(key4.eql(key5));
    try testing.expect(!key1.eql(key3));
    try testing.expect(!key4.eql(key6));
    try testing.expectEqual(key1.hash(), key2.hash());
    try testing.expectEqual(key4.hash(), key5.hash());

    // Test nested paths
    const key7 = LogMatcherKey{ .field = .{ .log_attribute = .{ .path = .{ .items = @constCast(&[_][]const u8{ "http", "method" }), .capacity = 2 } } } };
    const key8 = LogMatcherKey{ .field = .{ .log_attribute = .{ .path = .{ .items = @constCast(&[_][]const u8{ "http", "method" }), .capacity = 2 } } } };
    const key9 = LogMatcherKey{ .field = .{ .log_attribute = .{ .path = .{ .items = @constCast(&[_][]const u8{ "http", "status" }), .capacity = 2 } } } };

    try testing.expect(key7.eql(key8));
    try testing.expect(!key7.eql(key9));
    try testing.expectEqual(key7.hash(), key8.hash());
}

test "MetricMatcherKey: hash and equality" {
    const key1 = MetricMatcherKey{ .field = .{ .metric_field = .METRIC_FIELD_NAME } };
    const key2 = MetricMatcherKey{ .field = .{ .metric_field = .METRIC_FIELD_NAME } };
    const key3 = MetricMatcherKey{ .field = .{ .metric_field = .METRIC_FIELD_UNIT } };
    const key4 = MetricMatcherKey{ .field = .{ .datapoint_attribute = .{ .path = .{ .items = @constCast(&[_][]const u8{"status"}), .capacity = 1 } } } };
    const key5 = MetricMatcherKey{ .field = .{ .datapoint_attribute = .{ .path = .{ .items = @constCast(&[_][]const u8{"status"}), .capacity = 1 } } } };
    const key6 = MetricMatcherKey{ .field = .{ .datapoint_attribute = .{ .path = .{ .items = @constCast(&[_][]const u8{"env"}), .capacity = 1 } } } };

    try testing.expect(key1.eql(key2));
    try testing.expect(key4.eql(key5));
    try testing.expect(!key1.eql(key3));
    try testing.expect(!key4.eql(key6));
    try testing.expectEqual(key1.hash(), key2.hash());
    try testing.expectEqual(key4.hash(), key5.hash());
}

test "FieldRef: isKeyed" {
    const log_field = FieldRef{ .log_field = .LOG_FIELD_BODY };
    const log_attr = FieldRef{ .log_attribute = .{ .path = .{ .items = @constCast(&[_][]const u8{"service"}), .capacity = 1 } } };
    const resource_attr = FieldRef{ .resource_attribute = .{ .path = .{ .items = @constCast(&[_][]const u8{"env"}), .capacity = 1 } } };

    try testing.expect(!log_field.isKeyed());
    try testing.expect(log_attr.isKeyed());
    try testing.expect(resource_attr.isKeyed());
}

test "KeepValue: parse" {
    try testing.expectEqual(KeepValue.all, KeepValue.parse(""));
    try testing.expectEqual(KeepValue.all, KeepValue.parse("all"));
    try testing.expectEqual(KeepValue.none, KeepValue.parse("none"));
    try testing.expectEqual(KeepValue{ .percentage = 50 }, KeepValue.parse("50%"));
    // Backwards-compatible: N/s and N/m (duration=1)
    try testing.expectEqual(KeepValue{ .per_second = .{ .count = 100, .duration = 1 } }, KeepValue.parse("100/s"));
    try testing.expectEqual(KeepValue{ .per_minute = .{ .count = 1000, .duration = 1 } }, KeepValue.parse("1000/m"));
    // Arbitrary duration: N/Ds and N/Dm
    try testing.expectEqual(KeepValue{ .per_second = .{ .count = 1, .duration = 5 } }, KeepValue.parse("1/5s"));
    try testing.expectEqual(KeepValue{ .per_second = .{ .count = 1, .duration = 300 } }, KeepValue.parse("1/300s"));
    try testing.expectEqual(KeepValue{ .per_minute = .{ .count = 10, .duration = 5 } }, KeepValue.parse("10/5m"));
    // Invalid formats fall back to .all
    try testing.expectEqual(KeepValue.all, KeepValue.parse("1/0s")); // zero duration
    try testing.expectEqual(KeepValue.all, KeepValue.parse("1/x")); // invalid unit
    try testing.expectEqual(KeepValue.all, KeepValue.parse("/s")); // missing count
    try testing.expectEqual(KeepValue.all, KeepValue.parse("abc/5s")); // non-integer count
    try testing.expectEqual(KeepValue.all, KeepValue.parse("1/abcs")); // non-integer duration
}

test "KeepValue: rate-limit duration is clamped to avoid u32 ms-overflow" {
    // 5_000_000 minutes would translate to 3e11 ms — overflows u32 when
    // multiplied by 60_000 in storePolicyInfo. The parser clamps to
    // MAX_RATE_LIMIT_DURATION_MINUTES.
    const huge_min = KeepValue.parse("10/5000000m");
    try testing.expect(huge_min == .per_minute);
    try testing.expect(huge_min.per_minute.duration <= KeepValue.MAX_RATE_LIMIT_DURATION_MINUTES);

    // 5_000_000_000 seconds would similarly overflow when ×1_000.
    const huge_sec = KeepValue.parse("10/5000000000s");
    try testing.expect(huge_sec == .all or huge_sec.per_second.duration <= KeepValue.MAX_RATE_LIMIT_DURATION_SECONDS);

    // u32::MAX exactly. Either rejected via parseInt or clamped — either is fine.
    const u32_max = KeepValue.parse("10/4294967295s");
    try testing.expect(u32_max == .all or u32_max.per_second.duration <= KeepValue.MAX_RATE_LIMIT_DURATION_SECONDS);
}

test "KeepValue: restrictiveness comparison" {
    const all: KeepValue = .all;
    const none: KeepValue = .none;
    const pct50: KeepValue = .{ .percentage = 50 };
    const pct25: KeepValue = .{ .percentage = 25 };
    const rate: KeepValue = .{ .per_second = .{ .count = 100, .duration = 1 } };

    try testing.expect(none.isMoreRestrictiveThan(all));
    try testing.expect(none.isMoreRestrictiveThan(pct50));
    try testing.expect(pct50.isMoreRestrictiveThan(all));
    try testing.expect(pct25.isMoreRestrictiveThan(pct50));
    try testing.expect(!all.isMoreRestrictiveThan(rate));
}

test "LogMatcherIndex: build empty" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    var index = try LogMatcherIndex.build(allocator, noop_bus.eventBus(), &.{});
    defer index.deinit();

    try testing.expect(index.isEmpty());
    try testing.expectEqual(@as(usize, 0), index.getPolicyCount());
}

test "MetricMatcherIndex: build empty" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    var index = try MetricMatcherIndex.build(allocator, noop_bus.eventBus(), &.{});
    defer index.deinit();

    try testing.expect(index.isEmpty());
    try testing.expectEqual(@as(usize, 0), index.getPolicyCount());
}

test "LogMatcherIndex: build with single policy" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "test-policy"),
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

    var index = try LogMatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    try testing.expect(!index.isEmpty());
    try testing.expectEqual(@as(usize, 1), index.getDatabaseCount());
    try testing.expectEqual(@as(usize, 1), index.getPolicyCount());

    const policy_info = index.getPolicyByIndex(0);
    try testing.expect(policy_info != null);
    try testing.expectEqual(KeepValue.none, policy_info.?.keep);
    try testing.expectEqual(@as(u16, 1), policy_info.?.required_match_count);

    const policy_info_by_id = index.getPolicy("policy-1");
    try testing.expect(policy_info_by_id != null);
    try testing.expectEqualStrings("policy-1", policy_info_by_id.?.id);
}

test "MetricMatcherIndex: build with single policy" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    var policy = Policy{
        .id = try allocator.dupe(u8, "metric-policy-1"),
        .name = try allocator.dupe(u8, "test-metric-policy"),
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

    var index = try MetricMatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    try testing.expect(!index.isEmpty());
    try testing.expectEqual(@as(usize, 1), index.getDatabaseCount());
    try testing.expectEqual(@as(usize, 1), index.getPolicyCount());

    const policy_info = index.getPolicyByIndex(0);
    try testing.expect(policy_info != null);
    try testing.expectEqual(KeepValue.none, policy_info.?.keep);
}

test "LogMatcherIndex: build with keyed matchers" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "test-policy"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "all"),
        } },
    };
    // Create AttributePath with "service" as single path segment
    var attr_path = proto.policy.AttributePath{};
    try attr_path.path.append(allocator, try allocator.dupe(u8, "service"));
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_attribute = attr_path },
        .match = .{ .regex = try allocator.dupe(u8, "payment-api") },
    });
    defer policy.deinit(allocator);

    var index = try LogMatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    try testing.expect(!index.isEmpty());

    const expected_key = LogMatcherKey{ .field = .{ .log_attribute = .{ .path = .{ .items = @constCast(&[_][]const u8{"service"}), .capacity = 1 } } } };
    const db = index.getDatabase(expected_key);
    try testing.expect(db != null);
}

test "LogMatcherIndex: negated matcher creates negated database" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "test-policy"),
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

    var index = try LogMatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    try testing.expect(!index.isEmpty());

    const expected_key = LogMatcherKey{ .field = .{ .log_field = .LOG_FIELD_BODY } };
    const db = index.getDatabase(expected_key);
    try testing.expect(db != null);
    try testing.expect(db.?.negated_db != null);
    try testing.expect(db.?.positive_db == null);
}

test "LogMatcherIndex: scan database" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "test-policy"),
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

    var index = try LogMatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    const db = index.getDatabase(.{ .field = .{ .log_field = .LOG_FIELD_BODY } });
    try testing.expect(db != null);

    var result_buf: [256]u32 = undefined;

    const match_result = db.?.scanPositive("an error occurred", &result_buf);
    try testing.expectEqual(@as(usize, 1), match_result.count);
    try testing.expectEqual(@as(u32, 0), match_result.matches()[0]);

    const no_match_result = db.?.scanPositive("everything is fine", &result_buf);
    try testing.expectEqual(@as(usize, 0), no_match_result.count);
}

test "LogMatcherIndex: exists=true matcher is bucketed into exists_entries" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "test-policy"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "all"),
        } },
    };
    var attr_path = AttributePath{};
    try attr_path.path.append(allocator, try allocator.dupe(u8, "trace_id"));
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_attribute = attr_path },
        .match = .{ .exists = true },
    });
    defer policy.deinit(allocator);

    var index = try LogMatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    // exists matchers no longer compile to Hyperscan patterns; they live in
    // the matcher key's exists_entries slice and are dispatched by the engine
    // via accessor.callExists.
    try testing.expect(!index.isEmpty());
    try testing.expectEqual(@as(usize, 1), index.getPolicyCount());

    const keys = index.getMatcherKeys();
    try testing.expectEqual(@as(usize, 1), keys.len);
    try testing.expectEqual(@as(usize, 1), keys[0].exists_entries.len);
    try testing.expect(!keys[0].exists_entries[0].negate);

    // No Hyperscan database is compiled for an exists-only key.
    try testing.expect(index.getDatabase(keys[0]) == null);
    try testing.expectEqual(@as(usize, 0), index.getDatabaseCount());
}

test "LogMatcherIndex: exists=false matcher creates negated pattern" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "test-policy"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "all"),
        } },
    };
    // Create AttributePath with "trace_id" as single path segment
    var attr_path = AttributePath{};
    try attr_path.path.append(allocator, try allocator.dupe(u8, "trace_id"));
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_attribute = attr_path },
        .match = .{ .exists = false },
    });
    defer policy.deinit(allocator);

    var index = try LogMatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    // exists=false lives in exists_entries with negate=true; no Hyperscan DB.
    try testing.expect(!index.isEmpty());
    try testing.expectEqual(@as(usize, 1), index.getPolicyCount());

    const keys = index.getMatcherKeys();
    try testing.expectEqual(@as(usize, 1), keys.len);
    try testing.expectEqual(@as(usize, 1), keys[0].exists_entries.len);
    try testing.expect(keys[0].exists_entries[0].negate);
    try testing.expect(index.getDatabase(keys[0]) == null);
}

test "MetricMatcherIndex: metric_type with null match (implicit exists)" {
    // When policies arrive via HTTP sync, the Go server leaves match=null
    // for enum-type fields like metric_type. The matcher index should treat
    // this as an implicit exists=true, matching the Go engine behavior.
    const allocator = testing.allocator;

    var noop_bus: o11y.NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    const policy = Policy{
        .id = "drop-gauges",
        .name = "Drop gauge metrics",
        .enabled = true,
        .target = .{
            .metric = .{
                .match = .{
                    .items = @constCast(&[_]MetricMatcher{
                        .{
                            .field = .{ .metric_type = .METRIC_TYPE_GAUGE },
                            .match = null, // <-- This is what the HTTP sync produces
                            .negate = false,
                            .case_insensitive = false,
                        },
                    }),
                    .capacity = 1,
                },
                .keep = false,
            },
        },
    };

    var index = try MetricMatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    // The index should have registered one policy with one matcher
    try testing.expectEqual(@as(usize, 1), index.policies.len);
    try testing.expectEqual(@as(u16, 1), index.policies[0].required_match_count);
}

test "TraceMatcherIndex: span_kind null match with second resource_attribute matcher" {
    // Mirrors traces_multiple_matchers conformance case: an enum field with
    // null match (implicit exists) ANDed with a resource_attribute exact match.
    const allocator = testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    const policy = Policy{
        .id = "drop-internal-frontend-spans",
        .name = "Drop internal spans from frontend service",
        .enabled = true,
        .target = .{
            .trace = .{
                .match = .{
                    .items = @constCast(&[_]TraceMatcher{
                        .{
                            .field = .{ .span_kind = .SPAN_KIND_INTERNAL },
                            .match = null, // implicit exists via HTTP sync
                            .negate = false,
                            .case_insensitive = false,
                        },
                        .{
                            .field = .{ .resource_attribute = .{ .path = .{ .items = @constCast(&[_][]const u8{"service.name"}), .capacity = 1 } } },
                            .match = .{ .exact = "frontend" },
                            .negate = false,
                            .case_insensitive = false,
                        },
                    }),
                    .capacity = 2,
                },
            },
        },
    };

    var index = try TraceMatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    try testing.expect(!index.isEmpty());
    try testing.expectEqual(@as(usize, 1), index.getPolicyCount());
    // span_kind null match → exists entry (no DB); resource_attribute exact
    // match → one Hyperscan DB. required_match_count counts both.
    try testing.expectEqual(@as(usize, 1), index.getDatabaseCount());
    try testing.expectEqual(@as(u16, 2), index.policies[0].required_match_count);

    // Verify the exists bucket holds the span_kind entry.
    var exists_total: usize = 0;
    for (index.getMatcherKeys()) |k| exists_total += k.exists_entries.len;
    try testing.expectEqual(@as(usize, 1), exists_total);
}

test "TraceMatcherIndex: span_kind with null match (implicit exists)" {
    const allocator = testing.allocator;

    var noop_bus: o11y.NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    const policy = Policy{
        .id = "drop-internal-spans",
        .name = "Drop internal spans",
        .enabled = true,
        .target = .{
            .trace = .{
                .match = .{
                    .items = @constCast(&[_]TraceMatcher{
                        .{
                            .field = .{ .span_kind = .SPAN_KIND_INTERNAL },
                            .match = null, // <-- HTTP sync produces this
                            .negate = false,
                            .case_insensitive = false,
                        },
                    }),
                    .capacity = 1,
                },
            },
        },
    };

    var index = try TraceMatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    try testing.expect(!index.isEmpty());
    try testing.expectEqual(@as(usize, 1), index.getPolicyCount());

    // Implicit exists lives in exists_entries; no Hyperscan DB.
    try testing.expectEqual(@as(usize, 0), index.getDatabaseCount());
    try testing.expectEqual(@as(u16, 1), index.policies[0].required_match_count);
    const keys = index.getMatcherKeys();
    try testing.expectEqual(@as(usize, 1), keys.len);
    try testing.expectEqual(@as(usize, 1), keys[0].exists_entries.len);
}

test "MetricMatcherIndex: exists=true matcher is bucketed into exists_entries" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "test-policy"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    var attr_path = AttributePath{};
    try attr_path.path.append(allocator, try allocator.dupe(u8, "service.name"));
    try policy.target.?.metric.match.append(allocator, .{
        .field = .{ .resource_attribute = attr_path },
        .match = .{ .exists = true },
    });
    defer policy.deinit(allocator);

    var index = try MetricMatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    // exists=true is dispatched via accessor.callExists, not Hyperscan.
    try testing.expect(!index.isEmpty());
    try testing.expectEqual(@as(usize, 1), index.getPolicyCount());
    try testing.expectEqual(@as(usize, 0), index.getDatabaseCount());

    const keys = index.getMatcherKeys();
    try testing.expectEqual(@as(usize, 1), keys.len);
    try testing.expectEqual(@as(usize, 1), keys[0].exists_entries.len);
    try testing.expect(!keys[0].exists_entries[0].negate);
    try testing.expect(index.getDatabase(keys[0]) == null);
}

test "MetricMatcherIndex: metric_type exists is bucketed into exists_entries" {
    // metric_type with exists=true used to compile to a `^.+$` Hyperscan
    // pattern. After the accessor split, the exists semantic is dispatched
    // directly via accessor.callExists and lives in exists_entries.
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    const MetricType = proto.policy.MetricType;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "match-gauge-metrics"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    try policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_type = MetricType.METRIC_TYPE_GAUGE },
        .match = .{ .exists = true },
    });
    defer policy.deinit(allocator);

    var index = try MetricMatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    try testing.expect(!index.isEmpty());
    try testing.expectEqual(@as(usize, 0), index.getDatabaseCount());
    try testing.expectEqual(@as(usize, 1), index.getPolicyCount());

    const policy_info = index.getPolicy("policy-1");
    try testing.expect(policy_info != null);
    try testing.expectEqual(@as(u16, 1), policy_info.?.required_match_count);

    const keys = index.getMatcherKeys();
    try testing.expectEqual(@as(usize, 1), keys.len);
    try testing.expectEqual(@as(usize, 1), keys[0].exists_entries.len);
    try testing.expect(index.getDatabase(keys[0]) == null);
}

test "MetricMatcherIndex: metric_type with regex pattern" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    const MetricType = proto.policy.MetricType;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "match-gauge-metrics"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    // Match on metric_type with regex pattern for "gauge"
    try policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_type = MetricType.METRIC_TYPE_GAUGE },
        .match = .{ .exact = try allocator.dupe(u8, "gauge") },
    });
    defer policy.deinit(allocator);

    var index = try MetricMatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    try testing.expect(!index.isEmpty());

    const keys = index.getMatcherKeys();
    const db = index.getDatabase(keys[0]).?;
    var result_buf: [MAX_POLICIES]u32 = undefined;

    // Should match "gauge"
    var result = db.scanPositive("gauge", &result_buf);
    try testing.expectEqual(@as(usize, 1), result.count);

    // Should NOT match other types
    result = db.scanPositive("histogram", &result_buf);
    try testing.expectEqual(@as(usize, 0), result.count);

    result = db.scanPositive("sum", &result_buf);
    try testing.expectEqual(@as(usize, 0), result.count);
}

test "MetricMatcherIndex: aggregation_temporality field creates Hyperscan database" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    const AggregationTemporality = proto.policy.AggregationTemporality;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "match-delta-metrics"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    // Match on aggregation_temporality with regex for "delta"
    try policy.target.?.metric.match.append(allocator, .{
        .field = .{ .aggregation_temporality = AggregationTemporality.AGGREGATION_TEMPORALITY_DELTA },
        .match = .{ .exact = try allocator.dupe(u8, "delta") },
    });
    defer policy.deinit(allocator);

    var index = try MetricMatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    try testing.expect(!index.isEmpty());
    try testing.expectEqual(@as(usize, 1), index.getDatabaseCount());
    try testing.expectEqual(@as(usize, 1), index.getPolicyCount());

    const policy_info = index.getPolicy("policy-1");
    try testing.expect(policy_info != null);
    try testing.expectEqual(@as(u16, 1), policy_info.?.required_match_count);

    const keys = index.getMatcherKeys();
    const db = index.getDatabase(keys[0]).?;
    var result_buf: [MAX_POLICIES]u32 = undefined;

    // Should match "delta"
    var result = db.scanPositive("delta", &result_buf);
    try testing.expectEqual(@as(usize, 1), result.count);

    // Should NOT match "cumulative"
    result = db.scanPositive("cumulative", &result_buf);
    try testing.expectEqual(@as(usize, 0), result.count);
}

test "Mixed log and metric policies: each index only gets its type" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    var log_policy = Policy{
        .id = try allocator.dupe(u8, "log-policy-1"),
        .name = try allocator.dupe(u8, "test-log"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "all"),
        } },
    };
    try log_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer log_policy.deinit(allocator);

    var metric_policy = Policy{
        .id = try allocator.dupe(u8, "metric-policy-1"),
        .name = try allocator.dupe(u8, "test-metric"),
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

    const policies = &[_]Policy{ log_policy, metric_policy };

    // Log index should only have log policy
    var log_index = try LogMatcherIndex.build(allocator, noop_bus.eventBus(), policies);
    defer log_index.deinit();
    try testing.expectEqual(@as(usize, 1), log_index.getPolicyCount());
    try testing.expectEqual(@as(usize, 1), log_index.getDatabaseCount());

    const log_info = log_index.getPolicy("log-policy-1");
    try testing.expect(log_info != null);

    const metric_in_log = log_index.getPolicy("metric-policy-1");
    try testing.expect(metric_in_log == null);

    // Metric index should only have metric policy
    var metric_index = try MetricMatcherIndex.build(allocator, noop_bus.eventBus(), policies);
    defer metric_index.deinit();
    try testing.expectEqual(@as(usize, 1), metric_index.getPolicyCount());
    try testing.expectEqual(@as(usize, 1), metric_index.getDatabaseCount());

    const metric_info = metric_index.getPolicy("metric-policy-1");
    try testing.expect(metric_info != null);

    const log_in_metric = metric_index.getPolicy("log-policy-1");
    try testing.expect(log_in_metric == null);
}

// =============================================================================
// Tests for match types (starts_with, ends_with, contains, exact, exists)
// =============================================================================

test "formatPattern: regex returns pattern unchanged" {
    var buf: [64]u8 = undefined;
    var slice: []u8 = &buf;
    const result = formatPattern(&slice, "^hello.*world$", .regex);
    try testing.expectEqualStrings("^hello.*world$", result);
}

// exists matchers are no longer dispatched through Hyperscan / formatPattern,
// so there is no `.exists` pattern fixture to assert. Coverage lives in
// `*MatcherIndex: exists ... is bucketed into exists_entries`.

test "formatPattern: exact adds both anchors" {
    var buf: [64]u8 = undefined;
    var slice: []u8 = &buf;
    const result = formatPattern(&slice, "hello", .exact);
    try testing.expectEqualStrings("^hello$", result);
}

test "formatPattern: starts_with adds start anchor" {
    var buf: [64]u8 = undefined;
    var slice: []u8 = &buf;
    const result = formatPattern(&slice, "ERROR:", .starts_with);
    try testing.expectEqualStrings("^ERROR:", result);
}

test "formatPattern: ends_with adds end anchor" {
    var buf: [64]u8 = undefined;
    var slice: []u8 = &buf;
    const result = formatPattern(&slice, ".json", .ends_with);
    try testing.expectEqualStrings(".json$", result);
}

test "formatPattern: contains returns pattern unchanged" {
    var buf: [64]u8 = undefined;
    var slice: []u8 = &buf;
    const result = formatPattern(&slice, "password", .contains);
    try testing.expectEqualStrings("password", result);
}

test "Log matcher with starts_with" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    var policy = Policy{
        .id = try allocator.dupe(u8, "starts-with-policy"),
        .name = try allocator.dupe(u8, "test"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "all") } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .starts_with = try allocator.dupe(u8, "ERROR") },
    });
    defer policy.deinit(allocator);

    var index = try LogMatcherIndex.build(allocator, noop_bus.eventBus(), &[_]Policy{policy});
    defer index.deinit();

    const db = index.getDatabase(.{ .field = .{ .log_field = .LOG_FIELD_BODY } }).?;
    var result_buf: [8]u32 = undefined;

    // Should match strings starting with ERROR
    var result = db.scanPositive("ERROR: something failed", &result_buf);
    try testing.expectEqual(@as(usize, 1), result.count);

    result = db.scanPositive("ERROR", &result_buf);
    try testing.expectEqual(@as(usize, 1), result.count);

    // Should not match strings not starting with ERROR
    result = db.scanPositive("Warning: ERROR occurred", &result_buf);
    try testing.expectEqual(@as(usize, 0), result.count);

    result = db.scanPositive("Some ERROR here", &result_buf);
    try testing.expectEqual(@as(usize, 0), result.count);
}

test "Log matcher with ends_with" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    var policy = Policy{
        .id = try allocator.dupe(u8, "ends-with-policy"),
        .name = try allocator.dupe(u8, "test"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "all") } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .ends_with = try allocator.dupe(u8, ".json") },
    });
    defer policy.deinit(allocator);

    var index = try LogMatcherIndex.build(allocator, noop_bus.eventBus(), &[_]Policy{policy});
    defer index.deinit();

    const db = index.getDatabase(.{ .field = .{ .log_field = .LOG_FIELD_BODY } }).?;
    var result_buf: [8]u32 = undefined;

    // Should match strings ending with .json
    var result = db.scanPositive("config.json", &result_buf);
    try testing.expectEqual(@as(usize, 1), result.count);

    result = db.scanPositive("path/to/file.json", &result_buf);
    try testing.expectEqual(@as(usize, 1), result.count);

    // Should not match strings not ending with .json
    result = db.scanPositive("config.json.bak", &result_buf);
    try testing.expectEqual(@as(usize, 0), result.count);

    result = db.scanPositive("json file here", &result_buf);
    try testing.expectEqual(@as(usize, 0), result.count);
}

test "Log matcher with contains" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    var policy = Policy{
        .id = try allocator.dupe(u8, "contains-policy"),
        .name = try allocator.dupe(u8, "test"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "all") } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .contains = try allocator.dupe(u8, "password") },
    });
    defer policy.deinit(allocator);

    var index = try LogMatcherIndex.build(allocator, noop_bus.eventBus(), &[_]Policy{policy});
    defer index.deinit();

    const db = index.getDatabase(.{ .field = .{ .log_field = .LOG_FIELD_BODY } }).?;
    var result_buf: [8]u32 = undefined;

    // Should match strings containing password anywhere
    var result = db.scanPositive("password", &result_buf);
    try testing.expectEqual(@as(usize, 1), result.count);

    result = db.scanPositive("user password here", &result_buf);
    try testing.expectEqual(@as(usize, 1), result.count);

    result = db.scanPositive("my_password_field", &result_buf);
    try testing.expectEqual(@as(usize, 1), result.count);

    // Should not match strings without password
    result = db.scanPositive("pass word", &result_buf);
    try testing.expectEqual(@as(usize, 0), result.count);

    result = db.scanPositive("secret", &result_buf);
    try testing.expectEqual(@as(usize, 0), result.count);
}

test "Log matcher with exact" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    var policy = Policy{
        .id = try allocator.dupe(u8, "exact-policy"),
        .name = try allocator.dupe(u8, "test"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "all") } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .exact = try allocator.dupe(u8, "hello") },
    });
    defer policy.deinit(allocator);

    var index = try LogMatcherIndex.build(allocator, noop_bus.eventBus(), &[_]Policy{policy});
    defer index.deinit();

    const db = index.getDatabase(.{ .field = .{ .log_field = .LOG_FIELD_BODY } }).?;
    var result_buf: [8]u32 = undefined;

    // Should match exactly "hello"
    var result = db.scanPositive("hello", &result_buf);
    try testing.expectEqual(@as(usize, 1), result.count);

    // Should not match anything else
    result = db.scanPositive("hello world", &result_buf);
    try testing.expectEqual(@as(usize, 0), result.count);

    result = db.scanPositive("say hello", &result_buf);
    try testing.expectEqual(@as(usize, 0), result.count);

    result = db.scanPositive("Hello", &result_buf);
    try testing.expectEqual(@as(usize, 0), result.count);
}

test "Log matcher with case_insensitive" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    var policy = Policy{
        .id = try allocator.dupe(u8, "case-insensitive-policy"),
        .name = try allocator.dupe(u8, "test"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "all") } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .exact = try allocator.dupe(u8, "hello") },
        .case_insensitive = true,
    });
    defer policy.deinit(allocator);

    var index = try LogMatcherIndex.build(allocator, noop_bus.eventBus(), &[_]Policy{policy});
    defer index.deinit();

    const db = index.getDatabase(.{ .field = .{ .log_field = .LOG_FIELD_BODY } }).?;
    var result_buf: [8]u32 = undefined;

    // Should match case variations
    var result = db.scanPositive("hello", &result_buf);
    try testing.expectEqual(@as(usize, 1), result.count);

    result = db.scanPositive("Hello", &result_buf);
    try testing.expectEqual(@as(usize, 1), result.count);

    result = db.scanPositive("HELLO", &result_buf);
    try testing.expectEqual(@as(usize, 1), result.count);

    result = db.scanPositive("HeLLo", &result_buf);
    try testing.expectEqual(@as(usize, 1), result.count);

    // Should still not match partial
    result = db.scanPositive("hello world", &result_buf);
    try testing.expectEqual(@as(usize, 0), result.count);
}

test "Log matcher with starts_with case_insensitive" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    var policy = Policy{
        .id = try allocator.dupe(u8, "starts-with-ci-policy"),
        .name = try allocator.dupe(u8, "test"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "all") } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .starts_with = try allocator.dupe(u8, "error") },
        .case_insensitive = true,
    });
    defer policy.deinit(allocator);

    var index = try LogMatcherIndex.build(allocator, noop_bus.eventBus(), &[_]Policy{policy});
    defer index.deinit();

    const db = index.getDatabase(.{ .field = .{ .log_field = .LOG_FIELD_BODY } }).?;
    var result_buf: [8]u32 = undefined;

    var result = db.scanPositive("error: failed", &result_buf);
    try testing.expectEqual(@as(usize, 1), result.count);

    result = db.scanPositive("ERROR: failed", &result_buf);
    try testing.expectEqual(@as(usize, 1), result.count);

    result = db.scanPositive("Error: failed", &result_buf);
    try testing.expectEqual(@as(usize, 1), result.count);

    result = db.scanPositive("warning: error", &result_buf);
    try testing.expectEqual(@as(usize, 0), result.count);
}
