//! Allocation-free policy evaluator over projected field values.
//!
//! This module intentionally imports neither provider code nor generated
//! protobuf declarations. The protocol boundary ends at `ValueRef`.

const Runtime = @This();

const std = @import("std");
const capacity_mod = @import("policy_capacity");
const image_mod = @import("policy_image");
const compiler_for_testing = @import("policy_compiler");
pub const sampling = @import("sampling.zig");

pub const Capacity = capacity_mod.Capacity;
pub const PolicyImage = image_mod.PolicyImage;

pub const ValueRef = union(enum) {
    missing,
    string: []const u8,
    bytes: []const u8,
    signed: i64,
    unsigned: u64,
    float: f64,
    boolean: bool,
};

pub const Reason = enum(u16) {
    no_policy = 0,
    matched_keep = 1,
    matched_drop = 2,
    sampled_out = 3,
    rate_limited = 4,
    regex_unavailable = 5,
    invalid_projection = 6,
    invalid_image = 7,
};

pub const RateLimitSemantics = enum(u8) {
    worker_sharded,
    consistently_keyed,
    centralized_recorded,
};

pub const RegexBackend = struct {
    context: *anyopaque,
    /// One worker scratch region must cover every database in this image.
    required_scratch_bytes: u32,
    scanFn: *const fn (context: *anyopaque, matcher_id: u32, value: []const u8, scratch: []u8) bool,

    pub fn scan(self: RegexBackend, matcher_id: u32, value: []const u8, scratch: []u8) bool {
        return self.scanFn(self.context, matcher_id, value, scratch);
    }
};

pub const EvalContext = struct {
    image_epoch: u64,
    global_sequence: u64 = 0,
    request_sequence: u64 = 0,
    record_sequence: u64 = 0,
    worker_id: u16,
    signal: image_mod.Signal,
    record_format: u8 = 0,
    timestamp_ns: u64 = 0,
    record_key: []const u8,
    trace_state: []const u8 = "",
    input_hash: u64 = 0,
    input_size: u32 = 0,
    regex: ?RegexBackend = null,
    sampling_outcome: ?bool = null,
    rate_limit_outcome: ?bool = null,
    rate_limit_semantics: RateLimitSemantics = .worker_sharded,
    detail_journal: ?*MatchDetailJournal = null,
};

pub const Decision = struct {
    verdict: image_mod.Verdict,
    reason: Reason,
    winning_policy_index: u16,
    action_start: u32,
    action_count: u32,
    image_epoch: u64,
    image_hash_prefix: u64,
    image_hash: [image_mod.hash_bytes]u8,
    match_summary: u64,
    action_mask: u64,
    sampling_randomness: u64,
    sampling_threshold: u64,
    sampling_precision: u8,
    sampling_randomness_valid: bool,
    sampling_threshold_valid: bool,
    sampling_explicit_randomness: bool,
    sampled: bool,
    rate_limit_allowed: bool,

    pub const no_policy_index = std.math.maxInt(u16);

    /// Materialize the OTel `ot` tracestate member outside the hot evaluator.
    pub fn updateTraceState(self: Decision, destination: []u8, existing: []const u8) ?[]u8 {
        if (!self.sampling_threshold_valid) return null;
        return sampling.updateTraceState(
            destination,
            existing,
            self.sampling_threshold,
            self.sampling_precision,
            if (self.sampling_explicit_randomness) self.sampling_randomness else null,
        );
    }
};

/// Familiar façade over the data-oriented evaluator. The engine owns no state;
/// its image and worker storage remain caller-owned.
pub const PolicyEngine = struct {
    image: *const PolicyImage,
    worker: *WorkerState,

    pub fn init(image: *const PolicyImage, worker: *WorkerState) PolicyEngine {
        return .{ .image = image, .worker = worker };
    }

    pub fn evaluate(self: PolicyEngine, values: []const ValueRef, context: EvalContext) Decision {
        return Runtime.evaluate(self.image, self.worker, values, context);
    }
};

pub const PolicyResult = Decision;

pub const WorkerStats = struct {
    hits: []u64,
    misses: []u64,
    transforms: []u64,
};

/// Large mutable arrays live in caller-provided, worker-exclusive memory.
pub const WorkerState = struct {
    capacity: Capacity,
    generation: u32,
    match_counts: []u16,
    seen_generation: []u32,
    active_policy_indices: []u16,
    policy_dropped: []bool,
    active_count: u16,
    stats: WorkerStats,
    rate_window_second: []u64,
    rate_window_count: []u32,
    regex_scratch: []u8,
    decision_detail: []u8,

    pub const InitError = error{
        InvalidCapacity,
        InsufficientStorage,
    };

    /// Upper bound includes allocator alignment slop so any byte-slice address
    /// with sufficient length is accepted.
    pub fn requiredBytes(capacity: Capacity) usize {
        const policies: usize = capacity.max_policies;
        return 64 +
            policies * @sizeOf(u16) * 2 +
            policies * @sizeOf(bool) +
            policies * @sizeOf(u32) * 2 +
            policies * @sizeOf(u64) * 4 +
            capacity.max_context_bytes +
            capacity.max_group_bytes;
    }

    pub fn init(storage: []u8, capacity: Capacity) InitError!WorkerState {
        capacity.validate() catch return error.InvalidCapacity;
        if (storage.len < requiredBytes(capacity)) return error.InsufficientStorage;
        var fba = std.heap.FixedBufferAllocator.init(storage);
        const allocator = fba.allocator();
        const policies: usize = capacity.max_policies;
        const match_counts = allocator.alloc(u16, policies) catch return error.InsufficientStorage;
        const seen_generation = allocator.alloc(u32, policies) catch return error.InsufficientStorage;
        const active = allocator.alloc(u16, policies) catch return error.InsufficientStorage;
        const policy_dropped = allocator.alloc(bool, policies) catch return error.InsufficientStorage;
        const hits = allocator.alloc(u64, policies) catch return error.InsufficientStorage;
        const misses = allocator.alloc(u64, policies) catch return error.InsufficientStorage;
        const transforms = allocator.alloc(u64, policies) catch return error.InsufficientStorage;
        const rate_window_second = allocator.alloc(u64, policies) catch return error.InsufficientStorage;
        const rate_window_count = allocator.alloc(u32, policies) catch return error.InsufficientStorage;
        const regex_scratch = allocator.alloc(u8, capacity.max_context_bytes) catch return error.InsufficientStorage;
        const decision_detail = allocator.alloc(u8, capacity.max_group_bytes) catch return error.InsufficientStorage;
        @memset(match_counts, 0);
        @memset(policy_dropped, false);
        @memset(seen_generation, 0);
        @memset(hits, 0);
        @memset(misses, 0);
        @memset(transforms, 0);
        @memset(rate_window_second, 0);
        @memset(rate_window_count, 0);
        return .{
            .capacity = capacity,
            .generation = 0,
            .match_counts = match_counts,
            .seen_generation = seen_generation,
            .active_policy_indices = active,
            .policy_dropped = policy_dropped,
            .active_count = 0,
            .stats = .{ .hits = hits, .misses = misses, .transforms = transforms },
            .rate_window_second = rate_window_second,
            .rate_window_count = rate_window_count,
            .regex_scratch = regex_scratch,
            .decision_detail = decision_detail,
        };
    }

    fn beginRecord(self: *WorkerState) void {
        self.generation +%= 1;
        if (self.generation == 0) {
            // One bounded clear per 2^32 evaluations avoids stamp aliasing.
            @memset(self.seen_generation, 0);
            self.generation = 1;
        }
        self.active_count = 0;
    }

    fn activate(self: *WorkerState, policy_index: u16) void {
        if (self.seen_generation[policy_index] == self.generation) return;
        self.seen_generation[policy_index] = self.generation;
        self.match_counts[policy_index] = 0;
        self.active_policy_indices[self.active_count] = policy_index;
        self.active_count += 1;
    }

    pub fn clearStats(self: *WorkerState) void {
        @memset(self.stats.hits, 0);
        @memset(self.stats.misses, 0);
        @memset(self.stats.transforms, 0);
    }

    pub fn detailJournal(self: *WorkerState) MatchDetailJournal {
        return .{ .storage = self.decision_detail };
    }
};

pub const match_detail_bytes: usize = 8;

pub const MatchDetailJournal = struct {
    storage: []u8,
    count: u32 = 0,
    truncated: bool = false,

    pub noinline fn append(self: *MatchDetailJournal, policy_index: u16, matcher_index: u32, matched: bool) void {
        const offset = @as(usize, self.count) * match_detail_bytes;
        if (offset + match_detail_bytes > self.storage.len) {
            self.truncated = true;
            return;
        }
        putU16(self.storage, offset, policy_index);
        putU32(self.storage, offset + 2, matcher_index);
        self.storage[offset + 6] = @intFromBool(matched);
        self.storage[offset + 7] = 0;
        self.count += 1;
    }
};

pub const EvalFrame = struct {
    decision: Decision,
    winning_priority: i32,
    regex_missing: bool,
};

/// Common match-and-decide kernel. Cold error handling, projection, transforms,
/// and event encoding are deliberately outside this function.
pub noinline fn evaluate(
    image: *const PolicyImage,
    worker: *WorkerState,
    values: []const ValueRef,
    context: EvalContext,
) align(4096) linksection("__TEXT,__policy_vm") Decision {
    const hash_prefix = std.mem.readInt(u64, image.header.image_hash[0..8], .little);
    var frame: EvalFrame = .{
        .decision = .{
            .verdict = .unset,
            .reason = .no_policy,
            .winning_policy_index = Decision.no_policy_index,
            .action_start = 0,
            .action_count = 0,
            .image_epoch = context.image_epoch,
            .image_hash_prefix = hash_prefix,
            .image_hash = image.header.image_hash,
            .match_summary = 0,
            .action_mask = 0,
            .sampling_randomness = 0,
            .sampling_threshold = 0,
            .sampling_precision = 0,
            .sampling_randomness_valid = false,
            .sampling_threshold_valid = false,
            .sampling_explicit_randomness = false,
            .sampled = true,
            .rate_limit_allowed = true,
        },
        .winning_priority = std.math.minInt(i32),
        .regex_missing = false,
    };
    const decision = &frame.decision;
    if (values.len < image.header.field_count or image.header.policy_count > worker.capacity.max_policies) {
        decision.reason = .invalid_projection;
        return decision.*;
    }

    worker.beginRecord();
    for (0..image.header.policy_count) |policy_raw| {
        const policy_index: u16 = @intCast(policy_raw);
        const policy = image.policy(policy_index) catch {
            decision.reason = .invalid_image;
            return decision.*;
        };
        if (policy.signal != context.signal) continue;
        if (policy.flags & 1 == 0) continue;
        worker.activate(policy_index);
        var matched = true;
        for (policy.matcher_start..policy.matcher_start + policy.matcher_count) |matcher_index_raw| {
            const matcher_index: u32 = @intCast(matcher_index_raw);
            const matcher = image.matcher(matcher_index) catch {
                decision.reason = .invalid_image;
                return decision.*;
            };
            var condition = matchOne(
                image,
                matcher_index,
                matcher,
                values[matcher.field_index],
                worker,
                context.regex,
                &frame.regex_missing,
            );
            if (matcher.negated()) condition = !condition;
            if (context.detail_journal) |journal| journal.append(policy_index, matcher_index, condition);
            if (!condition) {
                matched = false;
                break;
            }
            worker.match_counts[policy_index] += 1;
        }
        if (!matched or worker.match_counts[policy_index] != policy.required_matches) {
            continue;
        }
        decision.match_summary ^= std.hash.Wyhash.hash(policy_index, context.record_key);
        const prior_drop = decision.verdict == .drop;
        if (policy.priority >= frame.winning_priority) {
            frame.winning_priority = policy.priority;
            decision.winning_policy_index = policy_index;
            decision.action_start = policy.action_start;
            decision.action_count = policy.action_count;
        }
        decision.action_mask |= actionMask(image, policy.action_start, policy.action_count);
        if (policy.verdict == .drop) {
            decision.verdict = .drop;
            decision.reason = .matched_drop;
        } else if (decision.verdict == .unset) {
            decision.verdict = .keep;
            decision.reason = .matched_keep;
        }

        var policy_dropped = policy.verdict == .drop;
        if (!prior_drop) policy_dropped = applySampling(policy, context, decision) or policy_dropped;

        decision.rate_limit_allowed = if (prior_drop) true else switch (context.rate_limit_semantics) {
            .worker_sharded, .consistently_keyed => context.rate_limit_outcome orelse rateLimit(
                worker,
                policy_index,
                policy.rate_limit_per_second,
                policy.rate_window_seconds,
                context.timestamp_ns,
            ),
            .centralized_recorded => context.rate_limit_outcome orelse false,
        };
        if (!decision.rate_limit_allowed) {
            policy_dropped = true;
            decision.verdict = .drop;
            decision.reason = .rate_limited;
        }
        worker.policy_dropped[policy_index] = policy_dropped;
    }
    if (decision.winning_policy_index == Decision.no_policy_index and frame.regex_missing) {
        decision.reason = .regex_unavailable;
    }
    recordStats(image, worker, decision.verdict);
    return decision.*;
}

noinline fn recordStats(image: *const PolicyImage, worker: *WorkerState, verdict: image_mod.Verdict) void {
    var drop_claimed = false;
    for (0..image.header.policy_count) |raw| {
        const policy_index: u16 = @intCast(raw);
        if (worker.seen_generation[policy_index] != worker.generation) continue;
        const item = image.policy(policy_index) catch continue;
        if (worker.match_counts[policy_index] != item.required_matches) continue;
        const policy_hit = if (verdict == .drop)
            worker.policy_dropped[policy_index] and !drop_claimed
        else
            !worker.policy_dropped[policy_index];
        if (policy_hit) {
            worker.stats.hits[policy_index] += 1;
            if (verdict == .drop) drop_claimed = true;
        } else {
            worker.stats.misses[policy_index] += 1;
        }
    }
}

noinline fn applySampling(policy: image_mod.Policy, context: EvalContext, decision: *Decision) bool {
    if (!policy.sampling_enabled) return false;
    const mode: sampling.Mode = switch (policy.sampling_mode) {
        .hash_seed => .hash_seed,
        .proportional => .proportional,
        .equalizing => .equalizing,
    };
    const result = sampling.evaluate(.{
        .threshold = policy.sampling_threshold,
        .mode = mode,
        .precision = policy.sampling_precision,
        .hash_seed = policy.sampling_hash_seed,
        .fail_closed = policy.sampling_fail_closed,
    }, context.record_key, context.trace_state);
    decision.sampled = context.sampling_outcome orelse result.keep;
    decision.sampling_precision = policy.sampling_precision;
    if (result.randomness) |randomness| {
        decision.sampling_randomness = randomness;
        decision.sampling_randomness_valid = true;
    }
    if (result.threshold) |threshold| {
        decision.sampling_threshold = threshold;
        decision.sampling_threshold_valid = true;
    }
    decision.sampling_explicit_randomness = result.explicit_randomness != null;
    if (!decision.sampled) {
        decision.verdict = .drop;
        decision.reason = .sampled_out;
    }
    return !decision.sampled;
}

noinline fn matchOne(
    image: *const PolicyImage,
    matcher_index: u32,
    matcher: image_mod.Matcher,
    value: ValueRef,
    worker: *WorkerState,
    regex: ?RegexBackend,
    regex_missing: *bool,
) bool {
    if (matcher.opcode == .exists) return value != .missing;
    return switch (matcher.opcode) {
        .exists => unreachable,
        .exact, .prefix, .suffix, .contains, .regex => matchBytes(
            image,
            matcher_index,
            matcher,
            value,
            worker,
            regex,
            regex_missing,
        ),
        .signed_eq, .signed_lt, .signed_lte, .signed_gt, .signed_gte => blk: {
            if (value != .signed) break :blk false;
            const expected = decodeSigned(matcher.value_lo, matcher.value_hi != 0);
            break :blk compareSigned(matcher.opcode, value.signed, expected);
        },
        .unsigned_eq, .unsigned_lt, .unsigned_lte, .unsigned_gt, .unsigned_gte => blk: {
            if (value != .unsigned) break :blk false;
            break :blk compareUnsigned(matcher.opcode, value.unsigned, matcher.value_lo);
        },
        .float_eq, .float_lt, .float_lte, .float_gt, .float_gte => blk: {
            if (value != .float) break :blk false;
            const encoded = image.matcherConstant(matcher_index) catch break :blk false;
            const expected = std.fmt.parseFloat(f64, encoded) catch break :blk false;
            break :blk compareFloat(matcher.opcode, value.float, expected);
        },
        .boolean_eq => if (value == .boolean) value.boolean == (matcher.value_lo != 0) else false,
    };
}

noinline fn matchBytes(
    image: *const PolicyImage,
    matcher_index: u32,
    matcher: image_mod.Matcher,
    value: ValueRef,
    worker: *WorkerState,
    regex: ?RegexBackend,
    regex_missing: *bool,
) bool {
    const actual = switch (value) {
        .string => |bytes| bytes,
        .bytes => |bytes| bytes,
        else => return false,
    };
    const expected = image.matcherConstant(matcher_index) catch return false;
    return switch (matcher.opcode) {
        .exact => if (matcher.caseInsensitive())
            std.ascii.eqlIgnoreCase(expected, actual)
        else
            matcher.stable_hash == std.hash.Wyhash.hash(0, actual) and std.mem.eql(u8, expected, actual),
        .prefix => if (matcher.caseInsensitive())
            actual.len >= expected.len and std.ascii.eqlIgnoreCase(actual[0..expected.len], expected)
        else
            std.mem.startsWith(u8, actual, expected),
        .suffix => if (matcher.caseInsensitive())
            actual.len >= expected.len and std.ascii.eqlIgnoreCase(actual[actual.len - expected.len ..], expected)
        else
            std.mem.endsWith(u8, actual, expected),
        .contains => if (matcher.caseInsensitive())
            containsIgnoreCase(actual, expected)
        else
            std.mem.indexOf(u8, actual, expected) != null,
        .regex => if (regex) |backend| blk: {
            if (backend.required_scratch_bytes > worker.regex_scratch.len) {
                regex_missing.* = true;
                break :blk false;
            }
            break :blk backend.scan(matcher_index, actual, worker.regex_scratch);
        } else blk: {
            regex_missing.* = true;
            break :blk false;
        },
        else => unreachable,
    };
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > haystack.len) return false;
    for (0..haystack.len - needle.len + 1) |start| {
        if (std.ascii.eqlIgnoreCase(haystack[start..][0..needle.len], needle)) return true;
    }
    return false;
}

noinline fn compareSigned(opcode: image_mod.MatchOpcode, actual: i64, expected: i64) bool {
    return switch (opcode) {
        .signed_eq => actual == expected,
        .signed_lt => actual < expected,
        .signed_lte => actual <= expected,
        .signed_gt => actual > expected,
        .signed_gte => actual >= expected,
        else => unreachable,
    };
}

fn decodeSigned(magnitude: u64, negative: bool) i64 {
    if (!negative) return @intCast(magnitude);
    if (magnitude == (@as(u64, 1) << 63)) return std.math.minInt(i64);
    return -@as(i64, @intCast(magnitude));
}

noinline fn compareUnsigned(opcode: image_mod.MatchOpcode, actual: u64, expected: u64) bool {
    return switch (opcode) {
        .unsigned_eq => actual == expected,
        .unsigned_lt => actual < expected,
        .unsigned_lte => actual <= expected,
        .unsigned_gt => actual > expected,
        .unsigned_gte => actual >= expected,
        else => unreachable,
    };
}

noinline fn compareFloat(opcode: image_mod.MatchOpcode, actual: f64, expected: f64) bool {
    return switch (opcode) {
        .float_eq => actual == expected,
        .float_lt => actual < expected,
        .float_lte => actual <= expected,
        .float_gt => actual > expected,
        .float_gte => actual >= expected,
        else => unreachable,
    };
}

noinline fn rateLimit(
    worker: *WorkerState,
    policy_index: u16,
    limit: u32,
    window_seconds: u32,
    timestamp_ns: u64,
) bool {
    if (limit == 0) return true;
    const duration = @as(u64, @max(window_seconds, 1)) * std.time.ns_per_s;
    const second = timestamp_ns / duration;
    if (worker.rate_window_second[policy_index] != second) {
        worker.rate_window_second[policy_index] = second;
        worker.rate_window_count[policy_index] = 1;
        return true;
    }
    if (worker.rate_window_count[policy_index] >= limit) return false;
    worker.rate_window_count[policy_index] += 1;
    return true;
}

noinline fn actionMask(image: *const PolicyImage, start: u32, count: u32) u64 {
    var mask: u64 = 0;
    for (start..start + count) |index_raw| {
        const index: u32 = @intCast(index_raw);
        const action = image.action(index) catch continue;
        mask |= @as(u64, 1) << @as(u6, @intCast(@intFromEnum(action.opcode)));
    }
    return mask;
}

pub const ActionCommand = struct {
    action_index: u32,
    opcode: image_mod.ActionOpcode,
    flags: u8,
    field_index: ?u16,
    value: []const u8,
    binding_id: u32,
};

/// Transform and extension dispatch walks compact actions after the common
/// kernel; protocol-object mutation remains a host responsibility.
pub const ActionIterator = struct {
    image: *const PolicyImage,
    cursor: u32,
    end: u32,

    pub fn init(image: *const PolicyImage, decision: Decision) ActionIterator {
        return .{
            .image = image,
            .cursor = decision.action_start,
            .end = decision.action_start + decision.action_count,
        };
    }

    pub fn initPolicy(image: *const PolicyImage, policy_index: u16) ?ActionIterator {
        const item = image.policy(policy_index) catch return null;
        return .{
            .image = image,
            .cursor = item.action_start,
            .end = item.action_start + item.action_count,
        };
    }

    pub fn next(self: *ActionIterator) ?ActionCommand {
        if (self.cursor >= self.end) return null;
        const index = self.cursor;
        self.cursor += 1;
        const action = self.image.action(index) catch return null;
        return .{
            .action_index = index,
            .opcode = action.opcode,
            .flags = action.flags,
            .field_index = if (action.field_index == std.math.maxInt(u16)) null else action.field_index,
            .value = self.image.actionValue(index) catch return null,
            .binding_id = action.binding_id,
        };
    }
};

pub const MatchedPolicyIterator = struct {
    image: *const PolicyImage,
    worker: *const WorkerState,
    cursor: u16 = 0,

    pub fn init(image: *const PolicyImage, worker: *const WorkerState) MatchedPolicyIterator {
        return .{ .image = image, .worker = worker };
    }

    pub fn next(self: *MatchedPolicyIterator) ?u16 {
        while (self.cursor < self.image.header.policy_count) {
            const index = self.cursor;
            self.cursor += 1;
            if (self.worker.seen_generation[index] != self.worker.generation) continue;
            const item = self.image.policy(index) catch continue;
            if (self.worker.match_counts[index] == item.required_matches) return index;
        }
        return null;
    }
};

pub const decision_event_version: u16 = 2;
pub const decision_event_bytes: usize = 128;

/// Stable binary replay record. Encoding is explicit little-endian.
pub const DecisionEvent = struct {
    global_sequence: u64,
    request_sequence: u64,
    record_sequence: u64,
    worker_id: u16,
    image_epoch: u64,
    image_hash_prefix: u64,
    signal: image_mod.Signal,
    record_format: u8,
    input_hash: u64,
    input_size: u32,
    verdict: image_mod.Verdict,
    reason: Reason,
    winning_policy_index: u16,
    match_summary: u64,
    action_mask: u64,
    sampling_randomness: u64,
    sampling_threshold: u64,
    sampling_precision: u8,
    sampling_randomness_valid: bool,
    sampling_threshold_valid: bool,
    sampling_explicit_randomness: bool,
    sampled: bool,
    rate_limit_allowed: bool,
    output_size: u32 = 0,
    error_flags: u32 = 0,

    pub fn fromDecision(context: EvalContext, decision: Decision) DecisionEvent {
        return .{
            .global_sequence = context.global_sequence,
            .request_sequence = context.request_sequence,
            .record_sequence = context.record_sequence,
            .worker_id = context.worker_id,
            .image_epoch = decision.image_epoch,
            .image_hash_prefix = decision.image_hash_prefix,
            .signal = context.signal,
            .record_format = context.record_format,
            .input_hash = context.input_hash,
            .input_size = context.input_size,
            .verdict = decision.verdict,
            .reason = decision.reason,
            .winning_policy_index = decision.winning_policy_index,
            .match_summary = decision.match_summary,
            .action_mask = decision.action_mask,
            .sampling_randomness = decision.sampling_randomness,
            .sampling_threshold = decision.sampling_threshold,
            .sampling_precision = decision.sampling_precision,
            .sampling_randomness_valid = decision.sampling_randomness_valid,
            .sampling_threshold_valid = decision.sampling_threshold_valid,
            .sampling_explicit_randomness = decision.sampling_explicit_randomness,
            .sampled = decision.sampled,
            .rate_limit_allowed = decision.rate_limit_allowed,
        };
    }

    pub fn encode(self: DecisionEvent, destination: *[decision_event_bytes]u8) void {
        @memset(destination, 0);
        putU16(destination, 0, decision_event_version);
        putU16(destination, 2, decision_event_bytes);
        putU64(destination, 8, self.global_sequence);
        putU64(destination, 16, self.request_sequence);
        putU64(destination, 24, self.record_sequence);
        putU16(destination, 32, self.worker_id);
        destination[34] = @intFromEnum(self.signal);
        destination[35] = self.record_format;
        putU64(destination, 40, self.image_epoch);
        putU64(destination, 48, self.image_hash_prefix);
        putU64(destination, 56, self.input_hash);
        putU32(destination, 64, self.input_size);
        destination[68] = @intFromEnum(self.verdict);
        putU16(destination, 70, @intFromEnum(self.reason));
        putU16(destination, 72, self.winning_policy_index);
        putU64(destination, 80, self.match_summary);
        putU64(destination, 88, self.action_mask);
        putU64(destination, 96, self.sampling_randomness);
        putU64(destination, 104, self.sampling_threshold);
        putU32(destination, 112, self.output_size);
        putU32(destination, 116, self.error_flags);
        destination[120] = self.sampling_precision;
        destination[121] = @intFromBool(self.sampled);
        destination[122] = @intFromBool(self.rate_limit_allowed);
        destination[123] = @intFromBool(self.sampling_randomness_valid);
        destination[124] = @intFromBool(self.sampling_threshold_valid);
        destination[125] = @intFromBool(self.sampling_explicit_randomness);
    }
};

pub const DecisionJournal = struct {
    storage: []u8,
    event_count: u32 = 0,

    pub fn append(self: *DecisionJournal, event: DecisionEvent) bool {
        const offset = @as(usize, self.event_count) * decision_event_bytes;
        if (offset + decision_event_bytes > self.storage.len) return false;
        event.encode(self.storage[offset..][0..decision_event_bytes]);
        self.event_count += 1;
        return true;
    }

    pub fn reset(self: *DecisionJournal) void {
        self.event_count = 0;
    }
};

fn putU16(bytes: []u8, offset: usize, value: u16) void {
    std.mem.writeInt(u16, bytes[offset..][0..2], value, .little);
}

fn putU32(bytes: []u8, offset: usize, value: u32) void {
    std.mem.writeInt(u32, bytes[offset..][0..4], value, .little);
}

fn putU64(bytes: []u8, offset: usize, value: u64) void {
    std.mem.writeInt(u64, bytes[offset..][0..8], value, .little);
}

test "worker state is entirely caller owned" {
    const capacity: Capacity = .{
        .max_connections = 4,
        .worker_count = 1,
        .max_policies = 8,
        .max_fields = 8,
        .max_matchers = 16,
        .max_actions = 8,
        .max_image_bytes = 4096,
        .max_record_bytes = 4096,
        .max_context_bytes = 1024,
        .max_group_bytes = 256,
        .journal_events_per_worker = 64,
        .extension_queue_bytes = 1024,
    };
    var storage: [WorkerState.requiredBytes(capacity)]u8 = undefined;
    var worker = try WorkerState.init(&storage, capacity);
    try std.testing.expectEqual(@as(usize, capacity.max_policies), worker.stats.hits.len);
    worker.stats.hits[7] = 4;
    worker.clearStats();
    try std.testing.expectEqual(@as(u64, 0), worker.stats.hits[7]);
}

test "decision event encoding is deterministic and bounded" {
    const event: DecisionEvent = .{
        .global_sequence = 1,
        .request_sequence = 2,
        .record_sequence = 3,
        .worker_id = 4,
        .image_epoch = 5,
        .image_hash_prefix = 6,
        .signal = .trace,
        .record_format = 7,
        .input_hash = 8,
        .input_size = 9,
        .verdict = .drop,
        .reason = .matched_drop,
        .winning_policy_index = 10,
        .match_summary = 11,
        .action_mask = 12,
        .sampling_randomness = 13,
        .sampling_threshold = 14,
        .sampling_precision = 4,
        .sampling_randomness_valid = true,
        .sampling_threshold_valid = true,
        .sampling_explicit_randomness = false,
        .sampled = true,
        .rate_limit_allowed = false,
    };
    var first: [decision_event_bytes]u8 = undefined;
    var second: [decision_event_bytes]u8 = undefined;
    event.encode(&first);
    event.encode(&second);
    try std.testing.expectEqualSlices(u8, &first, &second);
    try std.testing.expectEqual(decision_event_version, std.mem.readInt(u16, first[0..2], .little));
}

test "evaluation reaches policy indices 255 and 256 without capacity disagreement" {
    const compiler_mod = compiler_for_testing;
    const capacity: Capacity = .{
        .max_connections = 2,
        .worker_count = 1,
        .max_policies = 257,
        .max_fields = 4,
        .max_matchers = 257,
        .max_actions = 4,
        .max_image_bytes = 32 * 1024,
        .max_record_bytes = 1024,
        .max_context_bytes = 256,
        .max_group_bytes = 128,
        .journal_events_per_worker = 8,
        .extension_queue_bytes = 128,
    };
    const field: compiler_mod.FieldSpec = .{
        .signal = .log,
        .value_kind = .string,
        .selector_id = 1,
        .name = "body",
    };
    const matchers = [_]compiler_mod.MatcherSpec{.{ .field = field, .opcode = .exists }};
    var id_storage: [257][8]u8 = undefined;
    var policies: [257]compiler_mod.PolicySpec = undefined;
    for (&policies, 0..) |*policy, index| {
        const id = std.fmt.bufPrint(&id_storage[index], "p{d}", .{index}) catch unreachable;
        policy.* = .{
            .id = id,
            .verdict = .keep,
            .priority = @intCast(index),
            .matchers = &matchers,
        };
    }
    var compiler_workspace: [1024]u8 = undefined;
    var image_storage: [32 * 1024]u8 = undefined;
    var compiler = try compiler_mod.Compiler.init(capacity, &compiler_workspace, &image_storage);
    const bytes_256 = try compiler.compile(.{ .policies = policies[0..256], .seed = 1 });
    var image_256 = try PolicyImage.open(bytes_256);
    var worker_storage: [WorkerState.requiredBytes(capacity)]u8 = undefined;
    var worker = try WorkerState.init(&worker_storage, capacity);
    var detail = worker.detailJournal();
    const values = [_]ValueRef{.{ .string = "present" }};
    const context: EvalContext = .{
        .image_epoch = 1,
        .worker_id = 0,
        .signal = .log,
        .record_key = "record",
        .detail_journal = &detail,
    };
    const decision_255 = evaluate(&image_256, &worker, &values, context);
    try std.testing.expectEqual(@as(u16, 255), decision_255.winning_policy_index);
    try std.testing.expect(detail.truncated);

    const bytes_257 = try compiler.compile(.{ .policies = &policies, .seed = 2 });
    var image_257 = try PolicyImage.open(bytes_257);
    const decision_256 = evaluate(&image_257, &worker, &values, context);
    try std.testing.expectEqual(@as(u16, 256), decision_256.winning_policy_index);

    var too_small = capacity;
    too_small.max_policies = 256;
    compiler = try compiler_mod.Compiler.init(too_small, &compiler_workspace, &image_storage);
    try std.testing.expectError(error.TooManyPolicies, compiler.compile(.{ .policies = &policies, .seed = 3 }));
}

test "native matcher VM agrees with direct operations on generated records" {
    const compiler_mod = compiler_for_testing;
    const capacity: Capacity = .{
        .max_connections = 1,
        .worker_count = 1,
        .max_policies = 3,
        .max_fields = 1,
        .max_matchers = 3,
        .max_actions = 1,
        .max_image_bytes = 1024,
        .max_record_bytes = 64,
        .max_context_bytes = 128,
        .max_group_bytes = 64,
        .journal_events_per_worker = 8,
        .extension_queue_bytes = 64,
    };
    const field: compiler_mod.FieldSpec = .{
        .signal = .log,
        .value_kind = .string,
        .selector_id = 1,
        .name = "body",
    };
    const matchers = [_]compiler_mod.MatcherSpec{
        .{ .field = field, .opcode = .exact, .value = .{ .string = "a" } },
        .{ .field = field, .opcode = .prefix, .value = .{ .string = "b" } },
        .{ .field = field, .opcode = .contains, .value = .{ .string = "c" } },
    };
    const policies = [_]compiler_mod.PolicySpec{
        .{ .id = "exact", .verdict = .keep, .priority = 1, .matchers = matchers[0..1] },
        .{ .id = "prefix", .verdict = .drop, .priority = 2, .matchers = matchers[1..2] },
        .{ .id = "contains", .verdict = .keep, .priority = 3, .matchers = matchers[2..3] },
    };
    var compiler_workspace: [128]u8 = undefined;
    var image_storage: [1024]u8 = undefined;
    var compiler = try compiler_mod.Compiler.init(capacity, &compiler_workspace, &image_storage);
    const bytes = try compiler.compile(.{ .policies = &policies, .seed = 1 });
    var image = try PolicyImage.open(bytes);
    var worker_storage: [WorkerState.requiredBytes(capacity)]u8 = undefined;
    var worker = try WorkerState.init(&worker_storage, capacity);
    var prng = std.Random.DefaultPrng.init(0x1234_5678);
    const random = prng.random();
    var record: [32]u8 = undefined;
    for (0..10_000) |_| {
        const len = random.intRangeAtMost(usize, 0, record.len);
        for (record[0..len]) |*byte| byte.* = random.intRangeAtMost(u8, 'a', 'z');
        const input = record[0..len];
        var expected: u16 = Decision.no_policy_index;
        if (std.mem.eql(u8, input, "a")) expected = 0;
        if (std.mem.startsWith(u8, input, "b")) expected = 1;
        if (std.mem.indexOf(u8, input, "c") != null) expected = 2;
        const values = [_]ValueRef{.{ .string = input }};
        const decision = evaluate(&image, &worker, &values, .{
            .image_epoch = 1,
            .worker_id = 0,
            .signal = .log,
            .record_key = input,
        });
        try std.testing.expectEqual(expected, decision.winning_policy_index);
    }
}
