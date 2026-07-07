//! Probabilistic Sampler
//!
//! Implements the OpenTelemetry consistent probability sampling specification:
//! https://opentelemetry.io/docs/specs/otel/trace/tracestate-probability-sampling/
//!
//! Used for both trace and log sampling. The sampling decision is based on
//! comparing a 56-bit randomness value (R) against a rejection threshold (T).
//! If R >= T, the item is kept; otherwise it is dropped.
//!
//! ## Threshold Calculation
//!
//! The threshold is derived from the configured percentage:
//!   T = floor((1 - percentage/100) * 2^56)
//!
//! For example:
//!   - 100% sampling: T = 0 (keep everything)
//!   - 50% sampling: T = 2^55 (keep half)
//!   - 0% sampling: T = 2^56 (keep nothing)
//!
//! ## Randomness Value (R)
//!
//! The randomness value is derived from the raw input **bytes** (never from a
//! hex-encoded string):
//!   - For 16+ byte inputs (e.g. 16-byte binary trace IDs): uses the last 7
//!     bytes directly per the OTel consistent probability sampling spec.
//!   - For shorter inputs (e.g. log sample keys): hashes all bytes with
//!     splitmix64 for uniform distribution.
//!   - If an explicit `rv` value is present in the tracestate, it is used
//!     directly as the randomness value.
//!
//! Callers are responsible for supplying raw bytes. Trace IDs must be passed
//! as their 16-byte binary representation via `accessor.typed_value` (returning
//! `TypedValue.bytes`). The engine decodes any necessary format conversion
//! before calling the sampler.
//!
//! ## Tracestate Handling
//!
//! The sampler reads and writes the `th` (threshold) and `rv` (randomness value)
//! keys in the `ot` vendor section of the tracestate header, following the W3C
//! tracestate specification and OTel probability sampling spec.
//!
//! Consistency check: when both `rv` and `th` are present in the incoming
//! tracestate, the sampler verifies `rv >= th`. If inconsistent, the threshold
//! is erased from the output.

const std = @import("std");
const proto = @import("proto");
const testing = std.testing;

const TraceSamplingConfig = proto.policy.TraceSamplingConfig;
const SamplingMode = proto.policy.SamplingMode;

/// Maximum value for 56-bit randomness/threshold (2^56)
const max_56bit: u64 = 1 << 56;

/// Default sampling precision (hex digits)
const default_precision: u32 = 4;

/// Default hash seed
const default_hash_seed: u32 = 0;

/// Probabilistic sampler following OTel consistent probability sampling spec.
/// Used for both trace and log percentage-based sampling.
pub const ProbabilisticSampler = struct {
    /// Rejection threshold (T). Items with R >= T are kept.
    threshold: u64,
    /// Sampling mode
    mode: SamplingMode,
    /// Hash seed for deterministic sampling
    hash_seed: u32,
    /// Precision for threshold encoding (1-14 hex digits)
    precision: u32,
    /// Whether to reject on errors
    fail_closed: bool,
    /// Original percentage for reference
    percentage: f32,

    /// Initialize sampler from TraceSamplingConfig (used for trace policies).
    pub fn init(config: ?*const TraceSamplingConfig) ProbabilisticSampler {
        if (config == null) {
            // No config = keep all
            return .{
                .threshold = 0,
                .mode = .SAMPLING_MODE_HASH_SEED,
                .hash_seed = default_hash_seed,
                .precision = default_precision,
                .fail_closed = true,
                .percentage = 100.0,
            };
        }

        const cfg = config.?;
        const percentage = cfg.percentage;

        // Calculate threshold: T = floor((1 - percentage/100) * 2^56)
        const threshold = calculateThreshold(percentage);

        return .{
            .threshold = threshold,
            .mode = cfg.mode orelse .SAMPLING_MODE_HASH_SEED,
            .hash_seed = cfg.hash_seed orelse default_hash_seed,
            .precision = @min(14, @max(1, cfg.sampling_precision orelse default_precision)),
            .fail_closed = cfg.fail_closed orelse true,
            .percentage = percentage,
        };
    }

    /// Initialize sampler from a simple percentage (used for log policies).
    pub fn initFromPercentage(percentage: u8) ProbabilisticSampler {
        return .{
            .threshold = calculateThreshold(@floatFromInt(percentage)),
            .mode = .SAMPLING_MODE_HASH_SEED,
            .hash_seed = default_hash_seed,
            .precision = default_precision,
            .fail_closed = true,
            .percentage = @floatFromInt(percentage),
        };
    }

    /// Simple keep/drop decision on raw input bytes.
    /// For callers that don't need tracestate or SamplingResult.
    pub fn shouldKeep(self: ProbabilisticSampler, input: []const u8) bool {
        return self.sample(input, "").keep;
    }

    /// Independent random keep/drop for unkeyed log percentage sampling.
    /// Per spec v1.6.0, without a sample_key each record MUST be sampled with a
    /// fresh high-quality random value — never derived from timestamps or
    /// record content — so this is intentionally not idempotent.
    pub fn shouldKeepRandom(self: ProbabilisticSampler, io: std.Io) bool {
        if (self.percentage >= 100.0) return true;
        if (self.percentage <= 0.0) return false;
        var buf: [8]u8 = undefined;
        io.random(&buf);
        const r = std.mem.readInt(u64, &buf, .little) & (max_56bit - 1);
        return r >= self.threshold;
    }

    /// Calculate threshold from percentage
    /// T = floor((1 - percentage/100) * 2^56)
    pub fn calculateThreshold(percentage: f32) u64 {
        if (percentage >= 100.0) return 0; // Keep all
        if (percentage <= 0.0) return max_56bit; // Keep none

        const ratio = 1.0 - (@as(f64, percentage) / 100.0);
        const threshold_f = ratio * @as(f64, @floatFromInt(max_56bit));
        return @intFromFloat(@min(@as(f64, @floatFromInt(max_56bit)), @max(0.0, threshold_f)));
    }

    /// Convert a threshold value back to probability: prob = 1 - T / 2^56
    fn thresholdToProbability(t: u64) f64 {
        if (t >= max_56bit) return 0.0;
        if (t == 0) return 1.0;
        return 1.0 - @as(f64, @floatFromInt(t)) / @as(f64, @floatFromInt(max_56bit));
    }

    /// Convert a probability to threshold: T = floor((1 - prob) * 2^56)
    fn probabilityToThreshold(prob: f64) u64 {
        if (prob >= 1.0) return 0;
        if (prob <= 0.0) return max_56bit;
        const t = (1.0 - prob) * @as(f64, @floatFromInt(max_56bit));
        return @intFromFloat(@min(@as(f64, @floatFromInt(max_56bit)), @max(0.0, t)));
    }

    /// Make sampling decision for an item.
    ///
    /// Returns a SamplingResult with:
    /// - keep: whether to keep the item
    /// - new_threshold: threshold to write to tracestate (if sampling)
    /// - rv: explicit randomness value to preserve in tracestate (if present)
    pub fn sample(self: ProbabilisticSampler, input: []const u8, tracestate: []const u8) SamplingResult {
        // Edge cases
        if (self.percentage >= 100.0) {
            return .{ .keep = true, .new_threshold = encodeThresholdValue(0, self.precision), .rv = null };
        }
        if (self.percentage <= 0.0) {
            return .{ .keep = false, .new_threshold = null, .rv = null };
        }

        // Parse tracestate for rv and th
        const ts_info = parseOtFromTracestate(tracestate);

        // If explicit rv is present, use it as the randomness value
        const r: ?u64 = if (ts_info.rv) |rv_val|
            rv_val
        else
            self.computeRandomness(input);

        // If randomness couldn't be derived, respect fail_closed setting.
        // Per spec, threshold must be erased for spans with unknown probability.
        if (r == null) {
            return .{ .keep = !self.fail_closed, .new_threshold = null, .rv = null };
        }

        // Consistency check: if both rv and th are present, verify rv >= th
        if (ts_info.rv != null and ts_info.th != null) {
            if (ts_info.rv.? < ts_info.th.?) {
                // Inconsistent — erase threshold from output
                return .{ .keep = true, .new_threshold = null, .rv = ts_info.rv_hex };
            }
        }

        return switch (self.mode) {
            .SAMPLING_MODE_UNSPECIFIED, .SAMPLING_MODE_HASH_SEED => self.sampleHashSeed(r.?, ts_info.rv_hex),
            .SAMPLING_MODE_PROPORTIONAL => self.sampleProportional(r.?, ts_info.th, ts_info.rv_hex),
            .SAMPLING_MODE_EQUALIZING => self.sampleEqualizing(r.?, ts_info.th, ts_info.rv_hex),
            _ => self.sampleHashSeed(r.?, ts_info.rv_hex), // Unknown mode defaults to hash_seed
        };
    }

    /// Hash seed mode: deterministic sampling based on input hash
    fn sampleHashSeed(self: ProbabilisticSampler, r: u64, rv_hex: ?[]const u8) SamplingResult {
        const keep = r >= self.threshold;
        return .{
            .keep = keep,
            .new_threshold = if (keep) encodeThresholdValue(self.threshold, self.precision) else null,
            .rv = rv_hex,
        };
    }

    /// Proportional mode: multiply incoming probability with configured probability.
    ///
    /// Per OTel spec:
    ///   T_o = ProbabilityToThreshold(p * ThresholdToProbability(T_s))
    /// where p is the configured probability and T_s is the existing threshold.
    fn sampleProportional(
        self: ProbabilisticSampler,
        r: u64,
        existing_threshold: ?u64,
        rv_hex: ?[]const u8,
    ) SamplingResult {
        if (existing_threshold) |existing_t| {
            // Compute product threshold
            const prob_s = thresholdToProbability(existing_t);
            const prob_configured = thresholdToProbability(self.threshold);
            const prob_o = prob_configured * prob_s;
            const t_o = probabilityToThreshold(prob_o);

            // If product threshold is maximum (probability effectively zero), reject
            if (t_o >= max_56bit) {
                return .{ .keep = false, .new_threshold = null, .rv = rv_hex };
            }

            const keep = r >= t_o;
            return .{
                .keep = keep,
                .new_threshold = if (keep) encodeThresholdValue(t_o, self.precision) else null,
                .rv = rv_hex,
            };
        }

        // No existing threshold - use hash seed behavior
        return self.sampleHashSeed(r, rv_hex);
    }

    /// Equalizing mode: aim for equal threshold after this sampling stage.
    ///
    /// Per OTel spec:
    /// - When T_s > T_d (existing more restrictive): pass through, outbound = T_s
    /// - When T_s <= T_d: keep if R >= T_d, outbound = T_d
    fn sampleEqualizing(
        self: ProbabilisticSampler,
        r: u64,
        existing_threshold: ?u64,
        rv_hex: ?[]const u8,
    ) SamplingResult {
        if (existing_threshold) |existing_t| {
            if (existing_t > self.threshold) {
                // Existing threshold is more restrictive — cannot lower it,
                // so pass the span through with its existing threshold.
                return .{
                    .keep = true,
                    .new_threshold = encodeThresholdValue(existing_t, self.precision),
                    .rv = rv_hex,
                };
            }

            // Apply our threshold to equalize
            const keep = r >= self.threshold;
            return .{
                .keep = keep,
                .new_threshold = if (keep) encodeThresholdValue(self.threshold, self.precision) else null,
                .rv = rv_hex,
            };
        }

        // No existing threshold - use hash seed behavior
        return self.sampleHashSeed(r, rv_hex);
    }

    /// Compute 56-bit randomness value from raw input bytes.
    ///
    /// Per the OTel consistent probability sampling spec, the least-significant
    /// 56 bits of a 128-bit trace ID ARE the randomness value (last 7 bytes).
    /// Callers must supply raw bytes — hex-encoded strings are not accepted.
    ///
    /// - 16+ byte input: extracts the last 7 bytes as the 56-bit randomness value.
    /// - Shorter non-empty input (e.g. log sample keys): hashes with splitmix64.
    /// - Empty input: returns null (randomness cannot be derived).
    fn computeRandomness(self: ProbabilisticSampler, input: []const u8) ?u64 {
        if (input.len >= 16) {
            var r: u64 = 0;
            for (input[input.len - 7 ..]) |b| {
                r = (r << 8) | b;
            }
            return r & (max_56bit - 1);
        } else if (input.len > 0) {
            // Shorter input (log sample keys, etc.) — hash for uniform distribution.
            var r: u64 = 0;
            for (input) |b| {
                r = (r << 8) ^ b;
            }
            r ^= @as(u64, self.hash_seed);
            r = mixHash(r);
            return r & (max_56bit - 1);
        }
        return null;
    }

    /// Encode a threshold as a hex string for tracestate.
    /// Uses a struct-local buffer; returned slice is valid until next call.
    pub fn encodeThreshold(self: ProbabilisticSampler) []const u8 {
        return encodeThresholdValue(self.threshold, self.precision);
    }

    /// splitmix64 hash mixing function for good avalanche properties
    fn mixHash(x: u64) u64 {
        var h = x +% 0x9e3779b97f4a7c15;
        h = (h ^ (h >> 30)) *% 0xbf58476d1ce4e5b9;
        h = (h ^ (h >> 27)) *% 0x94d049bb133111eb;
        return h ^ (h >> 31);
    }
};

/// Encode a threshold value as a hex string for tracestate.
/// Returns a slice from a thread-local buffer — caller should copy if persistence needed.
fn encodeThresholdValue(threshold: u64, precision: u32) []const u8 {
    const S = struct {
        threadlocal var buf: [14]u8 = undefined;
    };

    const p = if (precision < 1) 4 else if (precision > 14) 14 else precision;

    const hex_chars = "0123456789abcdef";
    var len: usize = 0;

    // Encode p nibbles from the top of the 56-bit threshold
    var i: u32 = 0;
    while (i < p) : (i += 1) {
        const shift = @as(u6, @intCast(52 -| (i * 4)));
        const nibble = @as(u4, @truncate(threshold >> shift));
        S.buf[len] = hex_chars[nibble];
        len += 1;
    }

    // Strip trailing zeros per W3C tracestate spec
    while (len > 0 and S.buf[len - 1] == '0') {
        len -= 1;
    }

    // Always return at least "0"
    if (len == 0) {
        S.buf[0] = '0';
        len = 1;
    }

    return S.buf[0..len];
}

/// Result of sampling decision
pub const SamplingResult = struct {
    /// Whether to keep the item
    keep: bool,
    /// New threshold to write to tracestate (null if not sampling)
    new_threshold: ?[]const u8,
    /// Explicit randomness value to preserve in outgoing tracestate (null if not present)
    rv: ?[]const u8,
};

/// Parsed OT vendor section from tracestate
const OtTracestateInfo = struct {
    /// Parsed threshold value (numeric)
    th: ?u64,
    /// Parsed randomness value (numeric)
    rv: ?u64,
    /// Raw rv hex string to preserve in output
    rv_hex: ?[]const u8,
};

/// Parse the `ot=...` vendor section from a tracestate header.
/// Extracts both `th` (threshold) and `rv` (randomness value) keys.
fn parseOtFromTracestate(tracestate: []const u8) OtTracestateInfo {
    var info: OtTracestateInfo = .{ .th = null, .rv = null, .rv_hex = null };
    if (tracestate.len == 0) return info;

    // Look for "ot=..." vendor section
    var it = std.mem.splitScalar(u8, tracestate, ',');
    while (it.next()) |entry| {
        const trimmed = std.mem.trim(u8, entry, " ");
        if (std.mem.startsWith(u8, trimmed, "ot=")) {
            const ot_value = trimmed[3..];
            // Parse both th and rv from the ot value
            var kv_it = std.mem.splitScalar(u8, ot_value, ';');
            while (kv_it.next()) |kv| {
                if (std.mem.startsWith(u8, kv, "th:")) {
                    info.th = parseHexThreshold(kv[3..]);
                } else if (std.mem.startsWith(u8, kv, "rv:")) {
                    const hex = kv[3..];
                    info.rv = parseHexThreshold(hex);
                    info.rv_hex = hex;
                }
            }
            return info;
        }
    }

    return info;
}

/// Parse hex threshold value to u64
fn parseHexThreshold(hex: []const u8) ?u64 {
    if (hex.len == 0 or hex.len > 14) return null;

    var threshold: u64 = 0;
    for (hex) |c| {
        const digit: u64 = switch (c) {
            '0'...'9' => c - '0',
            'a'...'f' => c - 'a' + 10,
            'A'...'F' => c - 'A' + 10,
            else => return null,
        };
        threshold = (threshold << 4) | digit;
    }

    // Shift to fill 56 bits (14 hex digits = 56 bits)
    // If fewer digits provided, shift left to fill
    const shift: u6 = @intCast((14 - hex.len) * 4);
    return threshold << shift;
}

/// Maximum size for tracestate buffer (W3C spec allows up to ~8KB, but we use a reasonable limit)
pub const max_tracestate_len: usize = 512;

/// Update tracestate with sampling threshold and optional randomness value.
/// Adds or updates the `ot=th:THRESHOLD[;rv:VALUE]` entry in the tracestate.
///
/// Writes the result to the provided buffer and returns a slice of the written data.
/// Returns null if the buffer is too small.
///
/// Per W3C tracestate spec:
/// - Maximum 32 entries
/// - Our entry goes at the beginning (most recent sampler)
/// - If ot vendor already exists, update the th/rv values
pub fn updateTracestateInPlace(
    buf: []u8,
    existing_tracestate: []const u8,
    threshold_hex: []const u8,
) ?[]u8 {
    return updateTracestateInPlaceWithRv(buf, existing_tracestate, threshold_hex, null);
}

/// Update tracestate with sampling threshold and optional rv (randomness value).
pub fn updateTracestateInPlaceWithRv(
    buf: []u8,
    existing_tracestate: []const u8,
    threshold_hex: []const u8,
    rv_hex: ?[]const u8,
) ?[]u8 {
    // Build the new ot entry: "ot=th:THRESHOLD" or "ot=th:THRESHOLD;rv:VALUE"
    var new_ot_buf: [64]u8 = undefined;
    const new_ot = if (rv_hex) |rv|
        std.fmt.bufPrint(&new_ot_buf, "ot=th:{s};rv:{s}", .{ threshold_hex, rv }) catch return null
    else
        std.fmt.bufPrint(&new_ot_buf, "ot=th:{s}", .{threshold_hex}) catch return null;

    var pos: usize = 0;

    // Add our ot entry first (most recent sampler)
    if (pos + new_ot.len > buf.len) return null;
    @memcpy(buf[pos..][0..new_ot.len], new_ot);
    pos += new_ot.len;

    if (existing_tracestate.len == 0) {
        return buf[0..pos];
    }

    // Process existing entries
    var it = std.mem.splitScalar(u8, existing_tracestate, ',');
    var entry_count: usize = 1; // We already added one

    while (it.next()) |entry| {
        const trimmed = std.mem.trim(u8, entry, " ");
        if (trimmed.len == 0) continue;

        // Skip existing ot entry (we're replacing it)
        if (std.mem.startsWith(u8, trimmed, "ot=")) continue;

        // Check entry limit (W3C spec: max 32 entries)
        if (entry_count >= 32) break;

        // Check buffer space: need comma + entry
        if (pos + 1 + trimmed.len > buf.len) break;

        buf[pos] = ',';
        pos += 1;
        @memcpy(buf[pos..][0..trimmed.len], trimmed);
        pos += trimmed.len;
        entry_count += 1;
    }

    return buf[0..pos];
}

/// Compute the threshold hex string for a given percentage.
/// This is a standalone helper for when you don't have a full ProbabilisticSampler.
/// Returns a thread-local buffer - caller should copy if persistence needed.
pub fn thresholdHexFromPercentage(percentage: f32, precision: u32) []const u8 {
    return encodeThresholdValue(
        ProbabilisticSampler.calculateThreshold(percentage),
        @min(14, @max(1, precision)),
    );
}

// =============================================================================
// Tests
// =============================================================================

const sample_trace_id: [16]u8 = .{
    0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c,
    0x0d, 0x0e, 0x0f, 0x10,
};

test "ProbabilisticSampler: 100% keeps all" {
    const config: TraceSamplingConfig = .{
        .percentage = 100.0,
        .mode = null,
        .sampling_precision = null,
        .hash_seed = null,
        .fail_closed = null,
    };
    const sampler = ProbabilisticSampler.init(&config);

    // All trace IDs should be kept
    const trace_id = sample_trace_id;
    const result = sampler.sample(&trace_id, "");

    try testing.expect(result.keep);
}

test "ProbabilisticSampler: 0% rejects all" {
    const config: TraceSamplingConfig = .{
        .percentage = 0.0,
        .mode = null,
        .sampling_precision = null,
        .hash_seed = null,
        .fail_closed = null,
    };
    const sampler = ProbabilisticSampler.init(&config);

    const trace_id = sample_trace_id;
    const result = sampler.sample(&trace_id, "");

    try testing.expect(!result.keep);
}

test "ProbabilisticSampler: null config keeps all" {
    const sampler = ProbabilisticSampler.init(null);

    const trace_id = sample_trace_id;
    const result = sampler.sample(&trace_id, "");

    try testing.expect(result.keep);
}

test "ProbabilisticSampler: deterministic for same input" {
    const config: TraceSamplingConfig = .{
        .percentage = 50.0,
        .mode = null,
        .sampling_precision = null,
        .hash_seed = null,
        .fail_closed = null,
    };
    const sampler = ProbabilisticSampler.init(&config);

    const trace_id = sample_trace_id;

    const first_result = sampler.sample(&trace_id, "");
    for (0..100) |_| {
        const result = sampler.sample(&trace_id, "");
        try testing.expectEqual(first_result.keep, result.keep);
    }
}

test "ProbabilisticSampler: hash_seed affects sampling for short inputs" {
    const config1: TraceSamplingConfig = .{
        .percentage = 50.0,
        .mode = .SAMPLING_MODE_HASH_SEED,
        .sampling_precision = null,
        .hash_seed = 0,
        .fail_closed = null,
    };
    const config2: TraceSamplingConfig = .{
        .percentage = 50.0,
        .mode = .SAMPLING_MODE_HASH_SEED,
        .sampling_precision = null,
        .hash_seed = 12345,
        .fail_closed = null,
    };

    const sampler1 = ProbabilisticSampler.init(&config1);
    const sampler2 = ProbabilisticSampler.init(&config2);

    // hash_seed affects short inputs (log sample keys) where hashing is applied.
    // For 16-byte trace IDs, hash_seed is NOT applied per OTel spec.
    var different_count: u32 = 0;
    for (0..100) |i| {
        var input: [8]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0 };
        input[7] = @intCast(i);

        const r1 = sampler1.sample(&input, "");
        const r2 = sampler2.sample(&input, "");

        if (r1.keep != r2.keep) different_count += 1;
    }

    // With different seeds, we expect some results to differ
    try testing.expect(different_count > 0);
}

test "ProbabilisticSampler: approximate distribution for 50%" {
    const config: TraceSamplingConfig = .{
        .percentage = 50.0,
        .mode = null,
        .sampling_precision = null,
        .hash_seed = null,
        .fail_closed = null,
    };
    const sampler = ProbabilisticSampler.init(&config);

    var kept: u32 = 0;
    const total: u32 = 10000;

    for (0..total) |i| {
        var trace_id = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        // Per OTel spec, randomness is the least-significant 56 bits of the
        // trace ID (last 7 bytes), used directly without hashing.
        // Distribute across the full 56-bit range by varying the most
        // significant byte (index 9) uniformly and using lower bytes for detail.
        trace_id[9] = @intCast((i * 256 / total) & 0xff);
        trace_id[10] = @intCast(i & 0xff);
        trace_id[11] = @intCast((i >> 8) & 0xff);

        const result = sampler.sample(&trace_id, "");
        if (result.keep) kept += 1;
    }

    const ratio = @as(f64, @floatFromInt(kept)) / @as(f64, @floatFromInt(total));
    try testing.expect(ratio > 0.45 and ratio < 0.55);
}

test "ProbabilisticSampler: threshold calculation" {
    // 100% = threshold 0 (keep all)
    try testing.expectEqual(@as(u64, 0), ProbabilisticSampler.calculateThreshold(100.0));

    // 0% = threshold MAX (keep none)
    try testing.expectEqual(max_56bit, ProbabilisticSampler.calculateThreshold(0.0));

    // 50% = threshold is half of MAX
    const half_threshold = ProbabilisticSampler.calculateThreshold(50.0);
    const expected_half = max_56bit / 2;
    try testing.expect(half_threshold > expected_half - 1000 and half_threshold < expected_half + 1000);
}

test "ProbabilisticSampler: initFromPercentage" {
    const sampler = ProbabilisticSampler.initFromPercentage(50);
    try testing.expectEqual(@as(f32, 50.0), sampler.percentage);

    // 0% rejects all
    const zero = ProbabilisticSampler.initFromPercentage(0);
    try testing.expect(!zero.shouldKeep("anything"));

    // 100% keeps all
    const full = ProbabilisticSampler.initFromPercentage(100);
    try testing.expect(full.shouldKeep("anything"));
}

test "ProbabilisticSampler: shouldKeepRandom edge cases and distribution" {
    const io = std.Options.debug_io;

    // 100% keeps all, 0% rejects all
    try testing.expect(ProbabilisticSampler.initFromPercentage(100).shouldKeepRandom(io));
    try testing.expect(!ProbabilisticSampler.initFromPercentage(0).shouldKeepRandom(io));

    // Independent random decisions approximate the configured percentage
    const sampler = ProbabilisticSampler.initFromPercentage(50);
    var kept: u32 = 0;
    const total: u32 = 10000;
    for (0..total) |_| {
        if (sampler.shouldKeepRandom(io)) kept += 1;
    }
    const ratio = @as(f64, @floatFromInt(kept)) / @as(f64, @floatFromInt(total));
    try testing.expect(ratio > 0.45 and ratio < 0.55);
}

test "ProbabilisticSampler: shouldKeep matches sample" {
    const sampler = ProbabilisticSampler.initFromPercentage(50);
    const input = "test-input-bytes";

    // shouldKeep should match sample().keep
    try testing.expectEqual(sampler.sample(input, "").keep, sampler.shouldKeep(input));
}

test "ProbabilisticSampler: proportional mode computes product threshold" {
    // Configure sampler at 50%
    const config: TraceSamplingConfig = .{
        .percentage = 50.0,
        .mode = .SAMPLING_MODE_PROPORTIONAL,
        .sampling_precision = 14,
        .hash_seed = null,
        .fail_closed = null,
    };
    const sampler = ProbabilisticSampler.init(&config);

    // Existing threshold at 50% (th:8 = 0x80000000000000)
    // Proportional: 50% * 50% = 25%, so product threshold should be ~75% of max_56bit
    // T_o = ProbabilityToThreshold(0.5 * 0.5) = ProbabilityToThreshold(0.25)
    // T_o = (1 - 0.25) * 2^56 = 0.75 * 2^56

    var kept: u32 = 0;
    const total: u32 = 10000;

    for (0..total) |i| {
        var trace_id = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        trace_id[9] = @intCast((i * 256 / total) & 0xff);
        trace_id[10] = @intCast(i & 0xff);
        trace_id[11] = @intCast((i >> 8) & 0xff);

        const result = sampler.sample(&trace_id, "ot=th:8");
        if (result.keep) kept += 1;
    }

    // With 50% configured and 50% existing, effective should be ~25%
    const ratio = @as(f64, @floatFromInt(kept)) / @as(f64, @floatFromInt(total));
    try testing.expect(ratio > 0.20 and ratio < 0.30);
}

test "ProbabilisticSampler: proportional mode with no existing threshold falls back to hash_seed" {
    const config: TraceSamplingConfig = .{
        .percentage = 50.0,
        .mode = .SAMPLING_MODE_PROPORTIONAL,
        .sampling_precision = null,
        .hash_seed = null,
        .fail_closed = null,
    };
    const sampler = ProbabilisticSampler.init(&config);

    // No tracestate — should behave like hash_seed mode
    var kept: u32 = 0;
    const total: u32 = 10000;

    for (0..total) |i| {
        var trace_id = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        trace_id[9] = @intCast((i * 256 / total) & 0xff);
        trace_id[10] = @intCast(i & 0xff);
        trace_id[11] = @intCast((i >> 8) & 0xff);

        const result = sampler.sample(&trace_id, "");
        if (result.keep) kept += 1;
    }

    const ratio = @as(f64, @floatFromInt(kept)) / @as(f64, @floatFromInt(total));
    try testing.expect(ratio > 0.45 and ratio < 0.55);
}

test "ProbabilisticSampler: equalizing mode passes through more restrictive threshold" {
    // Configure sampler at 50% (threshold = 0x80000000000000)
    const config: TraceSamplingConfig = .{
        .percentage = 50.0,
        .mode = .SAMPLING_MODE_EQUALIZING,
        .sampling_precision = 14,
        .hash_seed = null,
        .fail_closed = null,
    };
    const sampler = ProbabilisticSampler.init(&config);

    // Existing threshold at 25% (th:c = 0xc0000000000000, more restrictive)
    // Since existing is more restrictive, all spans should pass through
    const trace_id = sample_trace_id;
    const result = sampler.sample(&trace_id, "ot=th:c");

    // Existing threshold (c = 0xc...) > sampler threshold (8 = 0x8...)
    // Per spec: pass through with existing threshold
    try testing.expect(result.keep);
    try testing.expect(result.new_threshold != null);
    // Output threshold should encode the existing (more restrictive) threshold
    try testing.expect(result.new_threshold.?[0] == 'c');
}

test "ProbabilisticSampler: equalizing mode applies own threshold when less restrictive" {
    // Configure sampler at 25% (threshold = 0xc0000000000000)
    const config: TraceSamplingConfig = .{
        .percentage = 25.0,
        .mode = .SAMPLING_MODE_EQUALIZING,
        .sampling_precision = 14,
        .hash_seed = null,
        .fail_closed = null,
    };
    const sampler = ProbabilisticSampler.init(&config);

    // Existing threshold at 50% (th:8 = 0x80000000000000, less restrictive)
    // Since our threshold is more restrictive, we should apply ours
    var kept: u32 = 0;
    const total: u32 = 10000;

    for (0..total) |i| {
        var trace_id = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        trace_id[9] = @intCast((i * 256 / total) & 0xff);
        trace_id[10] = @intCast(i & 0xff);
        trace_id[11] = @intCast((i >> 8) & 0xff);

        const result = sampler.sample(&trace_id, "ot=th:8");
        if (result.keep) kept += 1;
    }

    // Should sample at ~25% (our more restrictive threshold)
    const ratio = @as(f64, @floatFromInt(kept)) / @as(f64, @floatFromInt(total));
    try testing.expect(ratio > 0.20 and ratio < 0.30);
}

test "ProbabilisticSampler: rv from tracestate used as randomness" {
    // Configure sampler at 50% (threshold = 0x80000000000000)
    const config: TraceSamplingConfig = .{
        .percentage = 50.0,
        .mode = .SAMPLING_MODE_HASH_SEED,
        .sampling_precision = null,
        .hash_seed = null,
        .fail_closed = null,
    };
    const sampler = ProbabilisticSampler.init(&config);

    // rv:ff... = very high randomness, should always be kept at 50%
    // th:0 means upstream kept everything (consistent: rv >= 0)
    const trace_id = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    const result_high = sampler.sample(&trace_id, "ot=th:0;rv:ffffffffffffff");
    try testing.expect(result_high.keep);

    // rv:01... = very low randomness, should be dropped at 50%
    // th:0 means upstream kept everything (consistent: rv >= 0)
    const result_low = sampler.sample(&trace_id, "ot=th:0;rv:01000000000000");
    try testing.expect(!result_low.keep);
}

test "ProbabilisticSampler: rv preserved in output" {
    const config: TraceSamplingConfig = .{
        .percentage = 50.0,
        .mode = .SAMPLING_MODE_HASH_SEED,
        .sampling_precision = null,
        .hash_seed = null,
        .fail_closed = null,
    };
    const sampler = ProbabilisticSampler.init(&config);

    const trace_id = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    const result = sampler.sample(&trace_id, "ot=th:0;rv:ffffffffffffff");

    // rv should be preserved in the output
    try testing.expect(result.rv != null);
    try testing.expectEqualStrings("ffffffffffffff", result.rv.?);
}

test "ProbabilisticSampler: inconsistent rv/th erases threshold" {
    const config: TraceSamplingConfig = .{
        .percentage = 50.0,
        .mode = .SAMPLING_MODE_HASH_SEED,
        .sampling_precision = null,
        .hash_seed = null,
        .fail_closed = null,
    };
    const sampler = ProbabilisticSampler.init(&config);

    // rv < th means the span should not have been sampled at this threshold,
    // which is inconsistent. The sampler should erase the threshold.
    // rv:1 = 0x10000000000000, th:8 = 0x80000000000000 => rv < th, inconsistent
    const trace_id = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    const result = sampler.sample(&trace_id, "ot=th:8;rv:1");

    // Inconsistent: should keep (sampled flag says sampled) but erase threshold
    try testing.expect(result.keep);
    try testing.expect(result.new_threshold == null);
    // rv should still be preserved
    try testing.expect(result.rv != null);
}

test "parseOtFromTracestate: empty" {
    const info = parseOtFromTracestate("");
    try testing.expect(info.th == null);
    try testing.expect(info.rv == null);
}

test "parseOtFromTracestate: th only" {
    const info = parseOtFromTracestate("ot=th:8");
    try testing.expect(info.th != null);
    try testing.expectEqual(@as(u64, 0x80000000000000), info.th.?);
    try testing.expect(info.rv == null);
}

test "parseOtFromTracestate: th and rv" {
    const info = parseOtFromTracestate("ot=th:8;rv:abcd");
    try testing.expect(info.th != null);
    try testing.expectEqual(@as(u64, 0x80000000000000), info.th.?);
    try testing.expect(info.rv != null);
    try testing.expectEqual(@as(u64, 0xabcd0000000000), info.rv.?);
    try testing.expectEqualStrings("abcd", info.rv_hex.?);
}

test "parseOtFromTracestate: multiple entries with ot" {
    const info = parseOtFromTracestate("vendor1=val1,ot=th:4;rv:ff,vendor2=val2");
    try testing.expect(info.th != null);
    try testing.expectEqual(@as(u64, 0x40000000000000), info.th.?);
    try testing.expect(info.rv != null);
    try testing.expectEqual(@as(u64, 0xff000000000000), info.rv.?);
}

test "parseHexThreshold: single digit" {
    try testing.expectEqual(@as(?u64, 0x10000000000000), parseHexThreshold("1"));
    try testing.expectEqual(@as(?u64, 0x80000000000000), parseHexThreshold("8"));
    try testing.expectEqual(@as(?u64, 0xf0000000000000), parseHexThreshold("f"));
}

test "parseHexThreshold: multiple digits" {
    try testing.expectEqual(@as(?u64, 0x12000000000000), parseHexThreshold("12"));
    try testing.expectEqual(@as(?u64, 0x12340000000000), parseHexThreshold("1234"));
}

test "updateTracestateInPlace: empty tracestate" {
    var buf: [max_tracestate_len]u8 = undefined;
    const result = updateTracestateInPlace(&buf, "", "8");
    try testing.expect(result != null);
    try testing.expectEqualStrings("ot=th:8", result.?);
}

test "updateTracestateInPlace: existing entries preserved" {
    var buf: [max_tracestate_len]u8 = undefined;
    const result = updateTracestateInPlace(&buf, "vendor1=val1,vendor2=val2", "8");
    try testing.expect(result != null);
    try testing.expectEqualStrings("ot=th:8,vendor1=val1,vendor2=val2", result.?);
}

test "updateTracestateInPlace: existing ot entry replaced" {
    var buf: [max_tracestate_len]u8 = undefined;
    const result = updateTracestateInPlace(&buf, "ot=th:4,vendor1=val1", "8");
    try testing.expect(result != null);
    try testing.expectEqualStrings("ot=th:8,vendor1=val1", result.?);
}

test "updateTracestateInPlace: ot entry moved to front" {
    var buf: [max_tracestate_len]u8 = undefined;
    const result = updateTracestateInPlace(&buf, "vendor1=val1,ot=th:4,vendor2=val2", "8");
    try testing.expect(result != null);
    try testing.expectEqualStrings("ot=th:8,vendor1=val1,vendor2=val2", result.?);
}

test "updateTracestateInPlace: buffer too small returns null" {
    var buf: [5]u8 = undefined; // Too small to fit "ot=th:8"
    const result = updateTracestateInPlace(&buf, "", "8");
    try testing.expect(result == null);
}

test "updateTracestateInPlaceWithRv: includes rv" {
    var buf: [max_tracestate_len]u8 = undefined;
    const result = updateTracestateInPlaceWithRv(&buf, "", "8", "abcd");
    try testing.expect(result != null);
    try testing.expectEqualStrings("ot=th:8;rv:abcd", result.?);
}

test "updateTracestateInPlaceWithRv: replaces existing ot with rv" {
    var buf: [max_tracestate_len]u8 = undefined;
    const result = updateTracestateInPlaceWithRv(&buf, "ot=th:4;rv:1234,vendor=val", "8", "abcd");
    try testing.expect(result != null);
    try testing.expectEqualStrings("ot=th:8;rv:abcd,vendor=val", result.?);
}

test "thresholdHexFromPercentage: 50%" {
    const hex = thresholdHexFromPercentage(50.0, 4);
    // 50% means threshold = 2^55 = 0x80000000000000
    // Encoded with 4 digits precision (encodes top 4 nibbles)
    // The encoding extracts nibbles from the threshold by shifting
    try testing.expect(hex.len > 0);
    try testing.expect(hex[0] == '8'); // First nibble is 8
}

test "thresholdHexFromPercentage: 100%" {
    const hex = thresholdHexFromPercentage(100.0, 4);
    // 100% means threshold = 0
    try testing.expectEqualStrings("0", hex);
}

test "ProbabilisticSampler: thresholdToProbability and probabilityToThreshold roundtrip" {
    // 50% -> threshold -> probability should roundtrip
    const threshold_50 = ProbabilisticSampler.calculateThreshold(50.0);
    const prob = ProbabilisticSampler.thresholdToProbability(threshold_50);
    try testing.expect(prob > 0.499 and prob < 0.501);

    // Roundtrip: probability -> threshold -> probability
    const t = ProbabilisticSampler.probabilityToThreshold(0.25);
    const p = ProbabilisticSampler.thresholdToProbability(t);
    try testing.expect(p > 0.249 and p < 0.251);

    // Edge cases
    try testing.expectEqual(@as(f64, 1.0), ProbabilisticSampler.thresholdToProbability(0));
    try testing.expectEqual(@as(f64, 0.0), ProbabilisticSampler.thresholdToProbability(max_56bit));
    try testing.expectEqual(@as(u64, 0), ProbabilisticSampler.probabilityToThreshold(1.0));
    try testing.expectEqual(max_56bit, ProbabilisticSampler.probabilityToThreshold(0.0));
}

test "ProbabilisticSampler: fail_closed=true drops on empty input" {
    const config: TraceSamplingConfig = .{
        .percentage = 50.0,
        .fail_closed = true,
    };
    const sampler = ProbabilisticSampler.init(&config);

    // Empty input → no randomness → fail_closed=true → drop
    const result = sampler.sample("", "");
    try testing.expect(!result.keep);
    try testing.expect(result.new_threshold == null);
}

test "ProbabilisticSampler: fail_closed=false keeps on empty input" {
    const config: TraceSamplingConfig = .{
        .percentage = 50.0,
        .fail_closed = false,
    };
    const sampler = ProbabilisticSampler.init(&config);

    // Empty input → no randomness → fail_closed=false → keep
    const result = sampler.sample("", "");
    try testing.expect(result.keep);
    try testing.expect(result.new_threshold == null);
}

test "ProbabilisticSampler: fail_closed defaults to true when null" {
    const config: TraceSamplingConfig = .{
        .percentage = 50.0,
        .fail_closed = null,
    };
    const sampler = ProbabilisticSampler.init(&config);

    // Empty input → no randomness → default fail_closed=true → drop
    const result = sampler.sample("", "");
    try testing.expect(!result.keep);
}

test "ProbabilisticSampler: binary trace_id 100% keeps all" {
    const sampler = ProbabilisticSampler.initFromPercentage(100);
    const trace_id = sample_trace_id;
    const result = sampler.sample(&trace_id, "");
    try testing.expect(result.keep);
}

test "ProbabilisticSampler: binary trace_id 0% rejects all" {
    const sampler = ProbabilisticSampler.initFromPercentage(0);
    const trace_id = sample_trace_id;
    const result = sampler.sample(&trace_id, "");
    try testing.expect(!result.keep);
}

test "ProbabilisticSampler: binary trace_id approximate distribution for 50%" {
    const sampler = ProbabilisticSampler.initFromPercentage(50);

    var kept: u32 = 0;
    const total: u32 = 10000;

    for (0..total) |i| {
        var trace_id = [_]u8{0} ** 16;
        // Vary the randomness bytes (last 7 bytes) to sweep the full 56-bit range.
        trace_id[9] = @intCast((i * 256 / total) & 0xff);
        trace_id[10] = @intCast(i & 0xff);
        trace_id[11] = @intCast((i >> 8) & 0xff);
        const result = sampler.sample(&trace_id, "");
        if (result.keep) kept += 1;
    }

    const ratio = @as(f64, @floatFromInt(kept)) / @as(f64, @floatFromInt(total));
    try testing.expect(ratio > 0.45 and ratio < 0.55);
}
