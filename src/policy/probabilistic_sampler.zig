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
//! The randomness value is derived from the input bytes:
//!   - For 16-byte trace IDs: uses last 7 bytes (OTel spec)
//!   - For shorter inputs: hashes all bytes
//!   - Mixed with hash_seed and splitmix64 for uniform distribution
//!
//! ## Tracestate Handling
//!
//! The sampler reads and writes the `th` (threshold) key in the tracestate header
//! following the W3C tracestate specification.

const std = @import("std");
const proto = @import("proto");
const testing = std.testing;

const TraceSamplingConfig = proto.policy.TraceSamplingConfig;
const SamplingMode = proto.policy.SamplingMode;

/// Maximum value for 56-bit randomness/threshold (2^56)
const MAX_56BIT: u64 = 1 << 56;

/// Default sampling precision (hex digits)
const DEFAULT_PRECISION: u32 = 4;

/// Default hash seed
const DEFAULT_HASH_SEED: u32 = 0;

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
                .hash_seed = DEFAULT_HASH_SEED,
                .precision = DEFAULT_PRECISION,
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
            .hash_seed = cfg.hash_seed orelse DEFAULT_HASH_SEED,
            .precision = @min(14, @max(1, cfg.sampling_precision orelse DEFAULT_PRECISION)),
            .fail_closed = cfg.fail_closed orelse true,
            .percentage = percentage,
        };
    }

    /// Initialize sampler from a simple percentage (used for log policies).
    pub fn initFromPercentage(percentage: u8) ProbabilisticSampler {
        return .{
            .threshold = calculateThreshold(@floatFromInt(percentage)),
            .mode = .SAMPLING_MODE_HASH_SEED,
            .hash_seed = DEFAULT_HASH_SEED,
            .precision = DEFAULT_PRECISION,
            .fail_closed = true,
            .percentage = @floatFromInt(percentage),
        };
    }

    /// Simple keep/drop decision on raw input bytes.
    /// For callers that don't need tracestate or SamplingResult.
    pub fn shouldKeep(self: ProbabilisticSampler, input: []const u8) bool {
        return self.sample(input, "").keep;
    }

    /// Calculate threshold from percentage
    /// T = floor((1 - percentage/100) * 2^56)
    fn calculateThreshold(percentage: f32) u64 {
        if (percentage >= 100.0) return 0; // Keep all
        if (percentage <= 0.0) return MAX_56BIT; // Keep none

        const ratio = 1.0 - (@as(f64, percentage) / 100.0);
        const threshold_f = ratio * @as(f64, @floatFromInt(MAX_56BIT));
        return @intFromFloat(@min(@as(f64, @floatFromInt(MAX_56BIT)), @max(0.0, threshold_f)));
    }

    /// Make sampling decision for an item.
    ///
    /// Returns a SamplingResult with:
    /// - keep: whether to keep the item
    /// - new_threshold: threshold to write to tracestate (if sampling)
    pub fn sample(self: ProbabilisticSampler, input: []const u8, tracestate: []const u8) SamplingResult {
        // Edge cases
        if (self.percentage >= 100.0) {
            return .{ .keep = true, .new_threshold = null };
        }
        if (self.percentage <= 0.0) {
            return .{ .keep = false, .new_threshold = null };
        }

        return switch (self.mode) {
            .SAMPLING_MODE_UNSPECIFIED, .SAMPLING_MODE_HASH_SEED => self.sampleHashSeed(input),
            .SAMPLING_MODE_PROPORTIONAL => self.sampleProportional(input, tracestate),
            .SAMPLING_MODE_EQUALIZING => self.sampleEqualizing(input, tracestate),
            _ => self.sampleHashSeed(input), // Unknown mode defaults to hash_seed
        };
    }

    /// Hash seed mode: deterministic sampling based on input hash
    fn sampleHashSeed(self: ProbabilisticSampler, input: []const u8) SamplingResult {
        const r = self.computeRandomness(input);
        const keep = r >= self.threshold;
        return .{
            .keep = keep,
            .new_threshold = if (keep) self.encodeThreshold() else null,
        };
    }

    /// Proportional mode: adjust sampling relative to existing probability
    fn sampleProportional(self: ProbabilisticSampler, input: []const u8, tracestate: []const u8) SamplingResult {
        // Parse existing threshold from tracestate
        const existing_threshold = parseThresholdFromTracestate(tracestate);

        if (existing_threshold) |existing_t| {
            // If existing threshold is more restrictive (higher), respect it
            if (existing_t >= self.threshold) {
                // Already sampled at lower rate, check if it passes our threshold
                const r = self.computeRandomness(input);
                const keep = r >= self.threshold;
                return .{
                    .keep = keep,
                    .new_threshold = if (keep) self.encodeThreshold() else null,
                };
            }
            // Existing threshold is less restrictive - apply our more restrictive threshold
            const r = self.computeRandomness(input);
            const keep = r >= self.threshold;
            return .{
                .keep = keep,
                .new_threshold = if (keep) self.encodeThreshold() else null,
            };
        }

        // No existing threshold - use hash seed behavior
        return self.sampleHashSeed(input);
    }

    /// Equalizing mode: preferentially sample spans with higher existing rates
    fn sampleEqualizing(self: ProbabilisticSampler, input: []const u8, tracestate: []const u8) SamplingResult {
        // Parse existing threshold from tracestate
        const existing_threshold = parseThresholdFromTracestate(tracestate);

        if (existing_threshold) |existing_t| {
            // Calculate effective threshold for equalizing
            // Spans that were sampled at high rates (low threshold) should be
            // more likely to be dropped to equalize overall sampling
            const r = self.computeRandomness(input);

            // Use the more restrictive threshold
            const effective_threshold = @max(existing_t, self.threshold);
            const keep = r >= effective_threshold;
            return .{
                .keep = keep,
                .new_threshold = if (keep) self.encodeThreshold() else null,
            };
        }

        // No existing threshold - use hash seed behavior
        return self.sampleHashSeed(input);
    }

    /// Compute 56-bit randomness value from input bytes.
    ///
    /// For 16-byte trace IDs (standard OTel format), extracts the
    /// least-significant 56 bits (last 7 bytes) directly without hashing,
    /// per the OTel consistent probability sampling spec.
    ///
    /// For shorter inputs (e.g. log sample keys), hashes all bytes with
    /// hash_seed using splitmix64 for uniform distribution.
    fn computeRandomness(self: ProbabilisticSampler, input: []const u8) u64 {
        if (input.len >= 16) {
            // Standard 16-byte trace_id - extract last 7 bytes as randomness
            // directly, without hashing. Per OTel spec, the least-significant
            // 56 bits of the trace ID ARE the randomness value.
            var r: u64 = 0;
            for (input[input.len - 7 ..]) |b| {
                r = (r << 8) | b;
            }
            return r & (MAX_56BIT - 1);
        } else if (input.len > 0) {
            // Shorter input (log sample keys, etc.) - hash for uniform distribution
            var r: u64 = 0;
            for (input) |b| {
                r = (r << 8) ^ b;
            }
            r ^= @as(u64, self.hash_seed);
            r = mixHash(r);
            return r & (MAX_56BIT - 1);
        }

        return 0;
    }

    /// Encode threshold as hex string for tracestate.
    /// Returns a thread-local buffer - caller should copy if needed.
    pub fn encodeThreshold(self: ProbabilisticSampler) []const u8 {
        // Static buffer for threshold encoding
        const S = struct {
            threadlocal var buf: [14]u8 = undefined;
        };

        // Encode threshold as hex with trailing zeros removed
        const hex_chars = "0123456789abcdef";
        var len: usize = 0;
        var t = self.threshold;

        // Encode up to precision digits
        var i: u32 = 0;
        while (i < self.precision and t > 0) : (i += 1) {
            const nibble = @as(u4, @truncate(t >> 52));
            S.buf[len] = hex_chars[nibble];
            len += 1;
            t <<= 4;
        }

        // If threshold is 0, encode as "0"
        if (len == 0) {
            S.buf[0] = '0';
            len = 1;
        }

        return S.buf[0..len];
    }

    /// splitmix64 hash mixing function for good avalanche properties
    fn mixHash(x: u64) u64 {
        var h = x +% 0x9e3779b97f4a7c15;
        h = (h ^ (h >> 30)) *% 0xbf58476d1ce4e5b9;
        h = (h ^ (h >> 27)) *% 0x94d049bb133111eb;
        return h ^ (h >> 31);
    }
};

/// Result of sampling decision
pub const SamplingResult = struct {
    /// Whether to keep the item
    keep: bool,
    /// New threshold to write to tracestate (null if not sampling)
    new_threshold: ?[]const u8,
};

/// Parse threshold value from tracestate header.
/// Looks for the `th` key in the `ot` vendor section.
/// Returns null if not found or invalid.
fn parseThresholdFromTracestate(tracestate: []const u8) ?u64 {
    if (tracestate.len == 0) return null;

    // Look for "ot=..." vendor section
    var it = std.mem.splitScalar(u8, tracestate, ',');
    while (it.next()) |entry| {
        const trimmed = std.mem.trim(u8, entry, " ");
        if (std.mem.startsWith(u8, trimmed, "ot=")) {
            // Parse the ot value for th key
            const ot_value = trimmed[3..];
            return parseOtThreshold(ot_value);
        }
    }

    return null;
}

/// Parse threshold from OT vendor tracestate value
/// Format: "th:HEXVALUE" or "th:HEXVALUE;other:value"
fn parseOtThreshold(ot_value: []const u8) ?u64 {
    var it = std.mem.splitScalar(u8, ot_value, ';');
    while (it.next()) |kv| {
        if (std.mem.startsWith(u8, kv, "th:")) {
            const hex_value = kv[3..];
            return parseHexThreshold(hex_value);
        }
    }
    return null;
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
pub const MAX_TRACESTATE_LEN: usize = 512;

/// Update tracestate with sampling threshold.
/// Adds or updates the `ot=th:THRESHOLD` entry in the tracestate.
///
/// Writes the result to the provided buffer and returns a slice of the written data.
/// Returns null if the buffer is too small.
///
/// Per W3C tracestate spec:
/// - Maximum 32 entries
/// - Our entry goes at the beginning (most recent sampler)
/// - If ot vendor already exists, update the th value
pub fn updateTracestateInPlace(
    buf: []u8,
    existing_tracestate: []const u8,
    threshold_hex: []const u8,
) ?[]u8 {
    // Build the new ot entry: "ot=th:THRESHOLD"
    var new_ot_buf: [32]u8 = undefined;
    const new_ot = std.fmt.bufPrint(&new_ot_buf, "ot=th:{s}", .{threshold_hex}) catch return null;

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
    const sampler = ProbabilisticSampler{
        .threshold = ProbabilisticSampler.calculateThreshold(percentage),
        .mode = .SAMPLING_MODE_HASH_SEED,
        .hash_seed = 0,
        .precision = @min(14, @max(1, precision)),
        .fail_closed = true,
        .percentage = percentage,
    };
    return sampler.encodeThreshold();
}

// =============================================================================
// Tests
// =============================================================================

test "ProbabilisticSampler: 100% keeps all" {
    const config = TraceSamplingConfig{
        .percentage = 100.0,
        .mode = null,
        .sampling_precision = null,
        .hash_seed = null,
        .fail_closed = null,
    };
    const sampler = ProbabilisticSampler.init(&config);

    // All trace IDs should be kept
    const trace_id = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
    const result = sampler.sample(&trace_id, "");

    try testing.expect(result.keep);
}

test "ProbabilisticSampler: 0% rejects all" {
    const config = TraceSamplingConfig{
        .percentage = 0.0,
        .mode = null,
        .sampling_precision = null,
        .hash_seed = null,
        .fail_closed = null,
    };
    const sampler = ProbabilisticSampler.init(&config);

    const trace_id = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
    const result = sampler.sample(&trace_id, "");

    try testing.expect(!result.keep);
}

test "ProbabilisticSampler: null config keeps all" {
    const sampler = ProbabilisticSampler.init(null);

    const trace_id = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
    const result = sampler.sample(&trace_id, "");

    try testing.expect(result.keep);
}

test "ProbabilisticSampler: deterministic for same input" {
    const config = TraceSamplingConfig{
        .percentage = 50.0,
        .mode = null,
        .sampling_precision = null,
        .hash_seed = null,
        .fail_closed = null,
    };
    const sampler = ProbabilisticSampler.init(&config);

    const trace_id = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };

    const first_result = sampler.sample(&trace_id, "");
    for (0..100) |_| {
        const result = sampler.sample(&trace_id, "");
        try testing.expectEqual(first_result.keep, result.keep);
    }
}

test "ProbabilisticSampler: hash_seed affects sampling for short inputs" {
    const config1 = TraceSamplingConfig{
        .percentage = 50.0,
        .mode = .SAMPLING_MODE_HASH_SEED,
        .sampling_precision = null,
        .hash_seed = 0,
        .fail_closed = null,
    };
    const config2 = TraceSamplingConfig{
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
    const config = TraceSamplingConfig{
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
    try testing.expectEqual(MAX_56BIT, ProbabilisticSampler.calculateThreshold(0.0));

    // 50% = threshold is half of MAX
    const half_threshold = ProbabilisticSampler.calculateThreshold(50.0);
    const expected_half = MAX_56BIT / 2;
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

test "ProbabilisticSampler: shouldKeep matches sample" {
    const sampler = ProbabilisticSampler.initFromPercentage(50);
    const input = "test-input-bytes";

    // shouldKeep should match sample().keep
    try testing.expectEqual(sampler.sample(input, "").keep, sampler.shouldKeep(input));
}

test "parseThresholdFromTracestate: empty" {
    try testing.expectEqual(@as(?u64, null), parseThresholdFromTracestate(""));
}

test "parseThresholdFromTracestate: valid ot threshold" {
    // "ot=th:8" means threshold 0x80000000000000 (8 shifted to fill 56 bits)
    const result = parseThresholdFromTracestate("ot=th:8");
    try testing.expect(result != null);
    try testing.expectEqual(@as(u64, 0x80000000000000), result.?);
}

test "parseThresholdFromTracestate: multiple entries" {
    const result = parseThresholdFromTracestate("vendor1=val1,ot=th:4,vendor2=val2");
    try testing.expect(result != null);
    try testing.expectEqual(@as(u64, 0x40000000000000), result.?);
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
    var buf: [MAX_TRACESTATE_LEN]u8 = undefined;
    const result = updateTracestateInPlace(&buf, "", "8");
    try testing.expect(result != null);
    try testing.expectEqualStrings("ot=th:8", result.?);
}

test "updateTracestateInPlace: existing entries preserved" {
    var buf: [MAX_TRACESTATE_LEN]u8 = undefined;
    const result = updateTracestateInPlace(&buf, "vendor1=val1,vendor2=val2", "8");
    try testing.expect(result != null);
    try testing.expectEqualStrings("ot=th:8,vendor1=val1,vendor2=val2", result.?);
}

test "updateTracestateInPlace: existing ot entry replaced" {
    var buf: [MAX_TRACESTATE_LEN]u8 = undefined;
    const result = updateTracestateInPlace(&buf, "ot=th:4,vendor1=val1", "8");
    try testing.expect(result != null);
    try testing.expectEqualStrings("ot=th:8,vendor1=val1", result.?);
}

test "updateTracestateInPlace: ot entry moved to front" {
    var buf: [MAX_TRACESTATE_LEN]u8 = undefined;
    const result = updateTracestateInPlace(&buf, "vendor1=val1,ot=th:4,vendor2=val2", "8");
    try testing.expect(result != null);
    try testing.expectEqualStrings("ot=th:8,vendor1=val1,vendor2=val2", result.?);
}

test "updateTracestateInPlace: buffer too small returns null" {
    var buf: [5]u8 = undefined; // Too small to fit "ot=th:8"
    const result = updateTracestateInPlace(&buf, "", "8");
    try testing.expect(result == null);
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
