//! Pure OpenTelemetry consistent probability sampling.
//!
//! The implementation owns no memory and performs no I/O. Callers pass raw
//! trace IDs or stable record keys and, when present, the incoming tracestate.

const std = @import("std");

pub const max_randomness: u64 = @as(u64, 1) << 56;

pub const Mode = enum(u8) {
    hash_seed = 1,
    proportional = 2,
    equalizing = 3,
};

pub const Config = struct {
    threshold: u64,
    mode: Mode = .hash_seed,
    precision: u8 = 4,
    hash_seed: u32 = 0,
    fail_closed: bool = true,

    pub fn fromPercentage(percentage: f32) Config {
        return .{ .threshold = thresholdFromPercentage(percentage) };
    }

    pub fn validate(self: Config) bool {
        return self.threshold <= max_randomness and self.precision >= 1 and self.precision <= 14;
    }
};

pub const Result = struct {
    keep: bool,
    randomness: ?u64,
    threshold: ?u64,
    explicit_randomness: ?u64,
    invalid_context: bool = false,
};

const TraceState = struct {
    threshold: ?u64 = null,
    randomness: ?u64 = null,
};

pub fn evaluate(config: Config, input: []const u8, trace_state: []const u8) Result {
    const incoming = parseTraceState(trace_state);
    const randomness = incoming.randomness orelse computeRandomness(input, config.hash_seed);
    const value = randomness orelse return .{
        .keep = !config.fail_closed,
        .randomness = null,
        .threshold = null,
        .explicit_randomness = null,
        .invalid_context = true,
    };
    if (incoming.randomness != null and incoming.threshold != null and value < incoming.threshold.?) {
        return .{
            .keep = true,
            .randomness = value,
            .threshold = null,
            .explicit_randomness = incoming.randomness,
            .invalid_context = true,
        };
    }
    if (config.mode == .equalizing and incoming.randomness == null) {
        if (incoming.threshold) |existing| {
            if (existing >= config.threshold) return .{
                .keep = true,
                .randomness = value,
                .threshold = existing,
                .explicit_randomness = null,
            };
        }
    }

    const threshold = switch (config.mode) {
        .hash_seed => config.threshold,
        .proportional => proportionalThreshold(config.threshold, incoming.threshold),
        .equalizing => if (incoming.threshold) |existing|
            @max(existing, config.threshold)
        else
            config.threshold,
    };
    const keep = value >= threshold and threshold < max_randomness;
    return .{
        .keep = keep,
        .randomness = value,
        .threshold = if (keep) threshold else null,
        .explicit_randomness = incoming.randomness,
    };
}

pub fn thresholdFromPercentage(percentage: f32) u64 {
    if (percentage >= 100.0) return 0;
    if (percentage <= 0.0) return max_randomness;
    const ratio = 1.0 - (@as(f64, percentage) / 100.0);
    return @intFromFloat(ratio * @as(f64, @floatFromInt(max_randomness)));
}

pub fn writeThreshold(destination: []u8, threshold: u64, precision: u8) ?[]u8 {
    if (destination.len == 0 or precision < 1 or precision > 14 or threshold > max_randomness) return null;
    const hex = "0123456789abcdef";
    var len: usize = precision;
    if (destination.len < len) return null;
    for (0..precision) |index| {
        const shift: u6 = @intCast(52 - index * 4);
        const nibble: u4 = @truncate(threshold >> shift);
        destination[index] = hex[nibble];
    }
    while (len > 1 and destination[len - 1] == '0') len -= 1;
    return destination[0..len];
}

/// Replace the `ot` list member and retain at most the W3C limit of 32 members.
pub fn updateTraceState(
    destination: []u8,
    existing: []const u8,
    threshold: u64,
    precision: u8,
    explicit_randomness: ?u64,
) ?[]u8 {
    _ = explicit_randomness;
    var threshold_buffer: [14]u8 = undefined;
    const threshold_hex = writeThreshold(&threshold_buffer, threshold, precision) orelse return null;
    var position: usize = 0;
    append(destination, &position, "ot=") orelse return null;

    var wrote_subkey = false;
    var source_entries = std.mem.splitScalar(u8, existing, ',');
    while (source_entries.next()) |raw| {
        const entry = std.mem.trim(u8, raw, " ");
        if (!std.mem.startsWith(u8, entry, "ot=")) continue;
        var values = std.mem.splitScalar(u8, entry[3..], ';');
        while (values.next()) |raw_value| {
            const value = std.mem.trim(u8, raw_value, " ");
            if (value.len == 0 or std.mem.startsWith(u8, value, "th:")) continue;
            if (wrote_subkey) append(destination, &position, ";") orelse return null;
            append(destination, &position, value) orelse return null;
            wrote_subkey = true;
        }
        break;
    }
    if (wrote_subkey) append(destination, &position, ";") orelse return null;
    append(destination, &position, "th:") orelse return null;
    append(destination, &position, threshold_hex) orelse return null;

    var entries: usize = 1;
    var iterator = std.mem.splitScalar(u8, existing, ',');
    while (iterator.next()) |raw| {
        const entry = std.mem.trim(u8, raw, " ");
        if (entry.len == 0 or std.mem.startsWith(u8, entry, "ot=")) continue;
        if (entries == 32) break;
        if (destination.len -| position < entry.len + 1) break;
        destination[position] = ',';
        position += 1;
        append(destination, &position, entry) orelse unreachable;
        entries += 1;
    }
    return destination[0..position];
}

fn computeRandomness(input: []const u8, hash_seed: u32) ?u64 {
    if (input.len >= 16) {
        var value: u64 = 0;
        for (input[input.len - 7 ..]) |byte| value = (value << 8) | byte;
        return value;
    }
    if (input.len == 0) return null;
    var value: u64 = hash_seed;
    for (input) |byte| value = (value << 8) ^ byte;
    value +%= 0x9e3779b97f4a7c15;
    value = (value ^ (value >> 30)) *% 0xbf58476d1ce4e5b9;
    value = (value ^ (value >> 27)) *% 0x94d049bb133111eb;
    return (value ^ (value >> 31)) & (max_randomness - 1);
}

fn proportionalThreshold(configured: u64, incoming: ?u64) u64 {
    const existing = incoming orelse return configured;
    const configured_probability = 1.0 - @as(f64, @floatFromInt(configured)) /
        @as(f64, @floatFromInt(max_randomness));
    const existing_probability = 1.0 - @as(f64, @floatFromInt(existing)) /
        @as(f64, @floatFromInt(max_randomness));
    const probability = configured_probability * existing_probability;
    if (probability <= 0.0) return max_randomness;
    return @intFromFloat((1.0 - probability) * @as(f64, @floatFromInt(max_randomness)));
}

fn parseTraceState(trace_state: []const u8) TraceState {
    var result: TraceState = .{};
    var entries = std.mem.splitScalar(u8, trace_state, ',');
    while (entries.next()) |raw| {
        const entry = std.mem.trim(u8, raw, " ");
        if (!std.mem.startsWith(u8, entry, "ot=")) continue;
        var values = std.mem.splitScalar(u8, entry[3..], ';');
        while (values.next()) |value| {
            if (std.mem.startsWith(u8, value, "th:")) {
                result.threshold = parseHex(value[3..]);
            } else if (std.mem.startsWith(u8, value, "rv:")) {
                result.randomness = parseHex(value[3..]);
            }
        }
        break;
    }
    return result;
}

fn parseHex(hex: []const u8) ?u64 {
    if (hex.len == 0 or hex.len > 14) return null;
    var value: u64 = 0;
    for (hex) |character| {
        const digit: u64 = switch (character) {
            '0'...'9' => character - '0',
            'a'...'f' => character - 'a' + 10,
            else => return null,
        };
        value = (value << 4) | digit;
    }
    const shift: u6 = @intCast((14 - hex.len) * 4);
    return value << shift;
}

fn append(destination: []u8, position: *usize, value: []const u8) ?void {
    if (destination.len -| position.* < value.len) return null;
    @memcpy(destination[position.*..][0..value.len], value);
    position.* += value.len;
}

test "OTel trace IDs use their least-significant 56 bits" {
    const trace_id = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    const result = evaluate(Config.fromPercentage(50), &trace_id, "");
    try std.testing.expectEqual(@as(?u64, 0x09aabbccddeeff), result.randomness);
}

test "proportional and equalizing sampling honor incoming thresholds" {
    const half = thresholdFromPercentage(50);
    try std.testing.expectEqual(thresholdFromPercentage(25), proportionalThreshold(half, half));

    var equalizing = Config.fromPercentage(50);
    equalizing.mode = .equalizing;
    const equalized = evaluate(equalizing, "stable-key", "ot=th:c");
    if (equalized.keep) try std.testing.expectEqual(@as(?u64, 0xc0000000000000), equalized.threshold);
}

test "missing randomness obeys fail-closed and fail-open" {
    var config = Config.fromPercentage(50);
    var result = evaluate(config, "", "");
    try std.testing.expect(!result.keep);
    try std.testing.expect(result.invalid_context);
    config.fail_closed = false;
    result = evaluate(config, "", "");
    try std.testing.expect(result.keep);
}

test "inconsistent explicit randomness erases the threshold" {
    const result = evaluate(Config.fromPercentage(50), "ignored", "ot=rv:1;th:8");
    try std.testing.expect(result.keep);
    try std.testing.expect(result.invalid_context);
    try std.testing.expectEqual(@as(?u64, null), result.threshold);
}

test "tracestate replacement is bounded and deterministic" {
    var buffer: [64]u8 = undefined;
    const updated = updateTraceState(&buffer, "vendor=value,ot=th:1", 0x80000000000000, 4, null).?;
    try std.testing.expectEqualStrings("ot=th:8,vendor=value", updated);
}
