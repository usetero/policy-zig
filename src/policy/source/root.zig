//! Cold source precedence and normalization boundary.
//!
//! Provider protobuf and JSON adapters belong above this module. The compiler
//! sees only normalized `PolicySpec` values with duplicate IDs resolved.

const std = @import("std");
const compiler = @import("policy_compiler");
const proto = @import("proto");

pub const json = @import("json.zig");
pub const adapter = @import("adapter.zig");
pub const Selector = adapter.Selector;
pub const PreparedProgram = adapter.PreparedProgram;

pub const SourceType = enum(u8) {
    file = 1,
    http = 2,
    inline_config = 3,
};

pub const SourceKind = SourceType;

pub const PolicyMetadata = struct {
    provider_id: []const u8,
    source_type: SourceType,
    revision: u64,
};

pub const SourcePolicy = struct {
    policy: compiler.PolicySpec,
    source: SourceType,
    revision: u64,
};

pub const NormalizeError = error{
    OutputCapacityExceeded,
    AmbiguousRevision,
};

pub const ProviderError = error{
    InvalidSamplingMode,
    InvalidSamplingPrecision,
};

pub const ParsedPolicies = std.json.Parsed(proto.policy.SyncResponse);

/// Parse a canonical provider JSON payload. The returned arena owns every
/// generated child and is released with `ParsedPolicies.deinit` after the
/// policies have been normalized and compiled.
pub fn parsePoliciesBytes(allocator: std.mem.Allocator, bytes: []const u8) !ParsedPolicies {
    return proto.policy.SyncResponse.jsonDecode(bytes, .{}, allocator);
}

/// Parse the ergonomic policy-authoring JSON accepted by the provider spec.
/// The caller owns every returned policy and must call `freePolicies`.
pub fn parseAuthoringBytes(allocator: std.mem.Allocator, bytes: []const u8) ![]proto.policy.Policy {
    return json.parsePoliciesBytes(allocator, bytes);
}

pub fn freePolicies(allocator: std.mem.Allocator, policies: []proto.policy.Policy) void {
    for (policies) |*policy| policy.deinit(allocator);
    allocator.free(policies);
}

/// Convert generated provider configuration at the cold source boundary. No
/// generated type crosses into the compiler image or runtime dependency graph.
pub fn samplingFromProto(value: proto.policy.TraceSamplingConfig) ProviderError!compiler.SamplingConfig {
    const precision = value.sampling_precision orelse 4;
    if (precision < 1 or precision > 14) return error.InvalidSamplingPrecision;
    const mode: @TypeOf(@as(compiler.SamplingConfig, undefined).mode) = switch (value.mode orelse
        .SAMPLING_MODE_HASH_SEED) {
        .SAMPLING_MODE_UNSPECIFIED, .SAMPLING_MODE_HASH_SEED => .hash_seed,
        .SAMPLING_MODE_PROPORTIONAL => .proportional,
        .SAMPLING_MODE_EQUALIZING => .equalizing,
        _ => return error.InvalidSamplingMode,
    };
    return .{
        .percentage = value.percentage,
        .mode = mode,
        .precision = @intCast(precision),
        .hash_seed = value.hash_seed orelse 0,
        .fail_closed = value.fail_closed orelse true,
    };
}

/// Merge source policies into caller storage. Higher source priority wins;
/// equal-priority updates use the greatest revision. Output is sorted by ID so
/// policy indices and image hashes are independent of provider arrival order.
pub fn normalize(inputs: []const SourcePolicy, output: []compiler.PolicySpec) NormalizeError![]compiler.PolicySpec {
    var count: usize = 0;
    for (inputs, 0..) |candidate, candidate_index| {
        var exists = false;
        for (output[0..count]) |policy| {
            if (std.mem.eql(u8, policy.id, candidate.policy.id)) {
                exists = true;
                break;
            }
        }
        if (exists) continue;

        var winner = candidate;
        var winner_index = candidate_index;
        for (inputs, 0..) |other, other_index| {
            if (!std.mem.eql(u8, other.policy.id, candidate.policy.id)) continue;
            if (other.source == winner.source and other.revision == winner.revision and
                other_index != winner_index)
            {
                return error.AmbiguousRevision;
            }
            if (precedes(other, winner)) {
                winner = other;
                winner_index = other_index;
            }
        }
        if (count == output.len) return error.OutputCapacityExceeded;
        output[count] = winner.policy;
        count += 1;
    }
    std.mem.sort(compiler.PolicySpec, output[0..count], {}, struct {
        fn lessThan(_: void, left: compiler.PolicySpec, right: compiler.PolicySpec) bool {
            return std.mem.order(u8, left.id, right.id) == .lt;
        }
    }.lessThan);
    return output[0..count];
}

fn precedes(candidate: SourcePolicy, incumbent: SourcePolicy) bool {
    const candidate_priority = @intFromEnum(candidate.source);
    const incumbent_priority = @intFromEnum(incumbent.source);
    return candidate_priority > incumbent_priority or
        (candidate_priority == incumbent_priority and candidate.revision > incumbent.revision);
}

test "normalization resolves precedence and has stable order" {
    const no_matchers: []const compiler.MatcherSpec = &.{};
    const inputs = [_]SourcePolicy{
        .{ .policy = .{ .id = "z", .verdict = .keep, .matchers = no_matchers }, .source = .http, .revision = 1 },
        .{ .policy = .{ .id = "a", .verdict = .drop, .matchers = no_matchers }, .source = .file, .revision = 1 },
        .{
            .policy = .{ .id = "z", .verdict = .drop, .matchers = no_matchers },
            .source = .inline_config,
            .revision = 1,
        },
    };
    var output: [2]compiler.PolicySpec = undefined;
    const normalized = try normalize(&inputs, &output);
    try std.testing.expectEqualStrings("a", normalized[0].id);
    try std.testing.expectEqualStrings("z", normalized[1].id);
    try std.testing.expectEqual(@as(@TypeOf(normalized[1].verdict), .drop), normalized[1].verdict);
}

test "provider sampling configuration is normalized before compilation" {
    const normalized = try samplingFromProto(.{
        .percentage = 25,
        .mode = .SAMPLING_MODE_EQUALIZING,
        .sampling_precision = 8,
        .hash_seed = 9,
        .fail_closed = false,
    });
    try std.testing.expectEqual(@as(f32, 25), normalized.percentage);
    try std.testing.expectEqual(@as(@TypeOf(normalized.mode), .equalizing), normalized.mode);
    try std.testing.expectEqual(@as(u8, 8), normalized.precision);
    try std.testing.expect(!normalized.fail_closed);
}

test "canonical provider payload parsing remains a cold source concern" {
    var parsed = try parsePoliciesBytes(std.testing.allocator, "{\"policies\":[]}");
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 0), parsed.value.policies.items.len);
}
