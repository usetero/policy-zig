//! Provider-policy adapter for the compact compiler input.
//!
//! This is a cold boundary: generated provider objects are converted once to
//! numeric selectors and allocator-owned compiler IR, then disappear before
//! image publication.

const std = @import("std");
const compiler = @import("policy_compiler");
const image = @import("policy_image");
const proto = @import("proto");

const Policy = proto.policy.Policy;
const AttributePath = proto.policy.AttributePath;

pub const Selector = enum(u32) {
    log_field = 1,
    log_attribute = 2,
    resource_attribute = 3,
    scope_attribute = 4,
    metric_field = 5,
    datapoint_attribute = 6,
    metric_type = 7,
    aggregation_temporality = 8,
    trace_field = 9,
    span_attribute = 10,
    span_kind = 11,
    span_status = 12,
    event_name = 13,
    event_attribute = 14,
    link_trace_id = 15,
};

pub const action_flag_upsert: u8 = 1;
pub const action_flag_regex: u8 = 2;

pub const PreparedProgram = struct {
    arena: std.heap.ArenaAllocator,
    program: compiler.Program,

    pub fn deinit(self: *PreparedProgram) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub const PrepareError = error{
    MissingTarget,
    MissingField,
    MissingMatch,
    EmptyAttributePath,
    InvalidKeep,
    InvalidValue,
    UnsupportedExtension,
} || std.mem.Allocator.Error;

pub fn prepare(allocator: std.mem.Allocator, policies: []const Policy, seed: u64) PrepareError!PreparedProgram {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const scratch = arena.allocator();
    const specs = try scratch.alloc(compiler.PolicySpec, policies.len);
    for (policies, specs) |policy, *spec| spec.* = try preparePolicy(scratch, policy);
    std.mem.sort(compiler.PolicySpec, specs, {}, struct {
        fn lessThan(_: void, left: compiler.PolicySpec, right: compiler.PolicySpec) bool {
            return std.mem.order(u8, left.id, right.id) == .lt;
        }
    }.lessThan);
    return .{ .arena = arena, .program = .{ .policies = specs, .seed = seed } };
}

fn preparePolicy(allocator: std.mem.Allocator, policy: Policy) PrepareError!compiler.PolicySpec {
    const target = policy.target orelse return error.MissingTarget;
    return switch (target) {
        .log => |log| prepareLog(allocator, policy, log),
        .metric => |metric| prepareMetric(allocator, policy, metric),
        .trace => |trace| prepareTrace(allocator, policy, trace),
    };
}

fn prepareLog(allocator: std.mem.Allocator, policy: Policy, target: proto.policy.LogTarget) PrepareError!compiler.PolicySpec {
    const matchers = try allocator.alloc(compiler.MatcherSpec, target.match.items.len);
    for (target.match.items, matchers) |matcher, *output| {
        var field = try logField(allocator, matcher.field orelse return error.MissingField);
        output.* = try matcherSpec(allocator, field, matcher.match, matcher.negate, matcher.case_insensitive);
        adjustIdentifierField(&field, output);
        output.field = field;
    }

    var actions: std.ArrayList(compiler.ActionSpec) = .empty;
    if (target.transform) |transform| {
        try actions.ensureTotalCapacity(
            allocator,
            transform.remove.items.len + transform.redact.items.len +
                transform.rename.items.len + transform.add.items.len,
        );
        for (transform.remove.items) |item| actions.appendAssumeCapacity(.{
            .opcode = .remove,
            .field = try logField(allocator, item.field orelse return error.MissingField),
        });
        for (transform.redact.items) |item| {
            var value = item.replacement;
            var flags: u8 = 0;
            if (item.regex) |expression| {
                flags |= action_flag_regex;
                value = try joinPair(allocator, expression, item.replacement);
            }
            actions.appendAssumeCapacity(.{
                .opcode = .redact,
                .field = try logField(allocator, item.field orelse return error.MissingField),
                .value = value,
                .flags = flags,
            });
        }
        for (transform.rename.items) |item| actions.appendAssumeCapacity(.{
            .opcode = .rename,
            .field = try renameField(allocator, item.from orelse return error.MissingField),
            .value = item.to,
            .flags = if (item.upsert) action_flag_upsert else 0,
        });
        for (transform.add.items) |item| actions.appendAssumeCapacity(.{
            .opcode = .add,
            .field = try logField(allocator, item.field orelse return error.MissingField),
            .value = item.value,
            .flags = if (item.upsert) action_flag_upsert else 0,
        });
    }

    const keep = try parseLogKeep(target.keep);
    return .{
        .id = policy.id,
        .signal = .log,
        .verdict = keep.verdict,
        .enabled = policy.enabled,
        .matchers = matchers,
        .actions = try actions.toOwnedSlice(allocator),
        .sampling = keep.sampling,
        .rate_limit_per_second = keep.limit,
        .rate_window_seconds = keep.window_seconds,
    };
}

fn prepareMetric(
    allocator: std.mem.Allocator,
    policy: Policy,
    target: proto.policy.MetricTarget,
) PrepareError!compiler.PolicySpec {
    const matchers = try allocator.alloc(compiler.MatcherSpec, target.match.items.len);
    for (target.match.items, matchers) |matcher, *output| {
        const field = try metricField(allocator, matcher.field orelse return error.MissingField);
        output.* = try matcherSpec(allocator, field, matcher.match, matcher.negate, matcher.case_insensitive);
    }
    return .{
        .id = policy.id,
        .signal = .metric,
        .verdict = if (target.keep) .keep else .drop,
        .enabled = policy.enabled,
        .matchers = matchers,
    };
}

fn prepareTrace(allocator: std.mem.Allocator, policy: Policy, target: proto.policy.TraceTarget) PrepareError!compiler.PolicySpec {
    const matchers = try allocator.alloc(compiler.MatcherSpec, target.match.items.len);
    for (target.match.items, matchers) |matcher, *output| {
        var field = try traceField(allocator, matcher.field orelse return error.MissingField);
        output.* = try matcherSpec(allocator, field, matcher.match, matcher.negate, matcher.case_insensitive);
        adjustIdentifierField(&field, output);
        output.field = field;
    }
    return .{
        .id = policy.id,
        .signal = .trace,
        .verdict = .keep,
        .enabled = policy.enabled,
        .matchers = matchers,
        .sampling = if (target.keep) |keep| try samplingConfig(keep) else null,
    };
}

fn matcherSpec(
    allocator: std.mem.Allocator,
    field: compiler.FieldSpec,
    match: anytype,
    negated: bool,
    case_insensitive: bool,
) PrepareError!compiler.MatcherSpec {
    const selected = match orelse return error.MissingMatch;
    var output: compiler.MatcherSpec = .{
        .field = field,
        .opcode = .exists,
        .negated = negated,
        .case_insensitive = case_insensitive,
    };
    switch (selected) {
        .exact => |value| {
            output.opcode = .exact;
            output.value = .{ .string = if (field.value_kind == .bytes)
                try decodeHex(allocator, value)
            else
                value };
        },
        .regex => |value| {
            output.opcode = .regex;
            output.value = .{ .string = value };
        },
        .exists => |value| output.negated = negated != !value,
        .starts_with => |value| {
            output.opcode = .prefix;
            output.value = .{ .string = value };
        },
        .ends_with => |value| {
            output.opcode = .suffix;
            output.value = .{ .string = value };
        },
        .contains => |value| {
            output.opcode = .contains;
            output.value = .{ .string = value };
        },
        .equals => |value| try setEquals(allocator, &output, value),
        .gt => |value| try setNumeric(allocator, &output, value, .signed_gt, .float_gt),
        .gte => |value| try setNumeric(allocator, &output, value, .signed_gte, .float_gte),
        .lt => |value| try setNumeric(allocator, &output, value, .signed_lt, .float_lt),
        .lte => |value| try setNumeric(allocator, &output, value, .signed_lte, .float_lte),
    }
    return output;
}

fn setEquals(allocator: std.mem.Allocator, output: *compiler.MatcherSpec, value: proto.policy.Value) PrepareError!void {
    const selected = value.value orelse return error.InvalidValue;
    switch (selected) {
        .bool_value => |item| {
            output.opcode = .boolean_eq;
            output.value = .{ .boolean = item };
        },
        .int_value => |item| {
            output.opcode = .signed_eq;
            output.value = .{ .signed = item };
        },
        .double_value => |item| {
            output.opcode = .float_eq;
            output.value = .{ .float = try std.fmt.allocPrint(allocator, "{d}", .{item}) };
        },
        .bytes_value => |item| {
            output.opcode = .exact;
            output.value = .{ .string = item };
            output.field.value_kind = .bytes;
        },
        .hex_value => return error.InvalidValue,
        .string_value => |item| {
            output.opcode = .exact;
            output.value = .{ .string = item };
        },
    }
}

fn setNumeric(
    allocator: std.mem.Allocator,
    output: *compiler.MatcherSpec,
    value: proto.policy.NumericValue,
    int_opcode: image.MatchOpcode,
    float_opcode: image.MatchOpcode,
) PrepareError!void {
    switch (value.value orelse return error.InvalidValue) {
        .int_value => |item| {
            output.opcode = int_opcode;
            output.value = .{ .signed = item };
        },
        .double_value => |item| {
            output.opcode = float_opcode;
            output.value = .{ .float = try std.fmt.allocPrint(allocator, "{d}", .{item}) };
        },
    }
}

fn logField(allocator: std.mem.Allocator, field: anytype) PrepareError!compiler.FieldSpec {
    return switch (field) {
        .log_field => |item| enumField(allocator, .log, .log_field, @intFromEnum(item), logFieldKind(item)),
        .log_attribute => |item| pathField(allocator, .log, .log_attribute, item),
        .resource_attribute => |item| pathField(allocator, .log, .resource_attribute, item),
        .scope_attribute => |item| pathField(allocator, .log, .scope_attribute, item),
    };
}

fn renameField(allocator: std.mem.Allocator, field: proto.policy.LogRename.from_union) PrepareError!compiler.FieldSpec {
    return switch (field) {
        .from_log_field => |item| enumField(allocator, .log, .log_field, @intFromEnum(item), logFieldKind(item)),
        .from_log_attribute => |item| pathField(allocator, .log, .log_attribute, item),
        .from_resource_attribute => |item| pathField(allocator, .log, .resource_attribute, item),
        .from_scope_attribute => |item| pathField(allocator, .log, .scope_attribute, item),
    };
}

fn metricField(allocator: std.mem.Allocator, field: proto.policy.MetricMatcher.field_union) PrepareError!compiler.FieldSpec {
    return switch (field) {
        .metric_field => |item| enumField(allocator, .metric, .metric_field, @intFromEnum(item), .string),
        .datapoint_attribute => |item| pathField(allocator, .metric, .datapoint_attribute, item),
        .resource_attribute => |item| pathField(allocator, .metric, .resource_attribute, item),
        .scope_attribute => |item| pathField(allocator, .metric, .scope_attribute, item),
        .metric_type => |item| enumField(allocator, .metric, .metric_type, @intFromEnum(item), .string),
        .aggregation_temporality => |item| enumField(
            allocator,
            .metric,
            .aggregation_temporality,
            @intFromEnum(item),
            .string,
        ),
    };
}

fn traceField(allocator: std.mem.Allocator, field: proto.policy.TraceMatcher.field_union) PrepareError!compiler.FieldSpec {
    return switch (field) {
        .trace_field => |item| enumField(allocator, .trace, .trace_field, @intFromEnum(item), traceFieldKind(item)),
        .span_attribute => |item| pathField(allocator, .trace, .span_attribute, item),
        .resource_attribute => |item| pathField(allocator, .trace, .resource_attribute, item),
        .scope_attribute => |item| pathField(allocator, .trace, .scope_attribute, item),
        .span_kind => |item| enumField(allocator, .trace, .span_kind, @intFromEnum(item), .string),
        .span_status => |item| enumField(allocator, .trace, .span_status, @intFromEnum(item), .string),
        .event_name => |item| literalField(.trace, .event_name, item),
        .event_attribute => |item| pathField(allocator, .trace, .event_attribute, item),
        .link_trace_id => |item| literalField(.trace, .link_trace_id, item),
    };
}

fn enumField(
    allocator: std.mem.Allocator,
    signal: image.Signal,
    selector: Selector,
    value: i32,
    kind: image.ValueKind,
) std.mem.Allocator.Error!compiler.FieldSpec {
    return .{
        .signal = signal,
        .value_kind = kind,
        .selector_id = @intFromEnum(selector),
        .name = try std.fmt.allocPrint(allocator, "{d}", .{value}),
    };
}

fn literalField(signal: image.Signal, selector: Selector, value: []const u8) compiler.FieldSpec {
    return .{ .signal = signal, .value_kind = .string, .selector_id = @intFromEnum(selector), .name = value };
}

fn pathField(
    allocator: std.mem.Allocator,
    signal: image.Signal,
    selector: Selector,
    path: AttributePath,
) PrepareError!compiler.FieldSpec {
    if (path.path.items.len == 0) return error.EmptyAttributePath;
    var bytes: std.ArrayList(u8) = .empty;
    for (path.path.items, 0..) |segment, index| {
        if (index != 0) try bytes.append(allocator, 0);
        try bytes.appendSlice(allocator, segment);
    }
    return .{
        .signal = signal,
        .value_kind = .any,
        .selector_id = @intFromEnum(selector),
        .name = try bytes.toOwnedSlice(allocator),
    };
}

fn logFieldKind(field: proto.policy.LogField) image.ValueKind {
    return switch (field) {
        .LOG_FIELD_BODY => .any,
        .LOG_FIELD_TRACE_ID, .LOG_FIELD_SPAN_ID => .bytes,
        else => .string,
    };
}

fn traceFieldKind(field: proto.policy.TraceField) image.ValueKind {
    return switch (field) {
        .TRACE_FIELD_TRACE_ID, .TRACE_FIELD_SPAN_ID, .TRACE_FIELD_PARENT_SPAN_ID => .bytes,
        else => .string,
    };
}

fn adjustIdentifierField(field: *compiler.FieldSpec, matcher: *compiler.MatcherSpec) void {
    if (field.value_kind != .bytes) return;
    if (matcher.opcode == .exact) return;
    field.value_kind = .string;
}

fn decodeHex(allocator: std.mem.Allocator, input: []const u8) PrepareError![]const u8 {
    if (input.len == 0 or input.len % 2 != 0) return error.InvalidValue;
    const output = try allocator.alloc(u8, input.len / 2);
    return std.fmt.hexToBytes(output, input) catch return error.InvalidValue;
}

const Keep = struct {
    verdict: image.Verdict = .keep,
    sampling: ?compiler.SamplingConfig = null,
    limit: u32 = 0,
    window_seconds: u32 = 1,
};

fn parseLogKeep(value: []const u8) PrepareError!Keep {
    if (value.len == 0 or std.mem.eql(u8, value, "all")) return .{};
    if (std.mem.eql(u8, value, "none")) return .{ .verdict = .drop };
    if (value[value.len - 1] == '%') {
        const percentage = std.fmt.parseFloat(f32, value[0 .. value.len - 1]) catch return error.InvalidKeep;
        if (percentage < 0 or percentage > 100) return error.InvalidKeep;
        return .{ .sampling = .{ .percentage = percentage } };
    }
    const slash = std.mem.indexOfScalar(u8, value, '/') orelse return error.InvalidKeep;
    const limit = std.fmt.parseInt(u32, value[0..slash], 10) catch return error.InvalidKeep;
    if (limit == 0) return error.InvalidKeep;
    var duration = value[slash + 1 ..];
    if (duration.len == 0) return error.InvalidKeep;
    const unit = duration[duration.len - 1];
    duration = duration[0 .. duration.len - 1];
    const count = if (duration.len == 0) 1 else std.fmt.parseInt(u32, duration, 10) catch return error.InvalidKeep;
    if (count == 0) return error.InvalidKeep;
    const seconds = switch (unit) {
        's' => count,
        'm' => std.math.mul(u32, count, 60) catch return error.InvalidKeep,
        else => return error.InvalidKeep,
    };
    return .{ .limit = limit, .window_seconds = seconds };
}

fn samplingConfig(value: proto.policy.TraceSamplingConfig) PrepareError!compiler.SamplingConfig {
    const precision = value.sampling_precision orelse 4;
    if (precision < 1 or precision > 14) return error.InvalidValue;
    return .{
        .percentage = value.percentage,
        .mode = switch (value.mode orelse .SAMPLING_MODE_HASH_SEED) {
            .SAMPLING_MODE_UNSPECIFIED, .SAMPLING_MODE_HASH_SEED => .hash_seed,
            .SAMPLING_MODE_PROPORTIONAL => .proportional,
            .SAMPLING_MODE_EQUALIZING => .equalizing,
            else => return error.InvalidValue,
        },
        .precision = @intCast(precision),
        .hash_seed = value.hash_seed orelse 0,
        .fail_closed = value.fail_closed orelse true,
    };
}

fn joinPair(allocator: std.mem.Allocator, first: []const u8, second: []const u8) std.mem.Allocator.Error![]const u8 {
    const output = try allocator.alloc(u8, first.len + 1 + second.len);
    @memcpy(output[0..first.len], first);
    output[first.len] = 0;
    @memcpy(output[first.len + 1 ..], second);
    return output;
}
