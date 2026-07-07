const std = @import("std");
const proto = @import("proto");

const Policy = proto.policy.Policy;
const LogTarget = proto.policy.LogTarget;
const LogMatcher = proto.policy.LogMatcher;
const LogField = proto.policy.LogField;
const LogTransform = proto.policy.LogTransform;
const LogRemove = proto.policy.LogRemove;
const LogRedact = proto.policy.LogRedact;
const LogRename = proto.policy.LogRename;
const LogAdd = proto.policy.LogAdd;
const MetricTarget = proto.policy.MetricTarget;
const MetricMatcher = proto.policy.MetricMatcher;
const MetricField = proto.policy.MetricField;
const MetricType = proto.policy.MetricType;
const AggregationTemporality = proto.policy.AggregationTemporality;
const TraceTarget = proto.policy.TraceTarget;
const TraceMatcher = proto.policy.TraceMatcher;
const TraceField = proto.policy.TraceField;
const TraceSamplingConfig = proto.policy.TraceSamplingConfig;
const SamplingMode = proto.policy.SamplingMode;
const SpanKind = proto.policy.SpanKind;
const SpanStatusCode = proto.policy.SpanStatusCode;
const AttributePath = proto.policy.AttributePath;
const LogSampleKey = proto.policy.LogSampleKey;
const Value = proto.policy.Value;
const NumericValue = proto.policy.NumericValue;

/// Parse an AttributePath from a JSON value.
/// Supports three formats:
/// - String shorthand: "key" -> ["key"]
/// - Array shorthand: ["http", "method"] -> ["http", "method"]
/// - Canonical: {"path": ["http", "method"]} -> ["http", "method"]
fn parseAttributePath(allocator: std.mem.Allocator, value: std.json.Value) !AttributePath {
    var attr_path: AttributePath = .{};
    errdefer {
        for (attr_path.path.items) |segment| {
            allocator.free(segment);
        }
        attr_path.path.deinit(allocator);
    }

    switch (value) {
        .string => |s| {
            // String shorthand: "key" -> single-element path
            try attr_path.path.append(allocator, try allocator.dupe(u8, s));
        },
        .array => |arr| {
            // Array shorthand: ["http", "method"]
            try attr_path.path.ensureTotalCapacity(allocator, arr.items.len);
            for (arr.items) |item| {
                switch (item) {
                    .string => |s| {
                        attr_path.path.appendAssumeCapacity(try allocator.dupe(u8, s));
                    },
                    else => return error.InvalidAttributePath,
                }
            }
        },
        .object => |obj| {
            // Canonical format: {"path": ["http", "method"]}
            const path_value = obj.get("path") orelse return error.InvalidAttributePath;
            switch (path_value) {
                .array => |arr| {
                    try attr_path.path.ensureTotalCapacity(allocator, arr.items.len);
                    for (arr.items) |item| {
                        switch (item) {
                            .string => |s| {
                                attr_path.path.appendAssumeCapacity(try allocator.dupe(u8, s));
                            },
                            else => return error.InvalidAttributePath,
                        }
                    }
                },
                else => return error.InvalidAttributePath,
            }
        },
        else => return error.InvalidAttributePath,
    }

    if (attr_path.path.items.len == 0) {
        return error.EmptyAttributePath;
    }

    return attr_path;
}

/// Create an AttributePath from a simple key string.
/// For backward compatibility, a single key becomes a single-element path.
fn makeAttributePath(allocator: std.mem.Allocator, key: []const u8) !AttributePath {
    var attr_path: AttributePath = .{};
    try attr_path.path.append(allocator, try allocator.dupe(u8, key));
    return attr_path;
}

// =============================================================================
// New JSON Schema - matches YAML format closely
// =============================================================================

/// JSON schema for a log matcher
/// Example: { "log_field": "body", "regex": "GET /health" }
/// Example: { "log_attribute": "service", "regex": "payment.*" }
/// Example: { "log_attribute": ["http", "method"], "regex": "GET" }
/// Example: { "log_attribute": {"path": ["http", "method"]}, "regex": "GET" }
/// Example: { "log_field": "body", "starts_with": "ERROR", "case_insensitive": true }
/// Example: { "log_attribute": "cache.hit", "equals": true }
/// Example: { "log_attribute": ["http.response.status_code"], "gte": 500 }
const LogMatcherJson = struct {
    // Field selectors (one of these should be set)
    log_field: ?[]const u8 = null, // "body", "severity_text", etc.
    log_attribute: ?std.json.Value = null, // attribute path (string, array, or object)
    resource_attribute: ?std.json.Value = null, // resource attribute path
    scope_attribute: ?std.json.Value = null, // scope attribute path

    // Match type (one of these should be set)
    regex: ?[]const u8 = null,
    exact: ?[]const u8 = null,
    exists: ?bool = null,
    starts_with: ?[]const u8 = null,
    ends_with: ?[]const u8 = null,
    contains: ?[]const u8 = null,
    // Typed match types (v1.5.0). Using std.json.Value for shorthand inference:
    //   equals: true   → bool_value
    //   equals: 200    → int_value
    //   equals: 0.5    → double_value
    //   equals: "foo"  → string_value (v1.6.0)
    //   equals: { hex_value: "deadbeef" }  → canonical
    // gt/gte/lt/lte accept integer or float literals only.
    equals: ?std.json.Value = null,
    gt: ?std.json.Value = null,
    gte: ?std.json.Value = null,
    lt: ?std.json.Value = null,
    lte: ?std.json.Value = null,

    // Optional flags
    negate: bool = false,
    case_insensitive: bool = false,
};

/// JSON schema for a metric matcher
/// Example: { "metric_field": "name", "regex": "^debug\\." }
/// Example: { "datapoint_attribute": "env", "exact": "dev" }
/// Example: { "datapoint_attribute": ["tags", "env"], "exact": "prod" }
/// Example: { "metric_type": "METRIC_TYPE_HISTOGRAM", "exists": true }
/// Example: { "aggregation_temporality": "AGGREGATION_TEMPORALITY_DELTA", "exists": true }
const MetricMatcherJson = struct {
    // Field selectors (one of these should be set)
    metric_field: ?[]const u8 = null, // "name", "unit", etc.
    datapoint_attribute: ?std.json.Value = null, // datapoint attribute path
    resource_attribute: ?std.json.Value = null, // resource attribute path
    scope_attribute: ?std.json.Value = null, // scope attribute path
    metric_type: ?[]const u8 = null, // "METRIC_TYPE_GAUGE", "METRIC_TYPE_SUM", etc.
    aggregation_temporality: ?[]const u8 = null, // "AGGREGATION_TEMPORALITY_DELTA", etc.

    // Match type (one of these should be set)
    regex: ?[]const u8 = null,
    exact: ?[]const u8 = null,
    exists: ?bool = null,
    starts_with: ?[]const u8 = null,
    ends_with: ?[]const u8 = null,
    contains: ?[]const u8 = null,
    // Typed match types (v1.5.0).
    equals: ?std.json.Value = null,
    gt: ?std.json.Value = null,
    gte: ?std.json.Value = null,
    lt: ?std.json.Value = null,
    lte: ?std.json.Value = null,

    // Optional flags
    negate: bool = false,
    case_insensitive: bool = false,
};

/// JSON schema for a remove transform
const RemoveJson = struct {
    log_field: ?[]const u8 = null,
    log_attribute: ?std.json.Value = null,
    resource_attribute: ?std.json.Value = null,
    scope_attribute: ?std.json.Value = null,
};

/// JSON schema for a redact transform
const RedactJson = struct {
    log_field: ?[]const u8 = null,
    log_attribute: ?std.json.Value = null,
    resource_attribute: ?std.json.Value = null,
    scope_attribute: ?std.json.Value = null,
    replacement: []const u8 = "[REDACTED]",
    /// Optional RE2 regular expression for targeted replacement (v1.4.0). When
    /// set, `replacement` is interpreted as a template with `$0`, `$1..$99`,
    /// `${N}`, `${name}`, `$$` capture references. The regex operates on the
    /// textual representation returned by the accessor — consumers that want
    /// regex redact to no-op on non-string AnyValue variants should return null
    /// from their accessor for those values.
    regex: ?[]const u8 = null,
};

/// JSON schema for a rename transform
const RenameJson = struct {
    from_log_field: ?[]const u8 = null,
    from_log_attribute: ?std.json.Value = null,
    from_resource_attribute: ?std.json.Value = null,
    from_scope_attribute: ?std.json.Value = null,
    to: []const u8,
    upsert: bool = false,
};

/// JSON schema for an add transform
const AddJson = struct {
    log_field: ?[]const u8 = null,
    log_attribute: ?std.json.Value = null,
    resource_attribute: ?std.json.Value = null,
    scope_attribute: ?std.json.Value = null,
    value: []const u8,
    upsert: bool = false,
};

/// JSON schema for transforms
const TransformJson = struct {
    remove: ?[]RemoveJson = null,
    redact: ?[]RedactJson = null,
    rename: ?[]RenameJson = null,
    add: ?[]AddJson = null,
};

/// JSON schema for log sample key
/// Example: { "log_field": "body" }
/// Example: { "log_attribute": "trace_id" }
/// Example: { "log_attribute": ["request", "id"] }
const LogSampleKeyJson = struct {
    log_field: ?[]const u8 = null,
    log_attribute: ?std.json.Value = null,
    resource_attribute: ?std.json.Value = null,
    scope_attribute: ?std.json.Value = null,
};

/// JSON schema for log target
/// Example:
/// "log": {
///   "match": [{ "log_field": "body", "regex": "GET /health" }],
///   "keep": "none",
///   "transform": { ... },
///   "sample_key": { "log_attribute": "trace_id" }
/// }
const LogTargetJson = struct {
    match: ?[]LogMatcherJson = null,
    keep: []const u8 = "all",
    transform: ?TransformJson = null,
    sample_key: ?LogSampleKeyJson = null,
};

/// JSON schema for metric target
/// Example:
/// "metric": {
///   "match": [{ "metric_field": "name", "regex": "^debug\\." }],
///   "keep": false
/// }
const MetricTargetJson = struct {
    match: ?[]MetricMatcherJson = null,
    keep: bool = true,
};

/// JSON schema for a trace matcher
/// Example: { "trace_field": "TRACE_FIELD_NAME", "regex": "^ping$" }
/// Example: { "span_attribute": "peer.service", "exists": true }
/// Example: { "span_attribute": ["http", "method"], "regex": "GET" }
/// Example: { "span_kind": "SPAN_KIND_INTERNAL", "exists": true }
const TraceMatcherJson = struct {
    // Field selectors (one of these should be set)
    trace_field: ?[]const u8 = null, // "TRACE_FIELD_NAME", "TRACE_FIELD_TRACE_ID", etc.
    span_attribute: ?std.json.Value = null, // span attribute path
    resource_attribute: ?std.json.Value = null, // resource attribute path
    scope_attribute: ?std.json.Value = null, // scope attribute path
    span_kind: ?[]const u8 = null, // "SPAN_KIND_INTERNAL", "SPAN_KIND_SERVER", etc.
    span_status: ?[]const u8 = null, // "SPAN_STATUS_CODE_OK", "SPAN_STATUS_CODE_ERROR"
    event_name: ?[]const u8 = null, // event name to match
    event_attribute: ?std.json.Value = null, // event attribute path
    link_trace_id: ?[]const u8 = null, // link trace_id matcher

    // Match type (one of these should be set)
    regex: ?[]const u8 = null,
    exact: ?[]const u8 = null,
    exists: ?bool = null,
    starts_with: ?[]const u8 = null,
    ends_with: ?[]const u8 = null,
    contains: ?[]const u8 = null,
    // Typed match types (v1.5.0).
    equals: ?std.json.Value = null,
    gt: ?std.json.Value = null,
    gte: ?std.json.Value = null,
    lt: ?std.json.Value = null,
    lte: ?std.json.Value = null,

    // Optional flags
    negate: bool = false,
    case_insensitive: bool = false,
};

/// JSON schema for trace sampling config
const TraceSamplingConfigJson = struct {
    percentage: f32 = 100.0,
    mode: ?[]const u8 = null, // "SAMPLING_MODE_HASH_SEED", "SAMPLING_MODE_PROPORTIONAL", etc.
    sampling_precision: ?u32 = null,
    hash_seed: ?u32 = null,
    fail_closed: ?bool = null,
};

/// JSON schema for trace target
/// Example:
/// "trace": {
///   "match": [{ "trace_field": "TRACE_FIELD_NAME", "regex": "^ping$" }],
///   "keep": { "percentage": 50.0, "mode": "SAMPLING_MODE_HASH_SEED" }
/// }
const TraceTargetJson = struct {
    match: ?[]TraceMatcherJson = null,
    keep: ?TraceSamplingConfigJson = null,
};

/// JSON schema for a policy
/// Example:
/// {
///   "id": "drop-debug-metrics",
///   "name": "Drop debug metrics",
///   "metric": { ... }
/// }
/// or:
/// {
///   "id": "drop-health-checks",
///   "name": "Drop health check logs",
///   "log": { ... }
/// }
const PolicyJson = struct {
    id: []const u8,
    name: []const u8,
    description: ?[]const u8 = null,
    enabled: bool = true,

    // Target type (one of these should be set)
    log: ?LogTargetJson = null,
    metric: ?MetricTargetJson = null,
    trace: ?TraceTargetJson = null,
};

/// JSON schema for a policies file
const PoliciesFileJson = struct {
    policies: []PolicyJson,
};

// =============================================================================
// Public API
// =============================================================================

/// Parse policies-only JSON file
pub fn parsePoliciesFile(allocator: std.mem.Allocator, path: []const u8) ![]Policy {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const contents = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(contents);

    return parsePoliciesBytes(allocator, contents);
}

/// Parse policies from JSON bytes
pub fn parsePoliciesBytes(allocator: std.mem.Allocator, json_bytes: []const u8) ![]Policy {
    const parsed = try std.json.parseFromSlice(
        PoliciesFileJson,
        allocator,
        json_bytes,
        .{ .allocate = .alloc_always },
    );
    defer parsed.deinit();

    const json_policies = parsed.value;
    return parsePolicies(allocator, json_policies.policies);
}

/// Parse policies from JSON array
pub fn parsePolicies(allocator: std.mem.Allocator, json_policies: []PolicyJson) ![]Policy {
    var policies = try allocator.alloc(Policy, json_policies.len);

    for (json_policies, 0..) |json_policy, i| {
        policies[i] = try parsePolicy(allocator, json_policy);
    }

    return policies;
}

/// Parse a single policy
fn parsePolicy(allocator: std.mem.Allocator, json_policy: PolicyJson) !Policy {
    const id = try allocator.dupe(u8, json_policy.id);
    const name = try allocator.dupe(u8, json_policy.name);
    const description = if (json_policy.description) |desc| try allocator.dupe(u8, desc) else &.{};

    // Determine target type
    var target: ?Policy.target_union = null;

    if (json_policy.log) |log_json| {
        target = .{ .log = try parseLogTarget(allocator, log_json) };
    } else if (json_policy.metric) |metric_json| {
        target = .{ .metric = try parseMetricTarget(allocator, metric_json) };
    } else if (json_policy.trace) |trace_json| {
        target = .{ .trace = try parseTraceTarget(allocator, trace_json) };
    }

    return .{
        .id = id,
        .name = name,
        .description = description,
        .enabled = json_policy.enabled,
        .target = target,
    };
}

// =============================================================================
// Log Target Parsing
// =============================================================================

fn parseLogTarget(allocator: std.mem.Allocator, json: LogTargetJson) !LogTarget {
    var matchers = std.ArrayList(LogMatcher).empty;

    if (json.match) |json_matchers| {
        try matchers.ensureTotalCapacity(allocator, json_matchers.len);
        for (json_matchers) |jm| {
            const matcher = try parseLogMatcher(allocator, jm);
            matchers.appendAssumeCapacity(matcher);
        }
    }

    var transform: ?LogTransform = null;
    if (json.transform) |jt| {
        transform = try parseLogTransform(allocator, jt);
    }

    var sample_key: ?LogSampleKey = null;
    if (json.sample_key) |sk| {
        sample_key = try parseLogSampleKey(allocator, sk);
    }

    return .{
        .match = matchers,
        .keep = try allocator.dupe(u8, json.keep),
        .transform = transform,
        .sample_key = sample_key,
    };
}

fn parseLogSampleKey(allocator: std.mem.Allocator, json: LogSampleKeyJson) !LogSampleKey {
    const field: LogSampleKey.field_union = blk: {
        if (json.log_field) |field_name| {
            break :blk .{ .log_field = try parseLogFieldName(field_name) };
        } else if (json.log_attribute) |value| {
            break :blk .{ .log_attribute = try parseAttributePath(allocator, value) };
        } else if (json.resource_attribute) |value| {
            break :blk .{ .resource_attribute = try parseAttributePath(allocator, value) };
        } else if (json.scope_attribute) |value| {
            break :blk .{ .scope_attribute = try parseAttributePath(allocator, value) };
        } else {
            return error.MissingSampleKeyField;
        }
    };
    return .{ .field = field };
}

fn parseLogMatcher(allocator: std.mem.Allocator, jm: LogMatcherJson) !LogMatcher {
    // Parse field
    const field: LogMatcher.field_union = blk: {
        if (jm.log_field) |field_name| {
            break :blk .{ .log_field = try parseLogFieldName(field_name) };
        } else if (jm.log_attribute) |value| {
            break :blk .{ .log_attribute = try parseAttributePath(allocator, value) };
        } else if (jm.resource_attribute) |value| {
            break :blk .{ .resource_attribute = try parseAttributePath(allocator, value) };
        } else if (jm.scope_attribute) |value| {
            break :blk .{ .scope_attribute = try parseAttributePath(allocator, value) };
        } else {
            return error.MissingField;
        }
    };

    // Parse match
    const match: LogMatcher.match_union = blk: {
        if (jm.regex) |pattern| {
            break :blk .{ .regex = try allocator.dupe(u8, pattern) };
        } else if (jm.exact) |pattern| {
            break :blk .{ .exact = try allocator.dupe(u8, pattern) };
        } else if (jm.exists) |exists| {
            break :blk .{ .exists = exists };
        } else if (jm.starts_with) |pattern| {
            break :blk .{ .starts_with = try allocator.dupe(u8, pattern) };
        } else if (jm.ends_with) |pattern| {
            break :blk .{ .ends_with = try allocator.dupe(u8, pattern) };
        } else if (jm.contains) |pattern| {
            break :blk .{ .contains = try allocator.dupe(u8, pattern) };
        } else if (jm.equals) |v| {
            break :blk .{ .equals = try parseValue(allocator, v) };
        } else if (jm.gt) |v| {
            break :blk .{ .gt = try parseNumericValue(v) };
        } else if (jm.gte) |v| {
            break :blk .{ .gte = try parseNumericValue(v) };
        } else if (jm.lt) |v| {
            break :blk .{ .lt = try parseNumericValue(v) };
        } else if (jm.lte) |v| {
            break :blk .{ .lte = try parseNumericValue(v) };
        } else {
            return error.MissingMatch;
        }
    };

    return .{
        .negate = jm.negate,
        .case_insensitive = jm.case_insensitive,
        .field = field,
        .match = match,
    };
}

// =============================================================================
// Typed Value Parsing (v1.5.0)
// =============================================================================

/// Parse a Value from a JSON value using shorthand inference:
///   bool   → bool_value
///   int    → int_value
///   float  → double_value
///   string → string_value (v1.6.0)
///   object with hex_value/bytes_value/bool_value/int_value/double_value/string_value → canonical
fn parseValue(allocator: std.mem.Allocator, json_val: std.json.Value) !Value {
    switch (json_val) {
        .bool => |b| return Value{ .value = .{ .bool_value = b } },
        .integer => |i| return Value{ .value = .{ .int_value = i } },
        .float => |f| return Value{ .value = .{ .double_value = f } },
        .string => |s| return Value{ .value = .{ .string_value = try allocator.dupe(u8, s) } },
        .object => |obj| {
            if (obj.get("bool_value")) |v| {
                if (v != .bool) return error.InvalidValue;
                return Value{ .value = .{ .bool_value = v.bool } };
            }
            if (obj.get("int_value")) |v| {
                if (v != .integer) return error.InvalidValue;
                return Value{ .value = .{ .int_value = v.integer } };
            }
            if (obj.get("double_value")) |v| {
                if (v != .float) return error.InvalidValue;
                return Value{ .value = .{ .double_value = v.float } };
            }
            if (obj.get("hex_value")) |v| {
                if (v != .string) return error.InvalidValue;
                const bytes = try hexDecode(allocator, v.string);
                return Value{ .value = .{ .bytes_value = bytes } };
            }
            if (obj.get("bytes_value")) |v| {
                if (v != .string) return error.InvalidValue;
                const bytes = try allocator.dupe(u8, v.string);
                return Value{ .value = .{ .bytes_value = bytes } };
            }
            if (obj.get("string_value")) |v| {
                if (v != .string) return error.InvalidValue;
                return Value{ .value = .{ .string_value = try allocator.dupe(u8, v.string) } };
            }
            return error.InvalidValue;
        },
        else => return error.InvalidValue,
    }
}

/// Parse a NumericValue from a JSON value.
/// Accepts integer or float literals only.
fn parseNumericValue(json_val: std.json.Value) !NumericValue {
    switch (json_val) {
        .integer => |i| return NumericValue{ .value = .{ .int_value = i } },
        .float => |f| return NumericValue{ .value = .{ .double_value = f } },
        else => return error.InvalidNumericValue,
    }
}

/// Decode a lowercase-hex string to bytes. Caller owns the returned slice.
fn hexDecode(allocator: std.mem.Allocator, hex: []const u8) ![]const u8 {
    if (hex.len % 2 != 0) return error.InvalidHexValue;
    const out = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(out);
    for (0..out.len) |i| {
        const hi = try hexDigit(hex[i * 2]);
        const lo = try hexDigit(hex[i * 2 + 1]);
        out[i] = (hi << 4) | lo;
    }
    return out;
}

fn hexDigit(c: u8) !u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => error.InvalidHexValue,
    };
}

/// Maps a string `name` to an enum value of type `T` using a table of
/// `.{ alias, value }` entries, returning `err` when nothing matches. List an
/// enum value more than once to give it several accepted aliases (e.g. both the
/// short form and the proto constant name).
fn parseEnumAlias(
    comptime T: type,
    comptime table: []const struct { []const u8, T },
    comptime err: anyerror,
    name: []const u8,
) !T {
    inline for (table) |entry| {
        if (std.mem.eql(u8, name, entry[0])) return entry[1];
    }
    return err;
}

fn parseLogFieldName(name: []const u8) !LogField {
    return parseEnumAlias(LogField, &.{
        .{ "body", .LOG_FIELD_BODY },
        .{ "severity_text", .LOG_FIELD_SEVERITY_TEXT },
        .{ "trace_id", .LOG_FIELD_TRACE_ID },
        .{ "span_id", .LOG_FIELD_SPAN_ID },
        .{ "event_name", .LOG_FIELD_EVENT_NAME },
        .{ "resource_schema_url", .LOG_FIELD_RESOURCE_SCHEMA_URL },
        .{ "scope_schema_url", .LOG_FIELD_SCOPE_SCHEMA_URL },
    }, error.InvalidLogField, name);
}

fn parseLogTransform(allocator: std.mem.Allocator, jt: TransformJson) !LogTransform {
    var transform: LogTransform = .{};

    if (jt.remove) |removes| {
        try transform.remove.ensureTotalCapacity(allocator, removes.len);
        for (removes) |jr| {
            const remove = try parseLogRemove(allocator, jr);
            transform.remove.appendAssumeCapacity(remove);
        }
    }

    if (jt.redact) |redacts| {
        try transform.redact.ensureTotalCapacity(allocator, redacts.len);
        for (redacts) |jr| {
            const redact = try parseLogRedact(allocator, jr);
            transform.redact.appendAssumeCapacity(redact);
        }
    }

    if (jt.rename) |renames| {
        try transform.rename.ensureTotalCapacity(allocator, renames.len);
        for (renames) |jr| {
            const rename = try parseLogRename(allocator, jr);
            transform.rename.appendAssumeCapacity(rename);
        }
    }

    if (jt.add) |adds| {
        try transform.add.ensureTotalCapacity(allocator, adds.len);
        for (adds) |ja| {
            const add = try parseLogAdd(allocator, ja);
            transform.add.appendAssumeCapacity(add);
        }
    }

    return transform;
}

fn parseLogRemove(allocator: std.mem.Allocator, jr: RemoveJson) !LogRemove {
    const field: LogRemove.field_union = blk: {
        if (jr.log_field) |field_name| {
            break :blk .{ .log_field = try parseLogFieldName(field_name) };
        } else if (jr.log_attribute) |value| {
            break :blk .{ .log_attribute = try parseAttributePath(allocator, value) };
        } else if (jr.resource_attribute) |value| {
            break :blk .{ .resource_attribute = try parseAttributePath(allocator, value) };
        } else if (jr.scope_attribute) |value| {
            break :blk .{ .scope_attribute = try parseAttributePath(allocator, value) };
        } else {
            return error.MissingField;
        }
    };

    return .{ .field = field };
}

fn parseLogRedact(allocator: std.mem.Allocator, jr: RedactJson) !LogRedact {
    const field: LogRedact.field_union = blk: {
        if (jr.log_field) |field_name| {
            break :blk .{ .log_field = try parseLogFieldName(field_name) };
        } else if (jr.log_attribute) |value| {
            break :blk .{ .log_attribute = try parseAttributePath(allocator, value) };
        } else if (jr.resource_attribute) |value| {
            break :blk .{ .resource_attribute = try parseAttributePath(allocator, value) };
        } else if (jr.scope_attribute) |value| {
            break :blk .{ .scope_attribute = try parseAttributePath(allocator, value) };
        } else {
            return error.MissingField;
        }
    };

    const regex_copy: ?[]const u8 = if (jr.regex) |r| try allocator.dupe(u8, r) else null;

    return .{
        .field = field,
        .replacement = try allocator.dupe(u8, jr.replacement),
        .regex = regex_copy,
    };
}

fn parseLogRename(allocator: std.mem.Allocator, jr: RenameJson) !LogRename {
    const from: LogRename.from_union = blk: {
        if (jr.from_log_field) |field_name| {
            break :blk .{ .from_log_field = try parseLogFieldName(field_name) };
        } else if (jr.from_log_attribute) |value| {
            break :blk .{ .from_log_attribute = try parseAttributePath(allocator, value) };
        } else if (jr.from_resource_attribute) |value| {
            break :blk .{ .from_resource_attribute = try parseAttributePath(allocator, value) };
        } else if (jr.from_scope_attribute) |value| {
            break :blk .{ .from_scope_attribute = try parseAttributePath(allocator, value) };
        } else {
            return error.MissingField;
        }
    };

    return .{
        .from = from,
        .to = try allocator.dupe(u8, jr.to),
        .upsert = jr.upsert,
    };
}

fn parseLogAdd(allocator: std.mem.Allocator, ja: AddJson) !LogAdd {
    const field: LogAdd.field_union = blk: {
        if (ja.log_field) |field_name| {
            break :blk .{ .log_field = try parseLogFieldName(field_name) };
        } else if (ja.log_attribute) |value| {
            break :blk .{ .log_attribute = try parseAttributePath(allocator, value) };
        } else if (ja.resource_attribute) |value| {
            break :blk .{ .resource_attribute = try parseAttributePath(allocator, value) };
        } else if (ja.scope_attribute) |value| {
            break :blk .{ .scope_attribute = try parseAttributePath(allocator, value) };
        } else {
            return error.MissingField;
        }
    };

    return .{
        .field = field,
        .value = try allocator.dupe(u8, ja.value),
        .upsert = ja.upsert,
    };
}

// =============================================================================
// Metric Target Parsing
// =============================================================================

fn parseMetricTarget(allocator: std.mem.Allocator, json: MetricTargetJson) !MetricTarget {
    var matchers = std.ArrayList(MetricMatcher).empty;

    if (json.match) |json_matchers| {
        try matchers.ensureTotalCapacity(allocator, json_matchers.len);
        for (json_matchers) |jm| {
            const matcher = try parseMetricMatcher(allocator, jm);
            matchers.appendAssumeCapacity(matcher);
        }
    }

    return .{
        .match = matchers,
        .keep = json.keep,
    };
}

fn parseMetricMatcher(allocator: std.mem.Allocator, jm: MetricMatcherJson) !MetricMatcher {
    // Parse field
    const field: MetricMatcher.field_union = blk: {
        if (jm.metric_field) |field_name| {
            break :blk .{ .metric_field = try parseMetricFieldName(field_name) };
        } else if (jm.datapoint_attribute) |value| {
            break :blk .{ .datapoint_attribute = try parseAttributePath(allocator, value) };
        } else if (jm.resource_attribute) |value| {
            break :blk .{ .resource_attribute = try parseAttributePath(allocator, value) };
        } else if (jm.scope_attribute) |value| {
            break :blk .{ .scope_attribute = try parseAttributePath(allocator, value) };
        } else if (jm.metric_type) |type_name| {
            break :blk .{ .metric_type = try parseMetricType(type_name) };
        } else if (jm.aggregation_temporality) |temporality_name| {
            break :blk .{
                .aggregation_temporality = try parseAggregationTemporality(temporality_name),
            };
        } else {
            return error.MissingField;
        }
    };

    // Parse match (enum fields like metric_type and aggregation_temporality
    // default to exists=true when no explicit match is specified)
    const match: MetricMatcher.match_union = blk: {
        if (jm.regex) |pattern| {
            break :blk .{ .regex = try allocator.dupe(u8, pattern) };
        } else if (jm.exact) |pattern| {
            break :blk .{ .exact = try allocator.dupe(u8, pattern) };
        } else if (jm.exists) |exists| {
            break :blk .{ .exists = exists };
        } else if (jm.starts_with) |pattern| {
            break :blk .{ .starts_with = try allocator.dupe(u8, pattern) };
        } else if (jm.ends_with) |pattern| {
            break :blk .{ .ends_with = try allocator.dupe(u8, pattern) };
        } else if (jm.contains) |pattern| {
            break :blk .{ .contains = try allocator.dupe(u8, pattern) };
        } else if (jm.equals) |v| {
            break :blk .{ .equals = try parseValue(allocator, v) };
        } else if (jm.gt) |v| {
            break :blk .{ .gt = try parseNumericValue(v) };
        } else if (jm.gte) |v| {
            break :blk .{ .gte = try parseNumericValue(v) };
        } else if (jm.lt) |v| {
            break :blk .{ .lt = try parseNumericValue(v) };
        } else if (jm.lte) |v| {
            break :blk .{ .lte = try parseNumericValue(v) };
        } else if (jm.metric_type != null or jm.aggregation_temporality != null) {
            break :blk .{ .exists = true };
        } else {
            return error.MissingMatch;
        }
    };

    return .{
        .negate = jm.negate,
        .case_insensitive = jm.case_insensitive,
        .field = field,
        .match = match,
    };
}

fn parseMetricFieldName(name: []const u8) !MetricField {
    return parseEnumAlias(MetricField, &.{
        .{ "name", .METRIC_FIELD_NAME },
        .{ "description", .METRIC_FIELD_DESCRIPTION },
        .{ "unit", .METRIC_FIELD_UNIT },
        .{ "resource_schema_url", .METRIC_FIELD_RESOURCE_SCHEMA_URL },
        .{ "scope_schema_url", .METRIC_FIELD_SCOPE_SCHEMA_URL },
        .{ "scope_name", .METRIC_FIELD_SCOPE_NAME },
        .{ "scope_version", .METRIC_FIELD_SCOPE_VERSION },
    }, error.InvalidMetricField, name);
}

fn parseMetricType(name: []const u8) !MetricType {
    return parseEnumAlias(MetricType, &.{
        .{ "gauge", .METRIC_TYPE_GAUGE },
        .{ "METRIC_TYPE_GAUGE", .METRIC_TYPE_GAUGE },
        .{ "sum", .METRIC_TYPE_SUM },
        .{ "METRIC_TYPE_SUM", .METRIC_TYPE_SUM },
        .{ "histogram", .METRIC_TYPE_HISTOGRAM },
        .{ "METRIC_TYPE_HISTOGRAM", .METRIC_TYPE_HISTOGRAM },
        .{ "exponential_histogram", .METRIC_TYPE_EXPONENTIAL_HISTOGRAM },
        .{ "METRIC_TYPE_EXPONENTIAL_HISTOGRAM", .METRIC_TYPE_EXPONENTIAL_HISTOGRAM },
        .{ "summary", .METRIC_TYPE_SUMMARY },
        .{ "METRIC_TYPE_SUMMARY", .METRIC_TYPE_SUMMARY },
    }, error.InvalidMetricType, name);
}

fn parseAggregationTemporality(name: []const u8) !AggregationTemporality {
    return parseEnumAlias(AggregationTemporality, &.{
        .{ "delta", .AGGREGATION_TEMPORALITY_DELTA },
        .{ "AGGREGATION_TEMPORALITY_DELTA", .AGGREGATION_TEMPORALITY_DELTA },
        .{ "cumulative", .AGGREGATION_TEMPORALITY_CUMULATIVE },
        .{ "AGGREGATION_TEMPORALITY_CUMULATIVE", .AGGREGATION_TEMPORALITY_CUMULATIVE },
    }, error.InvalidAggregationTemporality, name);
}

// =============================================================================
// Trace Target Parsing
// =============================================================================

fn parseTraceTarget(allocator: std.mem.Allocator, json: TraceTargetJson) !TraceTarget {
    var matchers = std.ArrayList(TraceMatcher).empty;

    if (json.match) |json_matchers| {
        try matchers.ensureTotalCapacity(allocator, json_matchers.len);
        for (json_matchers) |jm| {
            const matcher = try parseTraceMatcher(allocator, jm);
            matchers.appendAssumeCapacity(matcher);
        }
    }

    var sampling_config: ?TraceSamplingConfig = null;
    if (json.keep) |jk| {
        sampling_config = try parseTraceSamplingConfig(jk);
    }

    return .{
        .match = matchers,
        .keep = sampling_config,
    };
}

fn parseTraceMatcher(allocator: std.mem.Allocator, jm: TraceMatcherJson) !TraceMatcher {
    // Parse field
    const field: TraceMatcher.field_union = blk: {
        if (jm.trace_field) |field_name| {
            break :blk .{ .trace_field = try parseTraceFieldName(field_name) };
        } else if (jm.span_attribute) |value| {
            break :blk .{ .span_attribute = try parseAttributePath(allocator, value) };
        } else if (jm.resource_attribute) |value| {
            break :blk .{ .resource_attribute = try parseAttributePath(allocator, value) };
        } else if (jm.scope_attribute) |value| {
            break :blk .{ .scope_attribute = try parseAttributePath(allocator, value) };
        } else if (jm.span_kind) |kind_name| {
            break :blk .{ .span_kind = try parseSpanKind(kind_name) };
        } else if (jm.span_status) |status_name| {
            break :blk .{ .span_status = try parseSpanStatusCode(status_name) };
        } else if (jm.event_name) |name| {
            break :blk .{ .event_name = try allocator.dupe(u8, name) };
        } else if (jm.event_attribute) |value| {
            break :blk .{ .event_attribute = try parseAttributePath(allocator, value) };
        } else if (jm.link_trace_id) |id| {
            break :blk .{ .link_trace_id = try allocator.dupe(u8, id) };
        } else {
            return error.MissingField;
        }
    };

    // Parse match
    const match: TraceMatcher.match_union = blk: {
        if (jm.regex) |pattern| {
            break :blk .{ .regex = try allocator.dupe(u8, pattern) };
        } else if (jm.exact) |pattern| {
            break :blk .{ .exact = try allocator.dupe(u8, pattern) };
        } else if (jm.exists) |exists| {
            break :blk .{ .exists = exists };
        } else if (jm.starts_with) |pattern| {
            break :blk .{ .starts_with = try allocator.dupe(u8, pattern) };
        } else if (jm.ends_with) |pattern| {
            break :blk .{ .ends_with = try allocator.dupe(u8, pattern) };
        } else if (jm.contains) |pattern| {
            break :blk .{ .contains = try allocator.dupe(u8, pattern) };
        } else if (jm.equals) |v| {
            break :blk .{ .equals = try parseValue(allocator, v) };
        } else if (jm.gt) |v| {
            break :blk .{ .gt = try parseNumericValue(v) };
        } else if (jm.gte) |v| {
            break :blk .{ .gte = try parseNumericValue(v) };
        } else if (jm.lt) |v| {
            break :blk .{ .lt = try parseNumericValue(v) };
        } else if (jm.lte) |v| {
            break :blk .{ .lte = try parseNumericValue(v) };
        } else {
            return error.MissingMatch;
        }
    };

    return .{
        .negate = jm.negate,
        .case_insensitive = jm.case_insensitive,
        .field = field,
        .match = match,
    };
}

fn parseTraceFieldName(name: []const u8) !TraceField {
    return parseEnumAlias(TraceField, &.{
        .{ "name", .TRACE_FIELD_NAME },
        .{ "TRACE_FIELD_NAME", .TRACE_FIELD_NAME },
        .{ "trace_id", .TRACE_FIELD_TRACE_ID },
        .{ "TRACE_FIELD_TRACE_ID", .TRACE_FIELD_TRACE_ID },
        .{ "span_id", .TRACE_FIELD_SPAN_ID },
        .{ "TRACE_FIELD_SPAN_ID", .TRACE_FIELD_SPAN_ID },
        .{ "parent_span_id", .TRACE_FIELD_PARENT_SPAN_ID },
        .{ "TRACE_FIELD_PARENT_SPAN_ID", .TRACE_FIELD_PARENT_SPAN_ID },
        .{ "trace_state", .TRACE_FIELD_TRACE_STATE },
        .{ "TRACE_FIELD_TRACE_STATE", .TRACE_FIELD_TRACE_STATE },
        .{ "resource_schema_url", .TRACE_FIELD_RESOURCE_SCHEMA_URL },
        .{ "TRACE_FIELD_RESOURCE_SCHEMA_URL", .TRACE_FIELD_RESOURCE_SCHEMA_URL },
        .{ "scope_schema_url", .TRACE_FIELD_SCOPE_SCHEMA_URL },
        .{ "TRACE_FIELD_SCOPE_SCHEMA_URL", .TRACE_FIELD_SCOPE_SCHEMA_URL },
        .{ "scope_name", .TRACE_FIELD_SCOPE_NAME },
        .{ "TRACE_FIELD_SCOPE_NAME", .TRACE_FIELD_SCOPE_NAME },
        .{ "scope_version", .TRACE_FIELD_SCOPE_VERSION },
        .{ "TRACE_FIELD_SCOPE_VERSION", .TRACE_FIELD_SCOPE_VERSION },
    }, error.InvalidTraceField, name);
}

fn parseSpanKind(name: []const u8) !SpanKind {
    return parseEnumAlias(SpanKind, &.{
        .{ "SPAN_KIND_UNSPECIFIED", .SPAN_KIND_UNSPECIFIED },
        .{ "SPAN_KIND_INTERNAL", .SPAN_KIND_INTERNAL },
        .{ "SPAN_KIND_SERVER", .SPAN_KIND_SERVER },
        .{ "SPAN_KIND_CLIENT", .SPAN_KIND_CLIENT },
        .{ "SPAN_KIND_PRODUCER", .SPAN_KIND_PRODUCER },
        .{ "SPAN_KIND_CONSUMER", .SPAN_KIND_CONSUMER },
    }, error.InvalidSpanKind, name);
}

fn parseSpanStatusCode(name: []const u8) !SpanStatusCode {
    return parseEnumAlias(SpanStatusCode, &.{
        .{ "unset", .SPAN_STATUS_CODE_UNSPECIFIED },
        .{ "SPAN_STATUS_CODE_UNSET", .SPAN_STATUS_CODE_UNSPECIFIED },
        .{ "SPAN_STATUS_CODE_UNSPECIFIED", .SPAN_STATUS_CODE_UNSPECIFIED },
        .{ "ok", .SPAN_STATUS_CODE_OK },
        .{ "SPAN_STATUS_CODE_OK", .SPAN_STATUS_CODE_OK },
        .{ "error", .SPAN_STATUS_CODE_ERROR },
        .{ "SPAN_STATUS_CODE_ERROR", .SPAN_STATUS_CODE_ERROR },
    }, error.InvalidSpanStatusCode, name);
}

fn parseSamplingMode(name: []const u8) !SamplingMode {
    return parseEnumAlias(SamplingMode, &.{
        .{ "SAMPLING_MODE_UNSPECIFIED", .SAMPLING_MODE_UNSPECIFIED },
        .{ "SAMPLING_MODE_HASH_SEED", .SAMPLING_MODE_HASH_SEED },
        .{ "SAMPLING_MODE_PROPORTIONAL", .SAMPLING_MODE_PROPORTIONAL },
        .{ "SAMPLING_MODE_EQUALIZING", .SAMPLING_MODE_EQUALIZING },
    }, error.InvalidSamplingMode, name);
}

fn parseTraceSamplingConfig(jk: TraceSamplingConfigJson) !TraceSamplingConfig {
    var config: TraceSamplingConfig = .{
        .percentage = jk.percentage,
    };

    if (jk.mode) |mode_name| {
        config.mode = try parseSamplingMode(mode_name);
    }

    config.sampling_precision = jk.sampling_precision;
    config.hash_seed = jk.hash_seed;
    config.fail_closed = jk.fail_closed;

    return config;
}

// =============================================================================
// Keep Value Parsing
// =============================================================================

/// Parse keep value - validates format
/// Valid formats: "all", "none", "N%", "N/s", "N/m", "N/Ds", "N/Dm"
pub fn parseKeepValue(s: []const u8) !void {
    if (s.len == 0 or std.mem.eql(u8, s, "all") or std.mem.eql(u8, s, "none")) {
        return;
    }
    // Check for percentage: "N%"
    if (s.len >= 2 and s[s.len - 1] == '%') {
        const num_str = s[0 .. s.len - 1];
        const pct = std.fmt.parseInt(u8, num_str, 10) catch return error.InvalidKeepValue;
        if (pct > 100) return error.InvalidKeepValue;
        return;
    }
    // Check for rate limit: "N/s", "N/m", "N/Ds", "N/Dm"
    if (std.mem.findScalar(u8, s, '/')) |slash_pos| {
        if (slash_pos == 0) return error.InvalidKeepValue;
        _ = std.fmt.parseInt(u32, s[0..slash_pos], 10) catch return error.InvalidKeepValue;
        const after_slash = s[slash_pos + 1 ..];
        if (after_slash.len == 0) return error.InvalidKeepValue;
        const unit = after_slash[after_slash.len - 1];
        if (unit != 's' and unit != 'm') return error.InvalidKeepValue;
        if (after_slash.len > 1) {
            const dur = std.fmt.parseInt(
                u32,
                after_slash[0 .. after_slash.len - 1],
                10,
            ) catch return error.InvalidKeepValue;
            if (dur == 0) return error.InvalidKeepValue;
        }
        return;
    }
    return error.InvalidKeepValue;
}

// =============================================================================
// Tests
// =============================================================================

test "parseKeepValue" {
    try parseKeepValue("all");
    try parseKeepValue("none");
    try parseKeepValue("");
    try parseKeepValue("50%");
    try parseKeepValue("0%");
    try parseKeepValue("100%");
    try parseKeepValue("100/s");
    try parseKeepValue("1000/m");
    // Arbitrary duration windows
    try parseKeepValue("1/5s");
    try parseKeepValue("1/300s");
    try parseKeepValue("10/5m");

    try std.testing.expectError(error.InvalidKeepValue, parseKeepValue("101%"));
    try std.testing.expectError(error.InvalidKeepValue, parseKeepValue("invalid"));
    try std.testing.expectError(error.InvalidKeepValue, parseKeepValue("100/x"));
    try std.testing.expectError(error.InvalidKeepValue, parseKeepValue("1/0s"));
    try std.testing.expectError(error.InvalidKeepValue, parseKeepValue("/s"));
    try std.testing.expectError(error.InvalidKeepValue, parseKeepValue("1/abcs"));
}

test "parsePoliciesBytes: log policy with new format" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "drop-health-checks",
        \\      "name": "Drop health check logs",
        \\      "log": {
        \\        "match": [
        \\          { "log_field": "body", "regex": "GET /health" }
        \\        ],
        \\        "keep": "none"
        \\      }
        \\    }
        \\  ]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);
    try std.testing.expectEqualStrings("drop-health-checks", policies[0].id);
    try std.testing.expectEqualStrings("Drop health check logs", policies[0].name);
    try std.testing.expect(policies[0].enabled);

    // Verify it's a log target
    try std.testing.expect(policies[0].target != null);
    try std.testing.expect(policies[0].target.? == .log);

    const log_target = policies[0].target.?.log;
    try std.testing.expectEqualStrings("none", log_target.keep);
    try std.testing.expectEqual(@as(usize, 1), log_target.match.items.len);

    const matcher = log_target.match.items[0];
    try std.testing.expect(matcher.field != null);
    try std.testing.expect(matcher.field.? == .log_field);
    try std.testing.expectEqual(LogField.LOG_FIELD_BODY, matcher.field.?.log_field);
    try std.testing.expect(matcher.match != null);
    try std.testing.expect(matcher.match.? == .regex);
    try std.testing.expectEqualStrings("GET /health", matcher.match.?.regex);
}

test "parsePoliciesBytes: metric policy with new format" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "drop-debug-metrics",
        \\      "name": "Drop debug metrics",
        \\      "metric": {
        \\        "match": [
        \\          { "metric_field": "name", "regex": "^debug\\." }
        \\        ],
        \\        "keep": false
        \\      }
        \\    }
        \\  ]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);
    try std.testing.expectEqualStrings("drop-debug-metrics", policies[0].id);
    try std.testing.expectEqualStrings("Drop debug metrics", policies[0].name);
    try std.testing.expect(policies[0].enabled);

    // Verify it's a metric target
    try std.testing.expect(policies[0].target != null);
    try std.testing.expect(policies[0].target.? == .metric);

    const metric_target = policies[0].target.?.metric;
    try std.testing.expectEqual(false, metric_target.keep);
    try std.testing.expectEqual(@as(usize, 1), metric_target.match.items.len);

    const matcher = metric_target.match.items[0];
    try std.testing.expect(matcher.field != null);
    try std.testing.expect(matcher.field.? == .metric_field);
    try std.testing.expectEqual(MetricField.METRIC_FIELD_NAME, matcher.field.?.metric_field);
    try std.testing.expect(matcher.match != null);
    try std.testing.expect(matcher.match.? == .regex);
    try std.testing.expectEqualStrings("^debug\\.", matcher.match.?.regex);
}

test "parsePoliciesBytes: log policy with attribute matcher" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "drop-dev-logs",
        \\      "name": "Drop development logs",
        \\      "log": {
        \\        "match": [
        \\          { "log_attribute": "environment", "exact": "development" }
        \\        ],
        \\        "keep": "none"
        \\      }
        \\    }
        \\  ]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);

    const log_target = policies[0].target.?.log;
    const matcher = log_target.match.items[0];
    try std.testing.expect(matcher.field.? == .log_attribute);
    try std.testing.expectEqualStrings("environment", matcher.field.?.log_attribute.path.items[0]);
    try std.testing.expect(matcher.match.? == .exact);
    try std.testing.expectEqualStrings("development", matcher.match.?.exact);
}

test "parsePoliciesBytes: metric policy with datapoint attribute" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "drop-dev-metrics",
        \\      "name": "Drop development metrics",
        \\      "metric": {
        \\        "match": [
        \\          { "datapoint_attribute": "env", "regex": "dev" }
        \\        ],
        \\        "keep": false
        \\      }
        \\    }
        \\  ]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);

    const metric_target = policies[0].target.?.metric;
    const matcher = metric_target.match.items[0];
    try std.testing.expect(matcher.field.? == .datapoint_attribute);
    try std.testing.expectEqualStrings("env", matcher.field.?.datapoint_attribute.path.items[0]);
    try std.testing.expect(matcher.match.? == .regex);
    try std.testing.expectEqualStrings("dev", matcher.match.?.regex);
}

test "parsePoliciesBytes: log policy with transform" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "redact-sensitive",
        \\      "name": "Redact sensitive data",
        \\      "log": {
        \\        "match": [
        \\          { "log_field": "body", "regex": "password" }
        \\        ],
        \\        "keep": "all",
        \\        "transform": {
        \\          "redact": [
        \\            { "log_attribute": "password", "replacement": "***" }
        \\          ],
        \\          "remove": [
        \\            { "log_attribute": "secret_key" }
        \\          ]
        \\        }
        \\      }
        \\    }
        \\  ]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);

    const log_target = policies[0].target.?.log;
    try std.testing.expectEqualStrings("all", log_target.keep);
    try std.testing.expect(log_target.transform != null);

    const transform = log_target.transform.?;
    try std.testing.expectEqual(@as(usize, 1), transform.redact.items.len);
    try std.testing.expectEqual(@as(usize, 1), transform.remove.items.len);

    // Check redact
    const redact = transform.redact.items[0];
    try std.testing.expect(redact.field.? == .log_attribute);
    try std.testing.expectEqualStrings("password", redact.field.?.log_attribute.path.items[0]);
    try std.testing.expectEqualStrings("***", redact.replacement);
    try std.testing.expect(redact.regex == null);

    // Check remove
    const remove = transform.remove.items[0];
    try std.testing.expect(remove.field.? == .log_attribute);
    try std.testing.expectEqualStrings("secret_key", remove.field.?.log_attribute.path.items[0]);
}

test "parsePoliciesBytes: log policy with redact regex (v1.4.0 targeted redaction)" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "redact-password-query-param",
        \\      "name": "Redact password query parameter in log body",
        \\      "log": {
        \\        "match": [
        \\          { "log_field": "body", "regex": "password=" }
        \\        ],
        \\        "transform": {
        \\          "redact": [
        \\            {
        \\              "log_field": "body",
        \\              "regex": "([?&]password=)[^&\\s]+(&session_id=)",
        \\              "replacement": "$1[REDACTED]$2"
        \\            }
        \\          ]
        \\        }
        \\      }
        \\    }
        \\  ]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);

    const log_target = policies[0].target.?.log;
    const transform = log_target.transform.?;
    const redact = transform.redact.items[0];
    try std.testing.expect(redact.field.? == .log_field);
    try std.testing.expectEqualStrings("$1[REDACTED]$2", redact.replacement);
    try std.testing.expect(redact.regex != null);
    try std.testing.expectEqualStrings("([?&]password=)[^&\\s]+(&session_id=)", redact.regex.?);
}

test "parsePoliciesBytes: mixed log and metric policies" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "log-policy",
        \\      "name": "Log Policy",
        \\      "log": {
        \\        "match": [
        \\          { "log_field": "body", "regex": "error" }
        \\        ],
        \\        "keep": "none"
        \\      }
        \\    },
        \\    {
        \\      "id": "metric-policy",
        \\      "name": "Metric Policy",
        \\      "metric": {
        \\        "match": [
        \\          { "metric_field": "name", "regex": "test_.*" }
        \\        ],
        \\        "keep": true
        \\      }
        \\    }
        \\  ]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 2), policies.len);

    // First policy should be log
    try std.testing.expectEqualStrings("log-policy", policies[0].id);
    try std.testing.expect(policies[0].target != null);
    try std.testing.expect(policies[0].target.? == .log);

    // Second policy should be metric
    try std.testing.expectEqualStrings("metric-policy", policies[1].id);
    try std.testing.expect(policies[1].target != null);
    try std.testing.expect(policies[1].target.? == .metric);
}

test "parsePoliciesBytes: negated matcher" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "keep-non-debug",
        \\      "name": "Keep non-debug logs",
        \\      "log": {
        \\        "match": [
        \\          { "log_field": "severity_text", "regex": "DEBUG", "negate": true }
        \\        ],
        \\        "keep": "all"
        \\      }
        \\    }
        \\  ]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);

    const log_target = policies[0].target.?.log;
    const matcher = log_target.match.items[0];
    try std.testing.expect(matcher.negate);
    try std.testing.expect(matcher.field.? == .log_field);
    try std.testing.expectEqual(LogField.LOG_FIELD_SEVERITY_TEXT, matcher.field.?.log_field);
}

test "parsePoliciesBytes: exists matcher" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "require-trace",
        \\      "name": "Require trace ID",
        \\      "log": {
        \\        "match": [
        \\          { "log_attribute": "trace_id", "exists": true }
        \\        ],
        \\        "keep": "all"
        \\      }
        \\    }
        \\  ]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);

    const log_target = policies[0].target.?.log;
    const matcher = log_target.match.items[0];
    try std.testing.expect(matcher.field.? == .log_attribute);
    try std.testing.expectEqualStrings("trace_id", matcher.field.?.log_attribute.path.items[0]);
    try std.testing.expect(matcher.match.? == .exists);
    try std.testing.expectEqual(true, matcher.match.?.exists);
}

test "parsePoliciesBytes: disabled policy" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "disabled-policy",
        \\      "name": "Disabled Policy",
        \\      "enabled": false,
        \\      "log": {
        \\        "match": [
        \\          { "log_field": "body", "regex": "test" }
        \\        ],
        \\        "keep": "none"
        \\      }
        \\    }
        \\  ]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);
    try std.testing.expect(!policies[0].enabled);
}

test "parsePoliciesBytes: trace policy with span name matcher" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "sample-ping-spans",
        \\      "name": "Sample ping spans at 50%",
        \\      "trace": {
        \\        "match": [
        \\          { "trace_field": "TRACE_FIELD_NAME", "regex": "^ping$" }
        \\        ],
        \\        "keep": {
        \\          "percentage": 50.0,
        \\          "mode": "SAMPLING_MODE_HASH_SEED",
        \\          "sampling_precision": 4
        \\        }
        \\      }
        \\    }
        \\  ]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);
    try std.testing.expectEqualStrings("sample-ping-spans", policies[0].id);

    // Verify it's a trace target
    try std.testing.expect(policies[0].target != null);
    try std.testing.expect(policies[0].target.? == .trace);

    const trace_target = policies[0].target.?.trace;
    try std.testing.expectEqual(@as(usize, 1), trace_target.match.items.len);

    // Check matcher
    const matcher = trace_target.match.items[0];
    try std.testing.expect(matcher.field != null);
    try std.testing.expect(matcher.field.? == .trace_field);
    try std.testing.expectEqual(TraceField.TRACE_FIELD_NAME, matcher.field.?.trace_field);
    try std.testing.expect(matcher.match != null);
    try std.testing.expect(matcher.match.? == .regex);
    try std.testing.expectEqualStrings("^ping$", matcher.match.?.regex);

    // Check sampling config
    try std.testing.expect(trace_target.keep != null);
    const sampling = trace_target.keep.?;
    try std.testing.expectEqual(@as(f32, 50.0), sampling.percentage);
    try std.testing.expect(sampling.mode != null);
    try std.testing.expectEqual(SamplingMode.SAMPLING_MODE_HASH_SEED, sampling.mode.?);
    try std.testing.expect(sampling.sampling_precision != null);
    try std.testing.expectEqual(@as(u32, 4), sampling.sampling_precision.?);
}

test "parsePoliciesBytes: trace policy with span kind matcher" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "sample-internal-spans",
        \\      "name": "Sample internal spans",
        \\      "trace": {
        \\        "match": [
        \\          { "span_kind": "SPAN_KIND_INTERNAL", "exists": true }
        \\        ],
        \\        "keep": {
        \\          "percentage": 75.0,
        \\          "mode": "SAMPLING_MODE_EQUALIZING"
        \\        }
        \\      }
        \\    }
        \\  ]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);

    const trace_target = policies[0].target.?.trace;
    const matcher = trace_target.match.items[0];
    try std.testing.expect(matcher.field.? == .span_kind);
    try std.testing.expectEqual(SpanKind.SPAN_KIND_INTERNAL, matcher.field.?.span_kind);
    try std.testing.expect(matcher.match.? == .exists);
    try std.testing.expectEqual(true, matcher.match.?.exists);

    const sampling = trace_target.keep.?;
    try std.testing.expectEqual(@as(f32, 75.0), sampling.percentage);
    try std.testing.expectEqual(SamplingMode.SAMPLING_MODE_EQUALIZING, sampling.mode.?);
}

test "parsePoliciesBytes: trace policy with span attribute" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "sample-peer-service",
        \\      "name": "Sample spans with peer.service",
        \\      "trace": {
        \\        "match": [
        \\          { "span_attribute": "peer.service", "exists": true }
        \\        ],
        \\        "keep": {
        \\          "percentage": 10.0,
        \\          "hash_seed": 12345
        \\        }
        \\      }
        \\    }
        \\  ]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);

    const trace_target = policies[0].target.?.trace;
    const matcher = trace_target.match.items[0];
    try std.testing.expect(matcher.field.? == .span_attribute);
    try std.testing.expectEqualStrings("peer.service", matcher.field.?.span_attribute.path.items[0]);

    const sampling = trace_target.keep.?;
    try std.testing.expectEqual(@as(f32, 10.0), sampling.percentage);
    try std.testing.expect(sampling.hash_seed != null);
    try std.testing.expectEqual(@as(u32, 12345), sampling.hash_seed.?);
}

test "parsePoliciesBytes: trace policy with resource attribute and exact match" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "sample-test-service",
        \\      "name": "Sample test-service spans",
        \\      "trace": {
        \\        "match": [
        \\          { "resource_attribute": "service.name", "exact": "test-service" }
        \\        ],
        \\        "keep": {
        \\          "percentage": 25.0,
        \\          "mode": "SAMPLING_MODE_PROPORTIONAL",
        \\          "sampling_precision": 6
        \\        }
        \\      }
        \\    }
        \\  ]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);

    const trace_target = policies[0].target.?.trace;
    const matcher = trace_target.match.items[0];
    try std.testing.expect(matcher.field.? == .resource_attribute);
    try std.testing.expectEqualStrings("service.name", matcher.field.?.resource_attribute.path.items[0]);
    try std.testing.expect(matcher.match.? == .exact);
    try std.testing.expectEqualStrings("test-service", matcher.match.?.exact);

    const sampling = trace_target.keep.?;
    try std.testing.expectEqual(@as(f32, 25.0), sampling.percentage);
    try std.testing.expectEqual(SamplingMode.SAMPLING_MODE_PROPORTIONAL, sampling.mode.?);
    try std.testing.expectEqual(@as(u32, 6), sampling.sampling_precision.?);
}

test "parsePoliciesBytes: trace policy with span status matcher" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "keep-error-spans",
        \\      "name": "Keep all error spans",
        \\      "trace": {
        \\        "match": [
        \\          { "span_status": "SPAN_STATUS_CODE_ERROR", "exists": true }
        \\        ],
        \\        "keep": {
        \\          "percentage": 100.0
        \\        }
        \\      }
        \\    }
        \\  ]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);

    const trace_target = policies[0].target.?.trace;
    const matcher = trace_target.match.items[0];
    try std.testing.expect(matcher.field.? == .span_status);
    try std.testing.expectEqual(SpanStatusCode.SPAN_STATUS_CODE_ERROR, matcher.field.?.span_status);

    const sampling = trace_target.keep.?;
    try std.testing.expectEqual(@as(f32, 100.0), sampling.percentage);
}

// =============================================================================
// Tests for AttributePath parsing formats
// =============================================================================

test "parseAttributePath: string shorthand" {
    const allocator = std.testing.allocator;

    // Parse JSON value representing a string
    const json_str =
        \\"service"
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
    defer parsed.deinit();

    var attr_path = try parseAttributePath(allocator, parsed.value);
    defer {
        for (attr_path.path.items) |segment| {
            allocator.free(segment);
        }
        attr_path.path.deinit(allocator);
    }

    try std.testing.expectEqual(@as(usize, 1), attr_path.path.items.len);
    try std.testing.expectEqualStrings("service", attr_path.path.items[0]);
}

test "parseAttributePath: array shorthand" {
    const allocator = std.testing.allocator;

    // Parse JSON value representing an array
    const json_str =
        \\["http", "method"]
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
    defer parsed.deinit();

    var attr_path = try parseAttributePath(allocator, parsed.value);
    defer {
        for (attr_path.path.items) |segment| {
            allocator.free(segment);
        }
        attr_path.path.deinit(allocator);
    }

    try std.testing.expectEqual(@as(usize, 2), attr_path.path.items.len);
    try std.testing.expectEqualStrings("http", attr_path.path.items[0]);
    try std.testing.expectEqualStrings("method", attr_path.path.items[1]);
}

test "parseAttributePath: canonical object format" {
    const allocator = std.testing.allocator;

    // Parse JSON value representing canonical format
    const json_str =
        \\{"path": ["request", "headers", "content-type"]}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
    defer parsed.deinit();

    var attr_path = try parseAttributePath(allocator, parsed.value);
    defer {
        for (attr_path.path.items) |segment| {
            allocator.free(segment);
        }
        attr_path.path.deinit(allocator);
    }

    try std.testing.expectEqual(@as(usize, 3), attr_path.path.items.len);
    try std.testing.expectEqualStrings("request", attr_path.path.items[0]);
    try std.testing.expectEqualStrings("headers", attr_path.path.items[1]);
    try std.testing.expectEqualStrings("content-type", attr_path.path.items[2]);
}

test "parseAttributePath: empty array returns error" {
    const allocator = std.testing.allocator;

    const json_str =
        \\[]
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
    defer parsed.deinit();

    const result = parseAttributePath(allocator, parsed.value);
    try std.testing.expectError(error.EmptyAttributePath, result);
}

test "parseAttributePath: invalid type returns error" {
    const allocator = std.testing.allocator;

    const json_str =
        \\123
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
    defer parsed.deinit();

    const result = parseAttributePath(allocator, parsed.value);
    try std.testing.expectError(error.InvalidAttributePath, result);
}

test "parseAttributePath: array with non-string element returns error" {
    const allocator = std.testing.allocator;

    const json_str =
        \\["http", 123, "method"]
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
    defer parsed.deinit();

    const result = parseAttributePath(allocator, parsed.value);
    try std.testing.expectError(error.InvalidAttributePath, result);
}

test "parsePoliciesBytes: log policy with array attribute path" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [{
        \\    "id": "drop-get-requests",
        \\    "name": "Drop GET requests",
        \\    "log": {
        \\      "match": [{
        \\        "log_attribute": ["http", "method"],
        \\        "regex": "GET"
        \\      }],
        \\      "keep": "none"
        \\    }
        \\  }]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);

    const log_target = policies[0].target.?.log;
    const matcher = log_target.match.items[0];

    // Verify the path has two segments
    const path = matcher.field.?.log_attribute.path.items;
    try std.testing.expectEqual(@as(usize, 2), path.len);
    try std.testing.expectEqualStrings("http", path[0]);
    try std.testing.expectEqualStrings("method", path[1]);
}

test "parsePoliciesBytes: log policy with canonical attribute path" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [{
        \\    "id": "drop-json-content",
        \\    "name": "Drop JSON content type",
        \\    "log": {
        \\      "match": [{
        \\        "log_attribute": {"path": ["request", "headers", "content-type"]},
        \\        "regex": "application/json"
        \\      }],
        \\      "keep": "none"
        \\    }
        \\  }]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);

    const log_target = policies[0].target.?.log;
    const matcher = log_target.match.items[0];

    // Verify the path has three segments
    const path = matcher.field.?.log_attribute.path.items;
    try std.testing.expectEqual(@as(usize, 3), path.len);
    try std.testing.expectEqualStrings("request", path[0]);
    try std.testing.expectEqualStrings("headers", path[1]);
    try std.testing.expectEqualStrings("content-type", path[2]);
}

test "parsePoliciesBytes: metric policy with nested datapoint attribute" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [{
        \\    "id": "filter-by-nested-tag",
        \\    "name": "Filter by nested tag",
        \\    "metric": {
        \\      "match": [{
        \\        "datapoint_attribute": ["tags", "env"],
        \\        "exact": "production"
        \\      }],
        \\      "keep": false
        \\    }
        \\  }]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);

    const metric_target = policies[0].target.?.metric;
    const matcher = metric_target.match.items[0];

    // Verify the path has two segments
    const path = matcher.field.?.datapoint_attribute.path.items;
    try std.testing.expectEqual(@as(usize, 2), path.len);
    try std.testing.expectEqualStrings("tags", path[0]);
    try std.testing.expectEqualStrings("env", path[1]);
}

test "parsePoliciesBytes: trace policy with nested span attribute" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [{
        \\    "id": "sample-by-http-status",
        \\    "name": "Sample by HTTP status",
        \\    "trace": {
        \\      "match": [{
        \\        "span_attribute": ["http", "response", "status_code"],
        \\        "regex": "5[0-9]{2}"
        \\      }],
        \\      "keep": {"percentage": 100.0}
        \\    }
        \\  }]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);

    const trace_target = policies[0].target.?.trace;
    const matcher = trace_target.match.items[0];

    // Verify the path has three segments
    const path = matcher.field.?.span_attribute.path.items;
    try std.testing.expectEqual(@as(usize, 3), path.len);
    try std.testing.expectEqualStrings("http", path[0]);
    try std.testing.expectEqualStrings("response", path[1]);
    try std.testing.expectEqualStrings("status_code", path[2]);
}

// =============================================================================
// Tests for optimized literal matchers and case_insensitive
// =============================================================================

test "parsePoliciesBytes: log policy with starts_with matcher" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [{
        \\    "id": "drop-error-logs",
        \\    "name": "Drop error logs",
        \\    "log": {
        \\      "match": [{
        \\        "log_field": "body",
        \\        "starts_with": "ERROR:"
        \\      }],
        \\      "keep": "none"
        \\    }
        \\  }]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);

    const log_target = policies[0].target.?.log;
    const matcher = log_target.match.items[0];

    try std.testing.expect(matcher.match.? == .starts_with);
    try std.testing.expectEqualStrings("ERROR:", matcher.match.?.starts_with);
    try std.testing.expect(!matcher.case_insensitive);
}

test "parsePoliciesBytes: log policy with ends_with matcher" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [{
        \\    "id": "drop-json-logs",
        \\    "name": "Drop JSON logs",
        \\    "log": {
        \\      "match": [{
        \\        "log_field": "body",
        \\        "ends_with": ".json"
        \\      }],
        \\      "keep": "none"
        \\    }
        \\  }]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);

    const log_target = policies[0].target.?.log;
    const matcher = log_target.match.items[0];

    try std.testing.expect(matcher.match.? == .ends_with);
    try std.testing.expectEqualStrings(".json", matcher.match.?.ends_with);
}

test "parsePoliciesBytes: log policy with contains matcher" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [{
        \\    "id": "drop-secret-logs",
        \\    "name": "Drop secret logs",
        \\    "log": {
        \\      "match": [{
        \\        "log_field": "body",
        \\        "contains": "password"
        \\      }],
        \\      "keep": "none"
        \\    }
        \\  }]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);

    const log_target = policies[0].target.?.log;
    const matcher = log_target.match.items[0];

    try std.testing.expect(matcher.match.? == .contains);
    try std.testing.expectEqualStrings("password", matcher.match.?.contains);
}

test "parsePoliciesBytes: log policy with case_insensitive flag" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [{
        \\    "id": "drop-error-logs-ci",
        \\    "name": "Drop error logs case insensitive",
        \\    "log": {
        \\      "match": [{
        \\        "log_field": "body",
        \\        "starts_with": "error",
        \\        "case_insensitive": true
        \\      }],
        \\      "keep": "none"
        \\    }
        \\  }]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);

    const log_target = policies[0].target.?.log;
    const matcher = log_target.match.items[0];

    try std.testing.expect(matcher.match.? == .starts_with);
    try std.testing.expectEqualStrings("error", matcher.match.?.starts_with);
    try std.testing.expect(matcher.case_insensitive);
}

test "parsePoliciesBytes: metric policy with contains and case_insensitive" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [{
        \\    "id": "filter-debug-metrics",
        \\    "name": "Filter debug metrics",
        \\    "metric": {
        \\      "match": [{
        \\        "metric_field": "name",
        \\        "contains": "debug",
        \\        "case_insensitive": true
        \\      }],
        \\      "keep": false
        \\    }
        \\  }]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);

    const metric_target = policies[0].target.?.metric;
    const matcher = metric_target.match.items[0];

    try std.testing.expect(matcher.match.? == .contains);
    try std.testing.expectEqualStrings("debug", matcher.match.?.contains);
    try std.testing.expect(matcher.case_insensitive);
}

// =============================================================================
// Tests for sample_key parsing
// =============================================================================

test "parsePoliciesBytes: log policy with sample_key log_field" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [{
        \\    "id": "sample-by-body",
        \\    "name": "Sample by body",
        \\    "log": {
        \\      "match": [{ "log_field": "body", "regex": ".*" }],
        \\      "keep": "50%",
        \\      "sample_key": { "log_field": "body" }
        \\    }
        \\  }]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| p.deinit(allocator);
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);

    const log_target = policies[0].target.?.log;
    try std.testing.expect(log_target.sample_key != null);

    const sample_key = log_target.sample_key.?;
    try std.testing.expect(sample_key.field != null);
    try std.testing.expect(sample_key.field.? == .log_field);
    try std.testing.expectEqual(LogField.LOG_FIELD_BODY, sample_key.field.?.log_field);
}

test "parsePoliciesBytes: log policy with sample_key log_attribute string" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [{
        \\    "id": "sample-by-trace",
        \\    "name": "Sample by trace_id",
        \\    "log": {
        \\      "match": [{ "log_field": "body", "regex": ".*" }],
        \\      "keep": "50%",
        \\      "sample_key": { "log_attribute": "trace_id" }
        \\    }
        \\  }]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| p.deinit(allocator);
        allocator.free(policies);
    }

    const log_target = policies[0].target.?.log;
    try std.testing.expect(log_target.sample_key != null);

    const sample_key = log_target.sample_key.?;
    try std.testing.expect(sample_key.field.? == .log_attribute);
    try std.testing.expectEqual(@as(usize, 1), sample_key.field.?.log_attribute.path.items.len);
    try std.testing.expectEqualStrings("trace_id", sample_key.field.?.log_attribute.path.items[0]);
}

test "parsePoliciesBytes: log policy with sample_key log_attribute array" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [{
        \\    "id": "sample-by-request-id",
        \\    "name": "Sample by request.id",
        \\    "log": {
        \\      "match": [{ "log_field": "body", "regex": ".*" }],
        \\      "keep": "50%",
        \\      "sample_key": { "log_attribute": ["request", "id"] }
        \\    }
        \\  }]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| p.deinit(allocator);
        allocator.free(policies);
    }

    const log_target = policies[0].target.?.log;
    const sample_key = log_target.sample_key.?;

    try std.testing.expect(sample_key.field.? == .log_attribute);
    try std.testing.expectEqual(@as(usize, 2), sample_key.field.?.log_attribute.path.items.len);
    try std.testing.expectEqualStrings("request", sample_key.field.?.log_attribute.path.items[0]);
    try std.testing.expectEqualStrings("id", sample_key.field.?.log_attribute.path.items[1]);
}

test "parsePoliciesBytes: log policy with sample_key resource_attribute" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [{
        \\    "id": "sample-by-host",
        \\    "name": "Sample by host",
        \\    "log": {
        \\      "match": [{ "log_field": "body", "regex": ".*" }],
        \\      "keep": "50%",
        \\      "sample_key": { "resource_attribute": "host.name" }
        \\    }
        \\  }]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| p.deinit(allocator);
        allocator.free(policies);
    }

    const log_target = policies[0].target.?.log;
    const sample_key = log_target.sample_key.?;

    try std.testing.expect(sample_key.field.? == .resource_attribute);
    try std.testing.expectEqualStrings("host.name", sample_key.field.?.resource_attribute.path.items[0]);
}

test "parsePoliciesBytes: log policy with sample_key scope_attribute" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [{
        \\    "id": "sample-by-scope",
        \\    "name": "Sample by scope name",
        \\    "log": {
        \\      "match": [{ "log_field": "body", "regex": ".*" }],
        \\      "keep": "50%",
        \\      "sample_key": { "scope_attribute": "name" }
        \\    }
        \\  }]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| p.deinit(allocator);
        allocator.free(policies);
    }

    const log_target = policies[0].target.?.log;
    const sample_key = log_target.sample_key.?;

    try std.testing.expect(sample_key.field.? == .scope_attribute);
    try std.testing.expectEqualStrings("name", sample_key.field.?.scope_attribute.path.items[0]);
}

test "parsePoliciesBytes: log policy without sample_key" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [{
        \\    "id": "no-sample-key",
        \\    "name": "No sample key",
        \\    "log": {
        \\      "match": [{ "log_field": "body", "regex": ".*" }],
        \\      "keep": "50%"
        \\    }
        \\  }]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| p.deinit(allocator);
        allocator.free(policies);
    }

    const log_target = policies[0].target.?.log;
    try std.testing.expect(log_target.sample_key == null);
}

// =============================================================================
// Tests for metric_type and aggregation_temporality
// =============================================================================

test "parsePoliciesBytes: metric policy with metric_type short form" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [{
        \\    "id": "drop-histograms",
        \\    "name": "Drop histogram metrics",
        \\    "metric": {
        \\      "match": [{
        \\        "metric_type": "histogram"
        \\      }],
        \\      "keep": false
        \\    }
        \\  }]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| p.deinit(allocator);
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);

    const metric_target = policies[0].target.?.metric;
    const matcher = metric_target.match.items[0];
    try std.testing.expect(matcher.field.? == .metric_type);
    try std.testing.expectEqual(MetricType.METRIC_TYPE_HISTOGRAM, matcher.field.?.metric_type);
    try std.testing.expect(matcher.match.? == .exists);
    try std.testing.expectEqual(true, matcher.match.?.exists);
}

test "parsePoliciesBytes: metric policy with metric_type canonical form" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [{
        \\    "id": "drop-gauges",
        \\    "name": "Drop gauge metrics",
        \\    "metric": {
        \\      "match": [{
        \\        "metric_type": "METRIC_TYPE_GAUGE",
        \\        "exists": true
        \\      }],
        \\      "keep": false
        \\    }
        \\  }]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| p.deinit(allocator);
        allocator.free(policies);
    }

    const metric_target = policies[0].target.?.metric;
    const matcher = metric_target.match.items[0];
    try std.testing.expect(matcher.field.? == .metric_type);
    try std.testing.expectEqual(MetricType.METRIC_TYPE_GAUGE, matcher.field.?.metric_type);
}

test "parsePoliciesBytes: metric policy with aggregation_temporality short form" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [{
        \\    "id": "drop-delta-metrics",
        \\    "name": "Drop delta metrics",
        \\    "metric": {
        \\      "match": [{
        \\        "aggregation_temporality": "delta"
        \\      }],
        \\      "keep": false
        \\    }
        \\  }]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| p.deinit(allocator);
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);

    const metric_target = policies[0].target.?.metric;
    const matcher = metric_target.match.items[0];
    try std.testing.expect(matcher.field.? == .aggregation_temporality);
    try std.testing.expectEqual(
        AggregationTemporality.AGGREGATION_TEMPORALITY_DELTA,
        matcher.field.?.aggregation_temporality,
    );
    try std.testing.expect(matcher.match.? == .exists);
    try std.testing.expectEqual(true, matcher.match.?.exists);
}

test "parsePoliciesBytes: metric policy with aggregation_temporality canonical form" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [{
        \\    "id": "drop-cumulative-metrics",
        \\    "name": "Drop cumulative metrics",
        \\    "metric": {
        \\      "match": [{
        \\        "aggregation_temporality": "AGGREGATION_TEMPORALITY_CUMULATIVE",
        \\        "exists": true
        \\      }],
        \\      "keep": false
        \\    }
        \\  }]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| p.deinit(allocator);
        allocator.free(policies);
    }

    const metric_target = policies[0].target.?.metric;
    const matcher = metric_target.match.items[0];
    try std.testing.expect(matcher.field.? == .aggregation_temporality);
    try std.testing.expectEqual(
        AggregationTemporality.AGGREGATION_TEMPORALITY_CUMULATIVE,
        matcher.field.?.aggregation_temporality,
    );
}

test "parsePoliciesBytes: trace policy with SPAN_STATUS_CODE_UNSET" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [{
        \\    "id": "match-unset-spans",
        \\    "name": "Match spans with unset status",
        \\    "trace": {
        \\      "match": [
        \\        { "span_status": "SPAN_STATUS_CODE_UNSET", "exists": true }
        \\      ]
        \\    }
        \\  }]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| p.deinit(allocator);
        allocator.free(policies);
    }

    const matcher = policies[0].target.?.trace.match.items[0];
    try std.testing.expect(matcher.field.? == .span_status);
    try std.testing.expectEqual(SpanStatusCode.SPAN_STATUS_CODE_UNSPECIFIED, matcher.field.?.span_status);
}

test "parsePoliciesBytes: trace policy with shortname trace fields" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [{
        \\    "id": "drop-by-scope",
        \\    "name": "Drop spans from specific scope",
        \\    "trace": {
        \\      "match": [
        \\        { "trace_field": "scope_name", "exact": "my-library" }
        \\      ]
        \\    }
        \\  }]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| p.deinit(allocator);
        allocator.free(policies);
    }

    const matcher = policies[0].target.?.trace.match.items[0];
    try std.testing.expect(matcher.field.? == .trace_field);
    try std.testing.expectEqual(TraceField.TRACE_FIELD_SCOPE_NAME, matcher.field.?.trace_field);
}

test "parsePoliciesBytes: trace policy with shortname resource_schema_url" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [{
        \\    "id": "drop-old-schema",
        \\    "name": "Drop traces from old schema",
        \\    "trace": {
        \\      "match": [
        \\        { "trace_field": "resource_schema_url", "exact": "https://old.schema/v1" }
        \\      ]
        \\    }
        \\  }]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| p.deinit(allocator);
        allocator.free(policies);
    }

    const matcher = policies[0].target.?.trace.match.items[0];
    try std.testing.expect(matcher.field.? == .trace_field);
    try std.testing.expectEqual(TraceField.TRACE_FIELD_RESOURCE_SCHEMA_URL, matcher.field.?.trace_field);
}

// =============================================================================
// v1.5.0: Typed matcher parsing tests
// =============================================================================

test "parseValue: bool shorthand" {
    const allocator = std.testing.allocator;
    const v = try parseValue(allocator, .{ .bool = true });
    try std.testing.expect(v.value != null);
    try std.testing.expect(v.value.? == .bool_value);
    try std.testing.expect(v.value.?.bool_value == true);
}

test "parseValue: int shorthand" {
    const allocator = std.testing.allocator;
    const v = try parseValue(allocator, .{ .integer = 200 });
    try std.testing.expect(v.value.? == .int_value);
    try std.testing.expectEqual(@as(i64, 200), v.value.?.int_value);
}

test "parseValue: float shorthand" {
    const allocator = std.testing.allocator;
    const v = try parseValue(allocator, .{ .float = 0.5 });
    try std.testing.expect(v.value.? == .double_value);
    try std.testing.expectEqual(@as(f64, 0.5), v.value.?.double_value);
}

test "parseValue: hex_value canonical" {
    const allocator = std.testing.allocator;
    var obj = std.json.ObjectMap.empty;
    defer obj.deinit(allocator);
    try obj.put(allocator, "hex_value", .{ .string = "deadbeef" });
    const v = try parseValue(allocator, .{ .object = obj });
    defer allocator.free(v.value.?.bytes_value);
    try std.testing.expect(v.value.? == .bytes_value);
    try std.testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, v.value.?.bytes_value);
}

test "parseValue: string shorthand (v1.6.0)" {
    const allocator = std.testing.allocator;
    const v = try parseValue(allocator, .{ .string = "foo" });
    defer allocator.free(v.value.?.string_value);
    try std.testing.expect(v.value.? == .string_value);
    try std.testing.expectEqualStrings("foo", v.value.?.string_value);
}

test "parseValue: string_value canonical (v1.6.0)" {
    const allocator = std.testing.allocator;
    var obj = std.json.ObjectMap.empty;
    defer obj.deinit(allocator);
    try obj.put(allocator, "string_value", .{ .string = "checkout-api" });
    const v = try parseValue(allocator, .{ .object = obj });
    defer allocator.free(v.value.?.string_value);
    try std.testing.expect(v.value.? == .string_value);
    try std.testing.expectEqualStrings("checkout-api", v.value.?.string_value);
}

test "parseValue: string_value with non-string JSON type returns InvalidValue" {
    const allocator = std.testing.allocator;
    var obj = std.json.ObjectMap.empty;
    defer obj.deinit(allocator);
    try obj.put(allocator, "string_value", .{ .integer = 123 });
    try std.testing.expectError(error.InvalidValue, parseValue(allocator, .{ .object = obj }));
}

test "parseValue: bool_value with non-bool JSON type returns InvalidValue" {
    const allocator = std.testing.allocator;
    var obj = std.json.ObjectMap.empty;
    defer obj.deinit(allocator);
    try obj.put(allocator, "bool_value", .{ .string = "true" });
    try std.testing.expectError(error.InvalidValue, parseValue(allocator, .{ .object = obj }));
}

test "parseValue: int_value with non-integer JSON type returns InvalidValue" {
    const allocator = std.testing.allocator;
    var obj = std.json.ObjectMap.empty;
    defer obj.deinit(allocator);
    try obj.put(allocator, "int_value", .{ .string = "200" });
    try std.testing.expectError(error.InvalidValue, parseValue(allocator, .{ .object = obj }));
}

test "parseValue: double_value with non-float JSON type returns InvalidValue" {
    const allocator = std.testing.allocator;
    var obj = std.json.ObjectMap.empty;
    defer obj.deinit(allocator);
    try obj.put(allocator, "double_value", .{ .integer = 5 });
    try std.testing.expectError(error.InvalidValue, parseValue(allocator, .{ .object = obj }));
}

test "parseValue: hex_value with non-string JSON type returns InvalidValue" {
    const allocator = std.testing.allocator;
    var obj = std.json.ObjectMap.empty;
    defer obj.deinit(allocator);
    try obj.put(allocator, "hex_value", .{ .integer = 5 });
    try std.testing.expectError(error.InvalidValue, parseValue(allocator, .{ .object = obj }));
}

test "parseValue: bytes_value with non-string JSON type returns InvalidValue" {
    const allocator = std.testing.allocator;
    var obj = std.json.ObjectMap.empty;
    defer obj.deinit(allocator);
    try obj.put(allocator, "bytes_value", .{ .bool = true });
    try std.testing.expectError(error.InvalidValue, parseValue(allocator, .{ .object = obj }));
}

test "parseNumericValue: int" {
    const v = try parseNumericValue(.{ .integer = 500 });
    try std.testing.expect(v.value.? == .int_value);
    try std.testing.expectEqual(@as(i64, 500), v.value.?.int_value);
}

test "parseNumericValue: float" {
    const v = try parseNumericValue(.{ .float = 0.1 });
    try std.testing.expect(v.value.? == .double_value);
    try std.testing.expectEqual(@as(f64, 0.1), v.value.?.double_value);
}

test "parseNumericValue: bool rejected" {
    try std.testing.expectError(error.InvalidNumericValue, parseNumericValue(.{ .bool = true }));
}

test "hexDecode: valid" {
    const allocator = std.testing.allocator;
    const bytes = try hexDecode(allocator, "4bf92f35");
    defer allocator.free(bytes);
    try std.testing.expectEqualSlices(u8, &.{ 0x4b, 0xf9, 0x2f, 0x35 }, bytes);
}

test "hexDecode: odd length rejected" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidHexValue, hexDecode(allocator, "abc"));
}

test "hexDecode: invalid char rejected" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidHexValue, hexDecode(allocator, "zz"));
}

test "parsePoliciesBytes: log policy with equals bool" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [{
        \\    "id": "drop-cache-hits",
        \\    "name": "Drop cache hit logs",
        \\    "log": {
        \\      "match": [
        \\        { "log_attribute": "cache.hit", "equals": true }
        \\      ],
        \\      "keep": "none"
        \\    }
        \\  }]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| p.deinit(allocator);
        allocator.free(policies);
    }

    const matcher = policies[0].target.?.log.match.items[0];
    try std.testing.expect(matcher.match.? == .equals);
    try std.testing.expect(matcher.match.?.equals.value.? == .bool_value);
    try std.testing.expect(matcher.match.?.equals.value.?.bool_value == true);
}

test "parsePoliciesBytes: log policy with equals string (v1.6.0)" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [{
        \\    "id": "drop-checkout",
        \\    "name": "Drop checkout logs",
        \\    "log": {
        \\      "match": [
        \\        { "resource_attribute": ["service.name"], "equals": "checkout-api" }
        \\      ],
        \\      "keep": "none"
        \\    }
        \\  }]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| p.deinit(allocator);
        allocator.free(policies);
    }

    const matcher = policies[0].target.?.log.match.items[0];
    try std.testing.expect(matcher.match.? == .equals);
    try std.testing.expect(matcher.match.?.equals.value.? == .string_value);
    try std.testing.expectEqualStrings("checkout-api", matcher.match.?.equals.value.?.string_value);
}

test "parsePoliciesBytes: log policy with gte int" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [{
        \\    "id": "drop-success",
        \\    "name": "Drop successful HTTP logs",
        \\    "log": {
        \\      "match": [
        \\        { "log_attribute": ["http.response.status_code"], "gte": 200 },
        \\        { "log_attribute": ["http.response.status_code"], "lt": 400 }
        \\      ],
        \\      "keep": "none"
        \\    }
        \\  }]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| p.deinit(allocator);
        allocator.free(policies);
    }

    const matchers = policies[0].target.?.log.match.items;
    try std.testing.expectEqual(@as(usize, 2), matchers.len);

    try std.testing.expect(matchers[0].match.? == .gte);
    try std.testing.expect(matchers[0].match.?.gte.value.? == .int_value);
    try std.testing.expectEqual(@as(i64, 200), matchers[0].match.?.gte.value.?.int_value);

    try std.testing.expect(matchers[1].match.? == .lt);
    try std.testing.expect(matchers[1].match.?.lt.value.? == .int_value);
    try std.testing.expectEqual(@as(i64, 400), matchers[1].match.?.lt.value.?.int_value);
}

test "parsePoliciesBytes: log policy with equals float" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [{
        \\    "id": "drop-low-ratio",
        \\    "name": "Drop low sampling ratio",
        \\    "log": {
        \\      "match": [
        \\        { "log_attribute": "sampling.ratio", "lt": 0.5 }
        \\      ],
        \\      "keep": "none"
        \\    }
        \\  }]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| p.deinit(allocator);
        allocator.free(policies);
    }

    const matcher = policies[0].target.?.log.match.items[0];
    try std.testing.expect(matcher.match.? == .lt);
    try std.testing.expect(matcher.match.?.lt.value.? == .double_value);
    try std.testing.expectEqual(@as(f64, 0.5), matcher.match.?.lt.value.?.double_value);
}

test "parsePoliciesBytes: trace policy with equals hex (bytes identifier)" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [{
        \\    "id": "keep-trace",
        \\    "name": "Keep all spans for a trace",
        \\    "trace": {
        \\      "match": [
        \\        {
        \\          "trace_field": "TRACE_FIELD_TRACE_ID",
        \\          "equals": { "hex_value": "4bf92f3577b34da6a3ce929d0e0e4736" }
        \\        }
        \\      ]
        \\    }
        \\  }]
        \\}
        \\
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| p.deinit(allocator);
        allocator.free(policies);
    }

    const matcher = policies[0].target.?.trace.match.items[0];
    try std.testing.expect(matcher.field.? == .trace_field);
    try std.testing.expectEqual(TraceField.TRACE_FIELD_TRACE_ID, matcher.field.?.trace_field);
    try std.testing.expect(matcher.match.? == .equals);
    try std.testing.expect(matcher.match.?.equals.value.? == .bytes_value);
    try std.testing.expectEqual(@as(usize, 16), matcher.match.?.equals.value.?.bytes_value.len);
}

test "parsePoliciesBytes: metric policy with gt" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [{
        \\    "id": "drop-small-metrics",
        \\    "name": "Drop small datapoint values",
        \\    "metric": {
        \\      "match": [
        \\        { "datapoint_attribute": "value", "gt": 1000 }
        \\      ],
        \\      "keep": false
        \\    }
        \\  }]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| p.deinit(allocator);
        allocator.free(policies);
    }

    const matcher = policies[0].target.?.metric.match.items[0];
    try std.testing.expect(matcher.match.? == .gt);
    try std.testing.expect(matcher.match.?.gt.value.? == .int_value);
    try std.testing.expectEqual(@as(i64, 1000), matcher.match.?.gt.value.?.int_value);
}
