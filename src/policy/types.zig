const std = @import("std");
const proto = @import("proto");
const provider_http = @import("./provider_http.zig");
const provider_file = @import("./provider_file.zig");
const policy_provider = @import("./provider.zig");
const policy_source = @import("./source.zig");

pub const Header = provider_http.Header;
pub const PolicyStage = proto.policy.PolicyStage;

// =============================================================================
// TelemetryType - Distinguishes between log and metric telemetry
// =============================================================================

/// Type of telemetry being evaluated
pub const TelemetryType = enum {
    /// Log telemetry (OTLP logs, Datadog logs, etc.)
    log,
    /// Metric telemetry (Prometheus, OTLP metrics, etc.)
    metric,
    /// Trace telemetry (OTLP traces only - Datadog traces not supported)
    trace,
};

// =============================================================================
// Extensions (spec v1.6.0) — dispatch types
// =============================================================================

/// Which disjoint slice of the telemetry stream a record fell into, relative
/// to one policy: matched and kept, matched but removed by the final keep
/// outcome (which another policy may have caused), or unmatched. The proto
/// ExtensionMode values MATCHED and ALL are unions over these, resolved to an
/// ExtensionSliceSet at snapshot compile time.
pub const ExtensionSlice = enum(u2) { kept, dropped, unmatched };

pub const ExtensionSliceSet = std.EnumSet(ExtensionSlice);

/// Resolve a proto ExtensionMode to the slice set it selects. UNSPECIFIED
/// and unknown future modes resolve to MATCHED, the spec default.
pub fn extensionSliceSet(mode: proto.policy.ExtensionMode) ExtensionSliceSet {
    return switch (mode) {
        .EXTENSION_MODE_KEPT => .init(.{ .kept = true }),
        .EXTENSION_MODE_DROPPED => .init(.{ .dropped = true }),
        .EXTENSION_MODE_UNMATCHED => .init(.{ .unmatched = true }),
        .EXTENSION_MODE_ALL => .init(.{ .kept = true, .dropped = true, .unmatched = true }),
        .EXTENSION_MODE_MATCHED, .EXTENSION_MODE_UNSPECIFIED, _ => .init(.{ .kept = true, .dropped = true }),
    };
}

/// One (policy, extension) pair compiled into a signal's matcher index.
/// `handler` and `slot` are assigned by the resolver at snapshot compile time
/// and are opaque to policy_zig — the sink that receives the binding
/// interprets them. Dispatch never re-parses the extension declaration or
/// compares type strings.
pub const ExtensionBinding = struct {
    /// Index into the signal index's policy list (matcher_index.PolicyIndex).
    policy_index: u16,
    /// Policy id, owned by the index (valid for the snapshot's lifetime).
    policy_id: []const u8,
    /// Opaque handler identifier from the resolver (e.g. an enum tag value).
    handler: u8,
    /// Opaque per-binding slot from the resolver (e.g. a batch index).
    slot: u32,
    /// Slices of the stream this binding's mode selects.
    slices: ExtensionSliceSet,
    /// Extension config bytes, owned by the index.
    config: []const u8,
};

/// Result of resolving one extension declaration to a handler.
pub const ExtensionResolution = struct {
    handler: u8,
    slot: u32,
};

/// Resolves and validates one extension declaration at snapshot compile time.
/// Implemented outside policy_zig (the extensions module); policy_zig only
/// stores the opaque resolution in the binding. Return null when the
/// extension is unsupported or its config is invalid: per spec rule 5 the
/// extension is skipped (fail-open) and reported via PolicySyncStatus.errors,
/// while the policy's core match/keep/transform still applies.
pub const ExtensionResolver = struct {
    ctx: *anyopaque,
    resolve: *const fn (
        io: std.Io,
        ctx: *anyopaque,
        signal: TelemetryType,
        policy_id: []const u8,
        extension: *const proto.policy.Extension,
    ) ?ExtensionResolution,
};

/// Receives records selected by an extension's mode. One function pointer +
/// ctx (the shape of the accessor primitives, not a vtable): it exists only
/// to break the module cycle — policy_zig cannot import the extensions
/// module that implements it.
///
/// Called synchronously inside `evaluate`, after the final keep outcome is
/// known and before transforms run, so implementations observe pre-transform
/// records. `record` is borrowed and valid ONLY for the duration of the
/// call; implementations copy (encode) what they keep and MUST NOT block.
pub const ExtensionSink = struct {
    ctx: *anyopaque,
    deliver: *const fn (
        ctx: *anyopaque,
        io: ?std.Io,
        signal: TelemetryType,
        record: *const anyopaque,
        binding: *const ExtensionBinding,
        slice: ExtensionSlice,
    ) void,
};

// =============================================================================
// Service and Provider Configuration
// =============================================================================

/// A key/value string pair used for resource attributes and labels.
pub const StringPair = struct {
    key: []const u8,
    value: []const u8,
};

/// Service metadata for identifying this edge instance
pub const ServiceMetadata = struct {
    /// Service name (e.g., "tero-edge")
    name: []const u8 = "tero-edge",
    /// Service namespace (e.g., "tero")
    namespace: []const u8 = "tero",
    /// Service version (e.g., "0.1.0", defaults to "latest")
    version: []const u8 = "latest",
    /// Service instance ID - generated at startup, not configurable
    /// This field is set by the runtime, not from config
    instance_id: []const u8 = "",
    /// Supported policy stages for this service.
    /// Different binaries support different stages (e.g., OTLP supports traces, Datadog does not).
    supported_stages: []const PolicyStage = &.{},
    /// Extra OTel resource attributes to include in policy sync requests.
    resource_attributes: []const StringPair = &.{},
    /// Free-form labels to include in policy sync requests.
    labels: []const StringPair = &.{},
};

/// Provider type enumeration
pub const ProviderType = enum {
    file,
    http,
};

/// Configuration for a policy provider
pub const ProviderConfig = struct {
    /// Unique identifier for this provider (used to track which policies came from where)
    id: []const u8 = "",
    type: ProviderType = .file,
    // For file provider
    path: ?[]const u8 = null,
    // For http provider
    url: ?[]const u8 = null,
    poll_interval: ?u64 = null, // seconds
    headers: []const Header = &.{}, // custom headers for http provider
};

// =============================================================================
// Field Reference Types
// =============================================================================

const LogRemove = proto.policy.LogRemove;
const LogRedact = proto.policy.LogRedact;
const LogRename = proto.policy.LogRename;
const LogAdd = proto.policy.LogAdd;
const LogMatcher = proto.policy.LogMatcher;
const LogField = proto.policy.LogField;
const LogSampleKey = proto.policy.LogSampleKey;
const MetricMatcher = proto.policy.MetricMatcher;
const MetricField = proto.policy.MetricField;
const AttributePath = proto.policy.AttributePath;

/// Reference to a field for accessor/mutator operations.
/// Attribute fields now use AttributePath for nested attribute access (v1.2.0).
pub const FieldRef = union(enum) {
    log_field: LogField,
    /// AttributePath for nested log attribute access (e.g., path: ["http", "method"])
    log_attribute: AttributePath,
    /// AttributePath for nested resource attribute access
    resource_attribute: AttributePath,
    /// AttributePath for nested scope attribute access
    scope_attribute: AttributePath,

    pub fn fromRemoveField(field: ?LogRemove.field_union) ?FieldRef {
        const f = field orelse return null;
        return switch (f) {
            .log_field => |v| .{ .log_field = v },
            .log_attribute => |v| .{ .log_attribute = v },
            .resource_attribute => |v| .{ .resource_attribute = v },
            .scope_attribute => |v| .{ .scope_attribute = v },
        };
    }

    pub fn fromRedactField(field: ?LogRedact.field_union) ?FieldRef {
        const f = field orelse return null;
        return switch (f) {
            .log_field => |v| .{ .log_field = v },
            .log_attribute => |v| .{ .log_attribute = v },
            .resource_attribute => |v| .{ .resource_attribute = v },
            .scope_attribute => |v| .{ .scope_attribute = v },
        };
    }

    pub fn fromRenameFrom(from: ?LogRename.from_union) ?FieldRef {
        const f = from orelse return null;
        return switch (f) {
            .from_log_field => |v| .{ .log_field = v },
            .from_log_attribute => |v| .{ .log_attribute = v },
            .from_resource_attribute => |v| .{ .resource_attribute = v },
            .from_scope_attribute => |v| .{ .scope_attribute = v },
        };
    }

    pub fn fromAddField(field: ?LogAdd.field_union) ?FieldRef {
        const f = field orelse return null;
        return switch (f) {
            .log_field => |v| .{ .log_field = v },
            .log_attribute => |v| .{ .log_attribute = v },
            .resource_attribute => |v| .{ .resource_attribute = v },
            .scope_attribute => |v| .{ .scope_attribute = v },
        };
    }

    pub fn fromMatcherField(field: ?LogMatcher.field_union) ?FieldRef {
        const f = field orelse return null;
        return switch (f) {
            .log_field => |v| .{ .log_field = v },
            .log_attribute => |v| .{ .log_attribute = v },
            .resource_attribute => |v| .{ .resource_attribute = v },
            .scope_attribute => |v| .{ .scope_attribute = v },
        };
    }

    pub fn fromSampleKeyField(field: ?LogSampleKey.field_union) ?FieldRef {
        const f = field orelse return null;
        return switch (f) {
            .log_field => |v| .{ .log_field = v },
            .log_attribute => |v| .{ .log_attribute = v },
            .resource_attribute => |v| .{ .resource_attribute = v },
            .scope_attribute => |v| .{ .scope_attribute = v },
        };
    }

    /// Check if this field ref is an enum-type field whose value is carried
    /// in the field union itself (no separate match needed).
    pub fn isEnumField(self: FieldRef) bool {
        _ = self;
        return false; // Log matchers have no enum-type fields
    }

    /// Check if this field ref requires a key (attribute-based fields)
    pub fn isKeyed(self: FieldRef) bool {
        return switch (self) {
            .log_attribute, .resource_attribute, .scope_attribute => true,
            .log_field => false,
        };
    }

    /// True if this is an attribute selector (AttributePath-backed) with an
    /// empty path. Such a selector is unsatisfiable and must be rejected at
    /// compile time. Non-attribute fields are never flagged.
    pub fn hasEmptyAttributePath(self: FieldRef) bool {
        return switch (self) {
            .log_attribute, .resource_attribute, .scope_attribute => |attr| attr.path.items.len == 0,
            .log_field => false,
        };
    }

    /// Get the path for attribute-based fields, empty slice for log_field.
    /// For backward compatibility, use getKey() which returns first segment as string.
    pub fn getPath(self: FieldRef) []const []const u8 {
        return switch (self) {
            .log_attribute => |attr| attr.path.items,
            .resource_attribute => |attr| attr.path.items,
            .scope_attribute => |attr| attr.path.items,
            .log_field => &.{},
        };
    }

    /// Get the key for attribute-based fields (first path segment), empty string for log_field.
    /// For nested paths, this returns the first segment only - use getPath() for full path.
    pub fn getKey(self: FieldRef) []const u8 {
        const path = self.getPath();
        if (path.len > 0) return path[0];
        return "";
    }
};

// =============================================================================
// Metric Field Reference Types
// =============================================================================

const MetricType = proto.policy.MetricType;
const AggregationTemporality = proto.policy.AggregationTemporality;

/// Reference to a metric field for accessor/mutator operations.
/// Enum fields (metric_type, aggregation_temporality) are matched as strings via Hyperscan.
/// Attribute fields now use AttributePath for nested attribute access (v1.2.0).
pub const MetricFieldRef = union(enum) {
    metric_field: MetricField,
    /// AttributePath for nested datapoint attribute access
    datapoint_attribute: AttributePath,
    /// AttributePath for nested resource attribute access
    resource_attribute: AttributePath,
    /// AttributePath for nested scope attribute access
    scope_attribute: AttributePath,
    /// Match on metric type (gauge, sum, histogram, etc.)
    metric_type: MetricType,
    /// Match on aggregation temporality (delta, cumulative)
    aggregation_temporality: AggregationTemporality,

    pub fn fromMatcherField(field: ?MetricMatcher.field_union) ?MetricFieldRef {
        const f = field orelse return null;
        return switch (f) {
            .metric_field => |v| .{ .metric_field = v },
            .datapoint_attribute => |v| .{ .datapoint_attribute = v },
            .resource_attribute => |v| .{ .resource_attribute = v },
            .scope_attribute => |v| .{ .scope_attribute = v },
            .metric_type => |v| .{ .metric_type = v },
            .aggregation_temporality => |v| .{ .aggregation_temporality = v },
        };
    }

    /// Check if this field ref is an enum-type field whose value is carried
    /// in the field union itself (no separate match needed).
    pub fn isEnumField(self: MetricFieldRef) bool {
        return switch (self) {
            .metric_type, .aggregation_temporality => true,
            .metric_field, .datapoint_attribute, .resource_attribute, .scope_attribute => false,
        };
    }

    /// Check if this field ref requires a key (attribute-based fields)
    pub fn isKeyed(self: MetricFieldRef) bool {
        return switch (self) {
            .datapoint_attribute, .resource_attribute, .scope_attribute => true,
            .metric_field, .metric_type, .aggregation_temporality => false,
        };
    }

    /// True if this is an attribute selector with an empty path (see
    /// `FieldRef.hasEmptyAttributePath`).
    pub fn hasEmptyAttributePath(self: MetricFieldRef) bool {
        return switch (self) {
            .datapoint_attribute, .resource_attribute, .scope_attribute => |attr| attr.path.items.len == 0,
            .metric_field, .metric_type, .aggregation_temporality => false,
        };
    }

    /// Get the path for attribute-based fields, empty slice for simple fields.
    pub fn getPath(self: MetricFieldRef) []const []const u8 {
        return switch (self) {
            .datapoint_attribute => |attr| attr.path.items,
            .resource_attribute => |attr| attr.path.items,
            .scope_attribute => |attr| attr.path.items,
            .metric_field, .metric_type, .aggregation_temporality => &.{},
        };
    }

    /// Get the key for attribute-based fields (first path segment), empty string for simple fields.
    pub fn getKey(self: MetricFieldRef) []const u8 {
        const path = self.getPath();
        if (path.len > 0) return path[0];
        return "";
    }
};

// =============================================================================
// TypedValue - typed field value for equals/gt/gte/lt/lte matchers
// =============================================================================

/// A typed field value returned by the `typed_value` accessor primitive.
///
/// String matchers (exact/regex/starts_with/ends_with/contains) consume the
/// `.string` variant; the typed matchers (`equals`, `gt`, `gte`, `lt`, `lte`)
/// compare all variants.
///
/// `string` and `bytes` slices are borrowed from the consumer record and must
/// remain valid for the duration of the `engine.evaluate` call.
pub const TypedValue = union(enum) {
    string: []const u8,
    bool: bool,
    int: i64,
    double: f64,
    bytes: []const u8,
};

// =============================================================================
// Log Accessor - Capability-tagged interface to consumer log records
// =============================================================================

/// Read+write interface to a log record. Callers construct one of these and
/// pass it to `engine.evaluate(.log, ctx, buf, .{ .accessor = &acc, ... })`;
/// the engine dispatches every read and write through these function
/// pointers, with ctx being the consumer-owned record the pointers operate on.
///
/// `typed_value` is the only required field. Optional primitives advertise
/// consumer capability: when an `apply*` transform needs a primitive that's
/// null, the transform no-ops (does not count toward `*_applied`) — so a
/// consumer that doesn't wire `set` simply won't apply redact/add even if a
/// matching policy fires.
pub const LogAccessor = struct {
    /// Read a field as a typed value. This is the single read primitive:
    /// string matchers consume the `.string` variant, the typed matchers
    /// (`equals`/`gt`/`gte`/`lt`/`lte`) compare all variants, sampling reads
    /// `.bytes`/`.string`, and regex redact reads `.string`.
    ///
    /// Identifier fields (`LOG_FIELD_TRACE_ID`, `LOG_FIELD_SPAN_ID`): return
    /// `.bytes` with the RAW id bytes. The engine hex-renders them for string
    /// matchers (so hex literals in policies match) and uses the raw bytes
    /// for sampling. Returning null hides the id from matching.
    ///
    /// Return null when the field is absent. A present-but-wrong-type value
    /// causes a non-match (never a runtime error) consistent with fail-open.
    typed_value: *const fn (ctx: *const anyopaque, field: FieldRef) ?TypedValue,

    /// Returns true if the field is present, regardless of underlying type.
    /// When null, the engine falls back to `typed_value(...) != null`,
    /// preserving the "non-null means present" semantics.
    exists: ?*const fn (ctx: *const anyopaque, field: FieldRef) bool = null,

    /// Upsert a field. The engine pre-checks `upsert=false` conflicts via
    /// `callExists`, so `set` is always called at a point where the write is
    /// expected to succeed.
    ///
    /// Wiring this enables: log.redact, log.add. When null, both transforms
    /// silently no-op for callers passing this accessor. Lifetime: bytes
    /// passed to `set` must outlive any reference the consumer retains; the
    /// engine allocates them into the caller-supplied `scratch` allocator.
    set: ?*const fn (ctx: *anyopaque, field: FieldRef, value: []const u8) void = null,

    /// Remove a field. Returns true iff the field existed (so the engine can
    /// count `removes_applied` accurately).
    ///
    /// Wiring this enables: log.remove. Required (together with `move`) for
    /// log.rename to function with `upsert=true`.
    delete: ?*const fn (ctx: *anyopaque, field: FieldRef) bool = null,

    /// Move a value from one field to another. The engine pre-checks source
    /// existence and resolves upsert semantics (delete target first when
    /// upsert=true; engine-side skip when upsert=false and target exists), so
    /// `move` itself does not take an upsert flag.
    ///
    /// `to` is a key in the same family as `from` (matches the proto
    /// `LogRename.to` shape: rename only targets attributes, single key).
    ///
    /// Wiring this enables: log.rename.
    move: ?*const fn (ctx: *anyopaque, from: FieldRef, to: []const u8) void = null,

    /// Returns true if the field is present. Uses the wired `exists` primitive
    /// when available, otherwise falls back to `typed_value != null`.
    pub fn callExists(self: *const LogAccessor, ctx: *const anyopaque, field: FieldRef) bool {
        if (self.exists) |f| return f(ctx, field);
        return self.typed_value(ctx, field) != null;
    }
};

/// Read+write interface to a metric record.
pub const MetricAccessor = struct {
    /// Read a field as a typed value. See `LogAccessor.typed_value`.
    typed_value: *const fn (ctx: *const anyopaque, field: MetricFieldRef) ?TypedValue,

    exists: ?*const fn (ctx: *const anyopaque, field: MetricFieldRef) bool = null,

    pub fn callExists(self: *const MetricAccessor, ctx: *const anyopaque, field: MetricFieldRef) bool {
        if (self.exists) |f| return f(ctx, field);
        return self.typed_value(ctx, field) != null;
    }
};

/// Read+write interface to a trace/span record. The only writable target today
/// is the W3C tracestate header (TRACE_FIELD_TRACE_STATE), which the engine
/// writes when probabilistic sampling produces a threshold; consumers wire
/// `set` to merge that threshold into their tracestate representation.
pub const TraceAccessor = struct {
    /// Read a field as a typed value. See `LogAccessor.typed_value`.
    ///
    /// Identifier fields (`TRACE_FIELD_TRACE_ID`, `TRACE_FIELD_SPAN_ID`,
    /// `TRACE_FIELD_PARENT_SPAN_ID`): return `.bytes` with the RAW id bytes;
    /// the engine hex-renders them for string matchers and uses the raw bytes
    /// for sampling.
    typed_value: *const fn (ctx: *const anyopaque, field: TraceFieldRef) ?TypedValue,

    exists: ?*const fn (ctx: *const anyopaque, field: TraceFieldRef) bool = null,

    /// Wiring this enables: trace sampling threshold writeback.
    set: ?*const fn (ctx: *anyopaque, field: TraceFieldRef, value: []const u8) void = null,

    pub fn callExists(self: *const TraceAccessor, ctx: *const anyopaque, field: TraceFieldRef) bool {
        if (self.exists) |f| return f(ctx, field);
        return self.typed_value(ctx, field) != null;
    }
};

// =============================================================================
// Trace Field Reference Types
// =============================================================================

const TraceMatcher = proto.policy.TraceMatcher;
const TraceField = proto.policy.TraceField;
const SpanKind = proto.policy.SpanKind;
const SpanStatusCode = proto.policy.SpanStatusCode;

/// Reference to a trace/span field for accessor/mutator operations.
/// Supports all field types from TraceMatcher for comprehensive span matching.
/// Attribute fields now use AttributePath for nested attribute access (v1.2.0).
pub const TraceFieldRef = union(enum) {
    /// Simple trace fields (name, trace_id, span_id, etc.)
    trace_field: TraceField,
    /// AttributePath for nested span attribute access
    span_attribute: AttributePath,
    /// AttributePath for nested resource attribute access
    resource_attribute: AttributePath,
    /// AttributePath for nested scope attribute access
    scope_attribute: AttributePath,
    /// Match on span kind (enum value)
    span_kind: SpanKind,
    /// Match on span status code (enum value)
    span_status: SpanStatusCode,
    /// Event name matcher (matches if span contains an event with this name)
    event_name: []const u8,
    /// AttributePath for nested event attribute access
    event_attribute: AttributePath,
    /// Link trace ID matcher (matches if span has a link to this trace)
    link_trace_id: []const u8,

    pub fn fromMatcherField(field: ?TraceMatcher.field_union) ?TraceFieldRef {
        const f = field orelse return null;
        return switch (f) {
            .trace_field => |v| .{ .trace_field = v },
            .span_attribute => |v| .{ .span_attribute = v },
            .resource_attribute => |v| .{ .resource_attribute = v },
            .scope_attribute => |v| .{ .scope_attribute = v },
            .span_kind => |v| .{ .span_kind = v },
            .span_status => |v| .{ .span_status = v },
            .event_name => |v| .{ .event_name = v },
            .event_attribute => |v| .{ .event_attribute = v },
            .link_trace_id => |v| .{ .link_trace_id = v },
        };
    }

    /// Check if this field ref is an enum-type field whose value is carried
    /// in the field union itself (no separate match needed).
    pub fn isEnumField(self: TraceFieldRef) bool {
        return switch (self) {
            .span_kind, .span_status => true,
            .trace_field,
            .span_attribute,
            .resource_attribute,
            .scope_attribute,
            .event_name,
            .event_attribute,
            .link_trace_id,
            => false,
        };
    }

    /// Check if this field ref requires a key (attribute-based fields)
    pub fn isKeyed(self: TraceFieldRef) bool {
        return switch (self) {
            .span_attribute, .resource_attribute, .scope_attribute, .event_attribute => true,
            .event_name, .link_trace_id => true,
            .trace_field, .span_kind, .span_status => false,
        };
    }

    /// True if this is an attribute selector with an empty path (see
    /// `FieldRef.hasEmptyAttributePath`). `event_name`/`link_trace_id` are
    /// scalar string fields, not attribute paths, so they are never flagged.
    pub fn hasEmptyAttributePath(self: TraceFieldRef) bool {
        return switch (self) {
            .span_attribute, .resource_attribute, .scope_attribute, .event_attribute => |attr| attr.path.items.len == 0,
            .event_name, .link_trace_id, .trace_field, .span_kind, .span_status => false,
        };
    }

    /// Get the path for attribute-based fields, empty slice for simple fields.
    pub fn getPath(self: TraceFieldRef) []const []const u8 {
        return switch (self) {
            .span_attribute => |attr| attr.path.items,
            .resource_attribute => |attr| attr.path.items,
            .scope_attribute => |attr| attr.path.items,
            .event_attribute => |attr| attr.path.items,
            .event_name, .link_trace_id, .trace_field, .span_kind, .span_status => &.{},
        };
    }

    /// Get the key for attribute-based fields (first path segment), empty string for simple fields.
    /// For event_name and link_trace_id, returns the value itself.
    pub fn getKey(self: TraceFieldRef) []const u8 {
        return switch (self) {
            .span_attribute, .resource_attribute, .scope_attribute, .event_attribute => |attr| blk: {
                const path = attr.path.items;
                break :blk if (path.len > 0) path[0] else "";
            },
            .event_name => |k| k,
            .link_trace_id => |k| k,
            .trace_field, .span_kind, .span_status => "",
        };
    }
};

// =============================================================================
// Transform Result
// =============================================================================

/// Result of applying transforms to a log record.
/// Tracks both attempted and applied counts for each transform stage.
/// Used for reporting transform hit/miss statistics.
pub const TransformResult = struct {
    /// Number of remove operations attempted
    removes_attempted: usize = 0,
    /// Number of remove operations applied (hits)
    removes_applied: usize = 0,
    /// Number of redact operations attempted
    redacts_attempted: usize = 0,
    /// Number of redact operations applied (hits)
    redacts_applied: usize = 0,
    /// Number of rename operations attempted
    renames_attempted: usize = 0,
    /// Number of rename operations applied (hits)
    renames_applied: usize = 0,
    /// Number of add operations attempted
    adds_attempted: usize = 0,
    /// Number of add operations applied (hits)
    adds_applied: usize = 0,

    pub fn totalApplied(self: TransformResult) usize {
        return self.removes_applied + self.redacts_applied + self.renames_applied + self.adds_applied;
    }

    pub fn totalAttempted(self: TransformResult) usize {
        return self.removes_attempted + self.redacts_attempted + self.renames_attempted + self.adds_attempted;
    }
};

// =============================================================================
// Provider - Tagged union over concrete provider types
// =============================================================================

pub const Policy = proto.policy.Policy;
const SourceType = policy_source.SourceType;
const PolicyCallback = policy_provider.PolicyCallback;
const PolicyUpdate = policy_provider.PolicyUpdate;

/// Provider is a tagged union over all concrete provider types.
pub const Provider = union(enum) {
    file: *provider_file.FileProvider,
    http: *provider_http.HttpProvider,
    testing: *TestProvider,

    pub fn getId(self: Provider) []const u8 {
        return switch (self) {
            inline else => |p| p.getId(),
        };
    }

    pub fn subscribe(self: Provider, callback: PolicyCallback) !void {
        return switch (self) {
            inline else => |p| p.subscribe(callback),
        };
    }

    /// Hand the provider a stats collector to pull per-policy stats from before
    /// each sync. Only the HTTP provider reports upstream; file/testing ignore it.
    pub fn setStatsCollector(self: Provider, collector: policy_provider.StatsCollector) void {
        switch (self) {
            .http => |p| p.setStatsCollector(collector),
            .file, .testing => {},
        }
    }

    /// Hand the provider extension sync hooks (v1.6.0): capability
    /// advertisement in sync requests and routing of broadcast extension
    /// configs from responses. Only the HTTP provider has a control plane;
    /// file/testing accept the call and ignore it (nowhere to advertise to, no
    /// broadcast to receive). Wired uniformly by `registry.subscribe`.
    pub fn setExtensionSyncHooks(self: Provider, hooks: policy_provider.ExtensionSyncHooks) void {
        switch (self) {
            .http => |p| p.setExtensionSyncHooks(hooks),
            .file, .testing => {},
        }
    }

    pub fn sourceType(self: Provider) SourceType {
        return switch (self) {
            .file => .file,
            .http => .http,
            .testing => .file,
        };
    }

    pub fn deinit(self: Provider) void {
        switch (self) {
            inline else => |p| p.deinit(),
        }
    }
};

/// Test provider for use in unit/integration tests.
pub const TestProvider = struct {
    allocator: std.mem.Allocator,
    id: []const u8,
    source_type: SourceType,
    policies: std.ArrayList(Policy),
    callbacks: std.ArrayList(PolicyCallback),

    pub fn init(allocator: std.mem.Allocator, id: []const u8, source_type: SourceType) TestProvider {
        return .{
            .allocator = allocator,
            .id = id,
            .source_type = source_type,
            .policies = .empty,
            .callbacks = .empty,
        };
    }

    pub fn deinit(self: *TestProvider) void {
        defer self.* = undefined;

        for (self.policies.items) |*p| {
            p.deinit(self.allocator);
        }
        self.policies.deinit(self.allocator);
        self.callbacks.deinit(self.allocator);
    }

    pub fn getId(self: *TestProvider) []const u8 {
        return self.id;
    }

    pub fn addPolicy(self: *TestProvider, policy: Policy) !void {
        const policy_copy = try policy.dupe(self.allocator);
        try self.policies.append(self.allocator, policy_copy);
    }

    pub fn removePolicy(self: *TestProvider, name: []const u8) void {
        var i: usize = 0;
        while (i < self.policies.items.len) {
            if (std.mem.eql(u8, self.policies.items[i].name, name)) {
                var removed = self.policies.orderedRemove(i);
                removed.deinit(self.allocator);
            } else {
                i += 1;
            }
        }
    }

    pub fn clearPolicies(self: *TestProvider) void {
        for (self.policies.items) |*p| {
            p.deinit(self.allocator);
        }
        self.policies.clearRetainingCapacity();
    }

    pub fn notifySubscribers(self: *TestProvider) !void {
        const update: PolicyUpdate = .{
            .policies = self.policies.items,
            .provider_id = self.id,
        };
        for (self.callbacks.items) |cb| {
            try cb.call(update);
        }
    }

    pub fn subscribe(self: *TestProvider, callback: PolicyCallback) !void {
        try self.callbacks.append(self.allocator, callback);
        try callback.call(.{
            .policies = self.policies.items,
            .provider_id = self.id,
        });
    }

    pub fn provider(self: *TestProvider) Provider {
        return .{ .testing = self };
    }
};
