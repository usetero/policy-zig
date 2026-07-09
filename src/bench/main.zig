// Benchmarks for policy-zig evaluation across telemetry types and policy counts.
// Each policy is a distinct regex that the test record never matches, forcing a
// full scan — all N patterns checked per call. Mirrors policy-go backendbench.
//
// Run: zig build bench
const std = @import("std");
const zbench = @import("zbench");
const policy_zig = @import("policy_zig");
const o11y = @import("observability");

const PolicyEngine = policy_zig.PolicyEngine;
const PolicyRegistry = policy_zig.Registry;
const FieldRef = policy_zig.FieldRef;
const MetricFieldRef = policy_zig.MetricFieldRef;
const TraceFieldRef = policy_zig.TraceFieldRef;
const LogAccessor = policy_zig.LogAccessor;
const MetricAccessor = policy_zig.MetricAccessor;
const TraceAccessor = policy_zig.TraceAccessor;
const TypedValue = policy_zig.TypedValue;
const NoopEventBus = o11y.NoopEventBus;

const COUNTS = [_]usize{ 1, 10, 100, 1000 };

// --- Minimal accessors ---

const BenchLog = struct {
    body: []const u8,
    fn access(ctx: *const anyopaque, field: FieldRef) ?TypedValue {
        const self: *const BenchLog = @ptrCast(@alignCast(ctx));
        return switch (field) {
            .log_field => |lf| if (lf == .LOG_FIELD_BODY) .{ .string = self.body } else null,
            else => null,
        };
    }
    const accessor: LogAccessor = .{ .typed_value = access };
};

const BenchMetric = struct {
    name: []const u8,
    fn access(ctx: *const anyopaque, field: MetricFieldRef) ?TypedValue {
        const self: *const BenchMetric = @ptrCast(@alignCast(ctx));
        return switch (field) {
            .metric_field => |mf| if (mf == .METRIC_FIELD_NAME) .{ .string = self.name } else null,
            else => null,
        };
    }
    const accessor: MetricAccessor = .{ .typed_value = access };
};

const BenchTrace = struct {
    name: []const u8,
    fn access(ctx: *const anyopaque, field: TraceFieldRef) ?TypedValue {
        const self: *const BenchTrace = @ptrCast(@alignCast(ctx));
        return switch (field) {
            .trace_field => |tf| if (tf == .TRACE_FIELD_NAME) .{ .string = self.name } else null,
            else => null,
        };
    }
    const accessor: TraceAccessor = .{ .typed_value = access };
};

// --- JSON builders (allocator passed per-call, Zig 0.16 style) ---

fn appendNum(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, n: usize) !void {
    var tmp: [20]u8 = undefined;
    const s = std.fmt.bufPrint(&tmp, "{d}", .{n}) catch unreachable;
    try buf.appendSlice(allocator, s);
}

fn buildLogJson(allocator: std.mem.Allocator, n: usize) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try buf.appendSlice(allocator, "{\"policies\":[");
    for (0..n) |i| {
        if (i > 0) try buf.append(allocator, ',');
        try buf.appendSlice(allocator, "{\"id\":\"log-");
        try appendNum(&buf, allocator, i);
        try buf.appendSlice(allocator, "\",\"name\":\"log-");
        try appendNum(&buf, allocator, i);
        try buf.appendSlice(allocator, "\",\"log\":{\"match\":[{\"log_field\":\"body\",\"regex\":\"secret-token-");
        try appendNum(&buf, allocator, i);
        try buf.appendSlice(allocator, "-[0-9a-f]{16}\"}],\"keep\":\"none\"}}");
    }
    try buf.appendSlice(allocator, "]}");
    return buf.toOwnedSlice(allocator);
}

fn buildMetricJson(allocator: std.mem.Allocator, n: usize) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try buf.appendSlice(allocator, "{\"policies\":[");
    for (0..n) |i| {
        if (i > 0) try buf.append(allocator, ',');
        try buf.appendSlice(allocator, "{\"id\":\"metric-");
        try appendNum(&buf, allocator, i);
        try buf.appendSlice(allocator, "\",\"name\":\"metric-");
        try appendNum(&buf, allocator, i);
        try buf.appendSlice(allocator, "\",\"metric\":{\"match\":[{\"metric_field\":\"name\",\"regex\":\"secret-token-");
        try appendNum(&buf, allocator, i);
        try buf.appendSlice(allocator, "-[0-9a-f]{16}\"}],\"keep\":false}}");
    }
    try buf.appendSlice(allocator, "]}");
    return buf.toOwnedSlice(allocator);
}

fn buildTraceJson(allocator: std.mem.Allocator, n: usize) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try buf.appendSlice(allocator, "{\"policies\":[");
    for (0..n) |i| {
        if (i > 0) try buf.append(allocator, ',');
        try buf.appendSlice(allocator, "{\"id\":\"trace-");
        try appendNum(&buf, allocator, i);
        try buf.appendSlice(allocator, "\",\"name\":\"trace-");
        try appendNum(&buf, allocator, i);
        try buf.appendSlice(allocator, "\",\"trace\":{\"match\":[{\"trace_field\":\"TRACE_FIELD_NAME\",\"regex\":\"secret-token-");
        try appendNum(&buf, allocator, i);
        try buf.appendSlice(allocator, "-[0-9a-f]{16}\"}],\"keep\":{\"percentage\":100.0}}}");
    }
    try buf.appendSlice(allocator, "]}");
    return buf.toOwnedSlice(allocator);
}

// --- Per-benchmark state structs (heap-allocated so registry doesn't move) ---
// zBench calls run(self, allocator) in a tight loop; setup happens in init().

const LogState = struct {
    registry: *PolicyRegistry,
    engine: PolicyEngine,
    ctx: BenchLog = .{ .body = "normal application log line, nothing sensitive here" },
    policy_id_buf: [1024][]const u8 = undefined,

    fn init(allocator: std.mem.Allocator, bus: *o11y.EventBus, n: usize) !*LogState {
        const json = try buildLogJson(allocator, n);
        defer allocator.free(json);
        const policies = try policy_zig.parser.parsePoliciesBytes(allocator, json);
        defer {
            for (policies) |*p| p.deinit(allocator);
            allocator.free(policies);
        }
        const self = try allocator.create(LogState);
        self.registry = try allocator.create(PolicyRegistry);
        self.registry.* = PolicyRegistry.init(allocator, bus);
        try self.registry.updatePolicies(policies, "bench", .file);
        self.engine = PolicyEngine.init(bus, self.registry);
        self.ctx = .{ .body = "normal application log line, nothing sensitive here" };
        return self;
    }

    fn deinit(self: *LogState, allocator: std.mem.Allocator) void {
        self.registry.deinit();
        allocator.destroy(self.registry);
        allocator.destroy(self);
    }

    pub fn run(self: *LogState, alloc: std.mem.Allocator) void {
        _ = alloc;
        _ = self.engine.evaluate(.log, &BenchLog.accessor, &self.ctx, &self.policy_id_buf, .{ .io = std.Options.debug_io });
    }
};

const MetricState = struct {
    registry: *PolicyRegistry,
    engine: PolicyEngine,
    ctx: BenchMetric = .{ .name = "http.server.request.duration" },
    policy_id_buf: [1024][]const u8 = undefined,

    fn init(allocator: std.mem.Allocator, bus: *o11y.EventBus, n: usize) !*MetricState {
        const json = try buildMetricJson(allocator, n);
        defer allocator.free(json);
        const policies = try policy_zig.parser.parsePoliciesBytes(allocator, json);
        defer {
            for (policies) |*p| p.deinit(allocator);
            allocator.free(policies);
        }
        const self = try allocator.create(MetricState);
        self.registry = try allocator.create(PolicyRegistry);
        self.registry.* = PolicyRegistry.init(allocator, bus);
        try self.registry.updatePolicies(policies, "bench", .file);
        self.engine = PolicyEngine.init(bus, self.registry);
        self.ctx = .{ .name = "http.server.request.duration" };
        return self;
    }

    fn deinit(self: *MetricState, allocator: std.mem.Allocator) void {
        self.registry.deinit();
        allocator.destroy(self.registry);
        allocator.destroy(self);
    }

    pub fn run(self: *MetricState, alloc: std.mem.Allocator) void {
        _ = alloc;
        _ = self.engine.evaluate(.metric, &BenchMetric.accessor, &self.ctx, &self.policy_id_buf, .{ .io = std.Options.debug_io });
    }
};

const TraceState = struct {
    registry: *PolicyRegistry,
    engine: PolicyEngine,
    ctx: BenchTrace = .{ .name = "GET /api/v1/users" },
    policy_id_buf: [1024][]const u8 = undefined,

    fn init(allocator: std.mem.Allocator, bus: *o11y.EventBus, n: usize) !*TraceState {
        const json = try buildTraceJson(allocator, n);
        defer allocator.free(json);
        const policies = try policy_zig.parser.parsePoliciesBytes(allocator, json);
        defer {
            for (policies) |*p| p.deinit(allocator);
            allocator.free(policies);
        }
        const self = try allocator.create(TraceState);
        self.registry = try allocator.create(PolicyRegistry);
        self.registry.* = PolicyRegistry.init(allocator, bus);
        try self.registry.updatePolicies(policies, "bench", .file);
        self.engine = PolicyEngine.init(bus, self.registry);
        self.ctx = .{ .name = "GET /api/v1/users" };
        return self;
    }

    fn deinit(self: *TraceState, allocator: std.mem.Allocator) void {
        self.registry.deinit();
        allocator.destroy(self.registry);
        allocator.destroy(self);
    }

    pub fn run(self: *TraceState, alloc: std.mem.Allocator) void {
        _ = alloc;
        _ = self.engine.evaluate(.trace, &BenchTrace.accessor, &self.ctx, &self.policy_id_buf, .{ .io = std.Options.debug_io });
    }
};

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    const bus = noop_bus.eventBus();

    var bench = zbench.Benchmark.init(allocator, .{});
    defer bench.deinit();

    // Build all states upfront (outside the timed loops), register with zBench.
    // We need bench name buffers to outlive bench.run().
    var name_bufs: [COUNTS.len * 3][32]u8 = undefined;
    var states_log: [COUNTS.len]*LogState = undefined;
    var states_metric: [COUNTS.len]*MetricState = undefined;
    var states_trace: [COUNTS.len]*TraceState = undefined;

    for (COUNTS, 0..) |n, idx| {
        states_log[idx] = try LogState.init(allocator, bus, n);
        const log_name = try std.fmt.bufPrint(&name_bufs[idx], "log/{d}", .{n});
        try bench.addParam(log_name, @as(*const LogState, states_log[idx]), .{});

        states_metric[idx] = try MetricState.init(allocator, bus, n);
        const metric_name = try std.fmt.bufPrint(&name_bufs[COUNTS.len + idx], "metric/{d}", .{n});
        try bench.addParam(metric_name, @as(*const MetricState, states_metric[idx]), .{});

        states_trace[idx] = try TraceState.init(allocator, bus, n);
        const trace_name = try std.fmt.bufPrint(&name_bufs[COUNTS.len * 2 + idx], "trace/{d}", .{n});
        try bench.addParam(trace_name, @as(*const TraceState, states_trace[idx]), .{});
    }

    const io = std.Options.debug_io;
    try bench.run(io, std.Io.File.stdout());

    for (states_log) |s| s.deinit(allocator);
    for (states_metric) |s| s.deinit(allocator);
    for (states_trace) |s| s.deinit(allocator);
}
