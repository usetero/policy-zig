//! Runtime benchmarks over compiled policy images.

const std = @import("std");
const policy = @import("policy_zig");
const zbench = @import("zbench");

const policy_counts = [_]usize{ 1, 10, 100, 256, 1000 };
const matching_counts = [_]usize{ 1, 100, 1000 };

var benchmark_checksum: u64 = 0;

const BenchState = struct {
    allocator: std.mem.Allocator,
    image_storage: []u8,
    worker_storage: []u8,
    image: policy.PolicyImage,
    worker: policy.WorkerState,
    engine: policy.PolicyEngine,
    values: [1]policy.ValueRef,
    context: policy.EvalContext,

    fn capacity(count: usize) policy.Capacity {
        return .{
            .max_connections = 1,
            .worker_count = 1,
            .max_policies = @intCast(count),
            .max_fields = 1,
            .max_matchers = @intCast(count),
            .max_actions = 1,
            .max_image_bytes = @intCast(256 + count * 128),
            .max_record_bytes = 4096,
            .max_context_bytes = 4096,
            .max_group_bytes = 512,
            .journal_events_per_worker = 1024,
            .extension_queue_bytes = 4096,
        };
    }

    fn init(allocator: std.mem.Allocator, count: usize, matching: bool, sample: bool) !*BenchState {
        const state = try allocator.create(BenchState);
        errdefer allocator.destroy(state);
        const capacity_value = capacity(count);
        state.allocator = allocator;
        state.image_storage = try allocator.alloc(u8, capacity_value.max_image_bytes);
        errdefer allocator.free(state.image_storage);
        state.worker_storage = try allocator.alloc(u8, policy.WorkerState.requiredBytes(capacity_value));
        errdefer allocator.free(state.worker_storage);

        const policies = try allocator.alloc(policy.compiler.PolicySpec, count);
        defer allocator.free(policies);
        const matchers = try allocator.alloc(policy.compiler.MatcherSpec, count);
        defer allocator.free(matchers);
        const identifiers = try allocator.alloc([16]u8, count);
        defer allocator.free(identifiers);
        const field: policy.compiler.FieldSpec = .{
            .signal = .log,
            .value_kind = .string,
            .selector_id = 1,
            .name = "body",
        };
        for (0..count) |index| {
            const identifier = try std.fmt.bufPrint(&identifiers[index], "policy-{d}", .{index});
            matchers[index] = .{
                .field = field,
                .opcode = .exact,
                .value = .{ .string = "never-matches" },
            };
            policies[index] = .{
                .id = identifier,
                .verdict = .drop,
                .priority = @intCast(index),
                .matchers = matchers[index .. index + 1],
                .sampling = if (sample) .{ .percentage = 50 } else null,
            };
        }

        var workspace: [256]u8 = undefined;
        var compiler = try policy.PolicyCompiler.init(capacity_value, &workspace, state.image_storage);
        const bytes = try compiler.compile(.{ .policies = policies, .seed = 0x1234 });
        state.image = try policy.PolicyImage.open(bytes);
        state.worker = try policy.WorkerState.init(state.worker_storage, capacity_value);
        state.engine = policy.PolicyEngine.init(&state.image, &state.worker);
        state.values = .{.{ .string = if (matching) "never-matches" else "ordinary application record" }};
        state.context = .{
            .image_epoch = 1,
            .worker_id = 0,
            .signal = .log,
            .record_key = "stable-benchmark-key",
        };
        return state;
    }

    fn deinit(self: *BenchState) void {
        const allocator = self.allocator;
        defer allocator.destroy(self);
        defer self.* = undefined;
        allocator.free(self.worker_storage);
        allocator.free(self.image_storage);
    }

    pub fn run(self: *BenchState, allocator: std.mem.Allocator) void {
        _ = allocator;
        const result = self.engine.evaluate(&self.values, self.context);
        const destination: *volatile u64 = &benchmark_checksum;
        destination.* +%= result.image_hash_prefix ^ result.match_summary ^ result.winning_policy_index;
    }
};

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();
    var benchmark = zbench.Benchmark.init(allocator, .{});
    defer benchmark.deinit();

    var names: [policy_counts.len + matching_counts.len + 1][40]u8 = undefined;
    var misses: [policy_counts.len]*BenchState = undefined;
    var matches: [matching_counts.len]*BenchState = undefined;
    for (policy_counts, 0..) |count, index| {
        misses[index] = try BenchState.init(allocator, count, false, false);
        const name = try std.fmt.bufPrint(&names[index], "exact-unmatched/{d}", .{count});
        try benchmark.addParam(name, @as(*const BenchState, misses[index]), .{});
    }
    for (matching_counts, 0..) |count, index| {
        matches[index] = try BenchState.init(allocator, count, true, false);
        const name = try std.fmt.bufPrint(&names[policy_counts.len + index], "exact-matched/{d}", .{count});
        try benchmark.addParam(name, @as(*const BenchState, matches[index]), .{});
    }
    const sampled = try BenchState.init(allocator, 1, true, true);
    try benchmark.addParam("otel-sampling/1", @as(*const BenchState, sampled), .{});

    const io = std.Options.debug_io;
    try benchmark.run(io, std.Io.File.stdout());
    var buffer: [256]u8 = undefined;
    var output = std.Io.File.stdout().writer(io, &buffer);
    try output.interface.print("checksum={d} image_bytes/1000={d} worker_bytes/1000={d}\n", .{
        benchmark_checksum,
        misses[misses.len - 1].image.bytes.len,
        policy.WorkerState.requiredBytes(BenchState.capacity(1000)),
    });
    try output.interface.flush();

    for (misses) |state| state.deinit();
    for (matches) |state| state.deinit();
    sampled.deinit();
}
