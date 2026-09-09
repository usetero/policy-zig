//! Pure offline replay against the exact serialized executable policy.

const std = @import("std");
const runtime = @import("policy_runtime");

pub const ReplayRecord = struct {
    values: []const runtime.ValueRef,
    context: runtime.EvalContext,
    expected_event: *const [runtime.decision_event_bytes]u8,
};

pub const Bundle = struct {
    image_bytes: []const u8,
    records: []const ReplayRecord,
    route_config_version: u64,
    raw_framed_input: []const u8,
    expected_transformed_bytes: []const u8,
};

pub const Mismatch = struct {
    record_index: u32,
    expected: [runtime.decision_event_bytes]u8,
    actual: [runtime.decision_event_bytes]u8,
};

pub const ReplayError = error{
    InvalidImage,
    InvalidWorkerStorage,
};

/// Replay consumes recorded time, sampling, and rate-limit outcomes from each
/// EvalContext, so host scheduling and fresh entropy cannot change a result.
pub fn run(bundle: Bundle, worker_storage: []u8, capacity: runtime.Capacity, mismatch: *?Mismatch) ReplayError!bool {
    mismatch.* = null;
    var image = runtime.PolicyImage.open(bundle.image_bytes) catch return error.InvalidImage;
    var worker = runtime.WorkerState.init(worker_storage, capacity) catch return error.InvalidWorkerStorage;
    for (bundle.records, 0..) |record, index| {
        const decision = runtime.evaluate(&image, &worker, record.values, record.context);
        const event = runtime.DecisionEvent.fromDecision(record.context, decision);
        var encoded: [runtime.decision_event_bytes]u8 = undefined;
        event.encode(&encoded);
        if (!std.mem.eql(u8, &encoded, record.expected_event)) {
            mismatch.* = .{
                .record_index = @intCast(index),
                .expected = record.expected_event.*,
                .actual = encoded,
            };
            return false;
        }
    }
    return true;
}

test "replay verifies a decision event byte for byte" {
    const compiler_mod = @import("policy_compiler");
    const capacity: runtime.Capacity = .{
        .max_connections = 1,
        .worker_count = 1,
        .max_policies = 4,
        .max_fields = 4,
        .max_matchers = 4,
        .max_actions = 4,
        .max_image_bytes = 1024,
        .max_record_bytes = 1024,
        .max_context_bytes = 256,
        .max_group_bytes = 128,
        .journal_events_per_worker = 8,
        .extension_queue_bytes = 128,
    };
    const field: compiler_mod.FieldSpec = .{ .signal = .log, .value_kind = .string, .selector_id = 1, .name = "body" };
    const matchers = [_]compiler_mod.MatcherSpec{.{ .field = field, .opcode = .exists }};
    const actions = [_]compiler_mod.ActionSpec{.{ .opcode = .remove, .field = field }};
    const policies = [_]compiler_mod.PolicySpec{.{
        .id = "keep",
        .verdict = .keep,
        .matchers = &matchers,
        .actions = &actions,
    }};
    var workspace: [256]u8 = undefined;
    var image_storage: [1024]u8 = undefined;
    var compiler = try compiler_mod.Compiler.init(capacity, &workspace, &image_storage);
    const image_bytes = try compiler.compile(.{ .policies = &policies, .seed = 9 });
    var image = try runtime.PolicyImage.open(image_bytes);
    const values = [_]runtime.ValueRef{.{ .string = "hello" }};
    const context: runtime.EvalContext = .{
        .image_epoch = 7,
        .global_sequence = 1,
        .worker_id = 0,
        .signal = .log,
        .record_key = "key",
        .sampling_outcome = true,
        .rate_limit_outcome = true,
    };
    var expected_worker_bytes: [runtime.WorkerState.requiredBytes(capacity)]u8 = undefined;
    var expected_worker = try runtime.WorkerState.init(&expected_worker_bytes, capacity);
    const decision = runtime.evaluate(&image, &expected_worker, &values, context);
    var action_iterator = runtime.ActionIterator.init(&image, decision);
    const action = action_iterator.next().?;
    try std.testing.expectEqual(@as(@TypeOf(action.opcode), .remove), action.opcode);
    try std.testing.expectEqual(@as(?u16, 0), action.field_index);
    try std.testing.expect(action_iterator.next() == null);
    const event = runtime.DecisionEvent.fromDecision(context, decision);
    var expected: [runtime.decision_event_bytes]u8 = undefined;
    event.encode(&expected);
    const records = [_]ReplayRecord{.{ .values = &values, .context = context, .expected_event = &expected }};
    var replay_worker_bytes: [runtime.WorkerState.requiredBytes(capacity)]u8 = undefined;
    var mismatch: ?Mismatch = null;
    try std.testing.expect(try run(.{
        .image_bytes = image_bytes,
        .records = &records,
        .route_config_version = 1,
        .raw_framed_input = "frame",
        .expected_transformed_bytes = "",
    }, &replay_worker_bytes, capacity, &mismatch));
    try std.testing.expect(mismatch == null);
}
