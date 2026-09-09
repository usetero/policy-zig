//! Cold compiler from normalized source policies to a bounded PolicyImage.

const std = @import("std");
const capacity_mod = @import("policy_capacity");
const image = @import("policy_image");

pub const Capacity = capacity_mod.Capacity;

pub const FieldSpec = struct {
    signal: image.Signal = .log,
    value_kind: image.ValueKind,
    selector_id: u32,
    name: []const u8,
};

pub const MatchValue = union(enum) {
    none,
    string: []const u8,
    signed: i64,
    unsigned: u64,
    /// Canonical decimal spelling, parsed once per comparison without storage.
    /// Keeping the source spelling avoids treating a Zig float layout as ABI.
    float: []const u8,
    boolean: bool,
};

pub const MatcherSpec = struct {
    field: FieldSpec,
    opcode: image.MatchOpcode,
    negated: bool = false,
    case_insensitive: bool = false,
    value: MatchValue = .none,
};

pub const ActionSpec = struct {
    opcode: image.ActionOpcode,
    field: ?FieldSpec = null,
    value: []const u8 = "",
    binding_id: u32 = 0,
    flags: u8 = 0,
};

/// Provider-neutral form of the OpenTelemetry probability-sampling contract.
/// Floating-point percentages are converted to a 56-bit threshold before the
/// image is published, so evaluation never parses provider configuration.
pub const SamplingConfig = struct {
    percentage: f32,
    mode: image.SamplingMode = .hash_seed,
    precision: u8 = 4,
    hash_seed: u32 = 0,
    fail_closed: bool = true,
};

/// Source IDs stay in the cold sidecar; only numeric order reaches the image.
pub const PolicySpec = struct {
    id: []const u8,
    signal: image.Signal = .log,
    verdict: image.Verdict,
    priority: i32 = 0,
    enabled: bool = true,
    matchers: []const MatcherSpec,
    actions: []const ActionSpec = &.{},
    sampling: ?SamplingConfig = null,
    rate_limit_per_second: u32 = 0,
    rate_window_seconds: u32 = 1,
};

pub const Program = struct {
    policies: []const PolicySpec,
    seed: u64,
};

pub const Section = enum {
    workspace,
    policies,
    fields,
    matchers,
    actions,
    image,
    string_blob,
};

pub const CapacityFailure = struct {
    section: Section,
    required: u64,
    available: u64,
};

pub const CompileError = error{
    InvalidCapacity,
    WorkspaceExhausted,
    TooManyPolicies,
    TooManyFields,
    TooManyMatchers,
    TooManyActions,
    ImageTooLarge,
    InvalidPolicy,
    InvalidMatcher,
    DuplicatePolicyId,
    IntegerOverflow,
    CorruptOutput,
};

const FieldScratch = struct {
    spec: FieldSpec,
};

/// The compiler owns no storage. Both mutable scratch and output are supplied
/// by the caller and can be reset immediately after a successful compile.
pub const Compiler = struct {
    capacity: Capacity,
    workspace: []u8,
    destination: []u8,
    failure: ?CapacityFailure = null,

    pub fn init(capacity: Capacity, workspace: []u8, destination: []u8) CompileError!Compiler {
        capacity.validate() catch return error.InvalidCapacity;
        if (destination.len < capacity.max_image_bytes) {
            return error.ImageTooLarge;
        }
        return .{
            .capacity = capacity,
            .workspace = workspace,
            .destination = destination[0..capacity.max_image_bytes],
        };
    }

    pub fn requiredWorkspace(capacity: Capacity) usize {
        return @as(usize, capacity.max_fields) * @sizeOf(FieldScratch) + @alignOf(FieldScratch) - 1;
    }

    /// Compile a deterministic image. Policies must already be in normalized
    /// precedence order; duplicate IDs are rejected to make that boundary exact.
    pub fn compile(self: *Compiler, program: Program) CompileError![]const u8 {
        self.failure = null;
        if (program.policies.len > self.capacity.max_policies) {
            return self.fail(.policies, program.policies.len, self.capacity.max_policies, error.TooManyPolicies);
        }

        var matcher_count: u64 = 0;
        var action_count: u64 = 0;
        var string_bytes: u64 = 0;
        for (program.policies, 0..) |policy, policy_index| {
            if (policy.id.len == 0) return error.InvalidPolicy;
            if (policy.sampling) |sampling| {
                if (std.math.isNan(sampling.percentage) or
                    sampling.precision < 1 or
                    sampling.precision > 14) return error.InvalidPolicy;
            }
            if (policy.matchers.len > std.math.maxInt(u16)) return error.InvalidPolicy;
            for (program.policies[0..policy_index]) |prior| {
                if (std.mem.eql(u8, prior.id, policy.id)) return error.DuplicatePolicyId;
            }
            matcher_count = std.math.add(u64, matcher_count, policy.matchers.len) catch return error.IntegerOverflow;
            action_count = std.math.add(u64, action_count, policy.actions.len) catch return error.IntegerOverflow;
            for (policy.matchers) |matcher| {
                try validateMatcher(matcher);
                string_bytes = try addMatcherStringBytes(string_bytes, matcher);
            }
            for (policy.actions) |action| {
                try validateAction(action);
                string_bytes = std.math.add(u64, string_bytes, action.value.len) catch return error.IntegerOverflow;
            }
        }
        if (matcher_count > self.capacity.max_matchers) {
            return self.fail(.matchers, matcher_count, self.capacity.max_matchers, error.TooManyMatchers);
        }
        if (action_count > self.capacity.max_actions) {
            return self.fail(.actions, action_count, self.capacity.max_actions, error.TooManyActions);
        }

        var fba = std.heap.FixedBufferAllocator.init(self.workspace);
        const scratch = fba.allocator();
        const fields = scratch.alloc(FieldScratch, self.capacity.max_fields) catch {
            return self.fail(
                .workspace,
                @sizeOf(FieldScratch) * @as(u64, self.capacity.max_fields),
                self.workspace.len,
                error.WorkspaceExhausted,
            );
        };
        var field_count: u16 = 0;
        for (program.policies) |policy| {
            for (policy.matchers) |matcher| {
                _ = try internField(self, fields, &field_count, matcher.field);
            }
            for (policy.actions) |action| {
                if (action.field) |field| _ = try internField(self, fields, &field_count, field);
            }
        }
        for (fields[0..field_count]) |field| {
            string_bytes = std.math.add(u64, string_bytes, field.spec.name.len) catch return error.IntegerOverflow;
        }

        const fields_offset: u64 = image.header_bytes;
        const policies_offset = fields_offset + @as(u64, field_count) * image.field_bytes;
        const matchers_offset = policies_offset + @as(u64, program.policies.len) * image.policy_bytes;
        const actions_offset = matchers_offset + matcher_count * image.matcher_bytes;
        const strings_offset = actions_offset + action_count * image.action_bytes;
        const total_bytes = strings_offset + string_bytes;
        if (total_bytes > self.capacity.max_image_bytes or
            total_bytes > self.destination.len or
            total_bytes > std.math.maxInt(u32))
        {
            const available = @min(self.capacity.max_image_bytes, self.destination.len);
            return self.fail(.image, total_bytes, available, error.ImageTooLarge);
        }

        const output = self.destination[0..@intCast(total_bytes)];
        @memset(output, 0);
        const header: image.Header = .{
            .flags = 0,
            .image_bytes = @intCast(total_bytes),
            .policy_count = @intCast(program.policies.len),
            .field_count = field_count,
            .matcher_count = @intCast(matcher_count),
            .action_count = @intCast(action_count),
            .fields_offset = @intCast(fields_offset),
            .policies_offset = @intCast(policies_offset),
            .matchers_offset = @intCast(matchers_offset),
            .actions_offset = @intCast(actions_offset),
            .strings_offset = @intCast(strings_offset),
            .strings_bytes = @intCast(string_bytes),
            .seed = program.seed,
            .image_hash = [_]u8{0} ** image.hash_bytes,
        };
        image.writeHeader(output, header);

        var string_cursor: u32 = 0;
        for (fields[0..field_count], 0..) |field, field_index| {
            const name_offset = string_cursor;
            copyString(output, header.strings_offset, &string_cursor, field.spec.name);
            image.writeField(output, header.fields_offset + field_index * image.field_bytes, .{
                .signal = field.spec.signal,
                .value_kind = field.spec.value_kind,
                .selector_id = field.spec.selector_id,
                .name_offset = name_offset,
                .name_len = @intCast(field.spec.name.len),
            });
        }

        var matcher_cursor: u32 = 0;
        var action_cursor: u32 = 0;
        for (program.policies, 0..) |policy, policy_index| {
            const matcher_start = matcher_cursor;
            for (policy.matchers) |matcher| {
                const field_index = findField(fields[0..field_count], matcher.field).?;
                const encoded = try encodeMatchValue(output, header.strings_offset, &string_cursor, matcher.value);
                image.writeMatcher(output, header.matchers_offset + @as(usize, matcher_cursor) * image.matcher_bytes, .{
                    .field_index = field_index,
                    .opcode = matcher.opcode,
                    .flags = @intFromBool(matcher.negated) |
                        (@as(u8, @intFromBool(matcher.case_insensitive)) << 1),
                    .policy_index = @intCast(policy_index),
                    .constant_offset = encoded.offset,
                    .constant_len = encoded.len,
                    .value_lo = encoded.lo,
                    .value_hi = encoded.hi,
                    .stable_hash = if (encoded.len == 0) 0 else std.hash.Wyhash.hash(0, matcherString(matcher.value)),
                });
                matcher_cursor += 1;
            }
            const action_start = action_cursor;
            for (policy.actions) |action| {
                const value_offset = string_cursor;
                copyString(output, header.strings_offset, &string_cursor, action.value);
                image.writeAction(output, header.actions_offset + @as(usize, action_cursor) * image.action_bytes, .{
                    .opcode = action.opcode,
                    .flags = action.flags,
                    .field_index = if (action.field) |field|
                        findField(fields[0..field_count], field).?
                    else
                        std.math.maxInt(u16),
                    .value_offset = value_offset,
                    .value_len = @intCast(action.value.len),
                    .binding_id = action.binding_id,
                });
                action_cursor += 1;
            }
            image.writePolicy(output, header.policies_offset + policy_index * image.policy_bytes, .{
                .signal = policy.signal,
                .required_matches = @intCast(policy.matchers.len),
                .verdict = policy.verdict,
                .flags = @intFromBool(policy.enabled),
                .priority = policy.priority,
                .matcher_start = matcher_start,
                .matcher_count = @intCast(policy.matchers.len),
                .action_start = action_start,
                .action_count = @intCast(policy.actions.len),
                .sampling_mode = if (policy.sampling) |sampling| sampling.mode else .hash_seed,
                .sampling_precision = if (policy.sampling) |sampling| sampling.precision else 4,
                .sampling_enabled = policy.sampling != null,
                .sampling_fail_closed = if (policy.sampling) |sampling| sampling.fail_closed else true,
                .rate_limit_per_second = policy.rate_limit_per_second,
                .rate_window_seconds = policy.rate_window_seconds,
                .sampling_threshold = if (policy.sampling) |sampling|
                    samplingThreshold(sampling.percentage)
                else
                    0,
                .sampling_hash_seed = if (policy.sampling) |sampling| sampling.hash_seed else 0,
            });
        }
        std.debug.assert(string_cursor == header.strings_bytes);
        image.seal(output);
        _ = image.PolicyImage.open(output) catch return error.CorruptOutput;
        return output;
    }

    fn fail(self: *Compiler, section: Section, required: u64, available: u64, err: CompileError) CompileError {
        self.failure = .{ .section = section, .required = required, .available = available };
        return err;
    }
};

const EncodedValue = struct {
    offset: u32 = 0,
    len: u32 = 0,
    lo: u64 = 0,
    hi: u64 = 0,
};

fn addMatcherStringBytes(current: u64, matcher: MatcherSpec) CompileError!u64 {
    const bytes = matcherString(matcher.value);
    return std.math.add(u64, current, bytes.len) catch error.IntegerOverflow;
}

fn validateMatcher(matcher: MatcherSpec) CompileError!void {
    if (matcher.field.name.len == 0 or matcher.field.name.len > std.math.maxInt(u32)) return error.InvalidMatcher;
    const valid = switch (matcher.opcode) {
        .exists => matcher.value == .none,
        .exact, .prefix, .suffix, .contains, .regex => matcher.value == .string and
            (matcher.field.value_kind == .string or
                matcher.field.value_kind == .bytes or
                matcher.field.value_kind == .any),
        .signed_eq, .signed_lt, .signed_lte, .signed_gt, .signed_gte => matcher.value == .signed and
            (matcher.field.value_kind == .signed or matcher.field.value_kind == .any),
        .unsigned_eq, .unsigned_lt, .unsigned_lte, .unsigned_gt, .unsigned_gte => matcher.value == .unsigned and
            (matcher.field.value_kind == .unsigned or matcher.field.value_kind == .any),
        .float_eq, .float_lt, .float_lte, .float_gt, .float_gte => matcher.value == .float and
            (matcher.field.value_kind == .float or matcher.field.value_kind == .any),
        .boolean_eq => matcher.value == .boolean and
            (matcher.field.value_kind == .boolean or matcher.field.value_kind == .any),
    };
    if (!valid) return error.InvalidMatcher;
}

fn validateAction(action: ActionSpec) CompileError!void {
    if (action.value.len > std.math.maxInt(u32)) return error.InvalidPolicy;
    const needs_field = action.opcode != .extension;
    if (needs_field != (action.field != null)) return error.InvalidPolicy;
    if (action.field) |field| {
        if (field.name.len == 0 or field.name.len > std.math.maxInt(u32)) return error.InvalidPolicy;
    }
}

fn matcherString(value: MatchValue) []const u8 {
    return switch (value) {
        .string => |bytes| bytes,
        .float => |bytes| bytes,
        else => "",
    };
}

fn samplingThreshold(percentage: f32) u64 {
    const range: u64 = @as(u64, 1) << 56;
    if (percentage >= 100.0) return 0;
    if (percentage <= 0.0) return range;
    const ratio = 1.0 - (@as(f64, percentage) / 100.0);
    return @intFromFloat(ratio * @as(f64, @floatFromInt(range)));
}

fn encodeMatchValue(output: []u8, strings_offset: u32, cursor: *u32, value: MatchValue) CompileError!EncodedValue {
    return switch (value) {
        .none => .{},
        .string => |bytes| blk: {
            const offset = cursor.*;
            copyString(output, strings_offset, cursor, bytes);
            break :blk .{ .offset = offset, .len = @intCast(bytes.len) };
        },
        .signed => |number| .{
            .lo = if (number >= 0) @intCast(number) else @as(u64, @intCast(-(number + 1))) + 1,
            .hi = @intFromBool(number < 0),
        },
        .unsigned => |number| .{ .lo = number },
        .float => |bytes| blk: {
            _ = std.fmt.parseFloat(f64, bytes) catch return error.InvalidMatcher;
            const offset = cursor.*;
            copyString(output, strings_offset, cursor, bytes);
            break :blk .{ .offset = offset, .len = @intCast(bytes.len) };
        },
        .boolean => |boolean| .{ .lo = @intFromBool(boolean) },
    };
}

fn internField(compiler: *Compiler, fields: []FieldScratch, count: *u16, spec: FieldSpec) CompileError!u16 {
    if (findField(fields[0..count.*], spec)) |index| return index;
    if (count.* >= compiler.capacity.max_fields) {
        return compiler.fail(.fields, @as(u64, count.*) + 1, compiler.capacity.max_fields, error.TooManyFields);
    }
    fields[count.*] = .{ .spec = spec };
    count.* += 1;
    return count.* - 1;
}

fn findField(fields: []const FieldScratch, spec: FieldSpec) ?u16 {
    for (fields, 0..) |field, index| {
        if (field.spec.signal == spec.signal and
            field.spec.value_kind == spec.value_kind and
            field.spec.selector_id == spec.selector_id and
            std.mem.eql(u8, field.spec.name, spec.name)) return @intCast(index);
    }
    return null;
}

fn copyString(output: []u8, strings_offset: u32, cursor: *u32, value: []const u8) void {
    const start = @as(usize, strings_offset) + cursor.*;
    @memcpy(output[start..][0..value.len], value);
    cursor.* += @intCast(value.len);
}

fn testCapacity() Capacity {
    return .{
        .max_connections = 4,
        .worker_count = 2,
        .max_policies = 8,
        .max_fields = 8,
        .max_matchers = 16,
        .max_actions = 8,
        .max_image_bytes = 4096,
        .max_record_bytes = 4096,
        .max_context_bytes = 1024,
        .max_group_bytes = 256,
        .journal_events_per_worker = 64,
        .extension_queue_bytes = 1024,
    };
}

test "compiler writes deterministic bounded images" {
    const field: FieldSpec = .{ .signal = .log, .value_kind = .string, .selector_id = 1, .name = "body" };
    const matchers = [_]MatcherSpec{.{ .field = field, .opcode = .prefix, .value = .{ .string = "secret" } }};
    const policies = [_]PolicySpec{.{ .id = "drop-secret", .verdict = .drop, .matchers = &matchers }};
    var workspace: [1024]u8 = undefined;
    var destination: [4096]u8 = undefined;
    var compiler = try Compiler.init(testCapacity(), &workspace, &destination);
    const first = try compiler.compile(.{ .policies = &policies, .seed = 42 });
    var first_copy: [4096]u8 = undefined;
    @memcpy(first_copy[0..first.len], first);
    const second = try compiler.compile(.{ .policies = &policies, .seed = 42 });
    try std.testing.expectEqualSlices(u8, first_copy[0..first.len], second);
}

test "compiler reports exact exhausted capacity" {
    const field: FieldSpec = .{ .signal = .log, .value_kind = .string, .selector_id = 1, .name = "body" };
    const matchers = [_]MatcherSpec{.{ .field = field, .opcode = .exists }};
    const policies = [_]PolicySpec{
        .{ .id = "one", .verdict = .keep, .matchers = &matchers },
        .{ .id = "two", .verdict = .drop, .matchers = &matchers },
    };
    var capacity = testCapacity();
    capacity.max_policies = 1;
    var workspace: [1024]u8 = undefined;
    var destination: [4096]u8 = undefined;
    var compiler = try Compiler.init(capacity, &workspace, &destination);
    try std.testing.expectError(error.TooManyPolicies, compiler.compile(.{ .policies = &policies, .seed = 0 }));
    try std.testing.expectEqual(Section.policies, compiler.failure.?.section);
    try std.testing.expectEqual(@as(u64, 2), compiler.failure.?.required);
}
