//! Immutable, relocatable policy image and explicit wire encoding.
//!
//! The byte region is the source of truth. Accessors decode little-endian
//! fields rather than casting bytes to structs, keeping the persisted ABI
//! independent of Zig layout and `@bitCast` behavior.

const std = @import("std");

pub const magic: u32 = 0x594c4f50; // "POLY" as little-endian bytes.
pub const abi_version: u16 = 2;
pub const header_bytes: u32 = 96;
pub const field_bytes: u32 = 16;
pub const policy_bytes: u32 = 48;
pub const matcher_bytes: u32 = 40;
pub const action_bytes: u32 = 16;
pub const hash_offset: usize = 64;
pub const hash_bytes: usize = 32;

pub const Signal = enum(u8) {
    log = 0,
    metric = 1,
    trace = 2,
};

pub const ValueKind = enum(u8) {
    any = 0,
    string = 1,
    bytes = 2,
    signed = 3,
    unsigned = 4,
    float = 5,
    boolean = 6,
};

pub const MatchOpcode = enum(u8) {
    exists = 0,
    exact = 1,
    prefix = 2,
    suffix = 3,
    contains = 4,
    regex = 5,
    signed_eq = 6,
    signed_lt = 7,
    signed_lte = 8,
    signed_gt = 9,
    signed_gte = 10,
    unsigned_eq = 11,
    unsigned_lt = 12,
    unsigned_lte = 13,
    unsigned_gt = 14,
    unsigned_gte = 15,
    float_eq = 16,
    float_lt = 17,
    float_lte = 18,
    float_gt = 19,
    float_gte = 20,
    boolean_eq = 21,
};

pub const ActionOpcode = enum(u8) {
    remove = 0,
    redact = 1,
    rename = 2,
    add = 3,
    extension = 4,
};

pub const Verdict = enum(u8) {
    unset = 0,
    keep = 1,
    drop = 2,
};

pub const SamplingMode = enum(u8) {
    hash_seed = 1,
    proportional = 2,
    equalizing = 3,
};

pub const Header = struct {
    flags: u16,
    image_bytes: u32,
    policy_count: u16,
    field_count: u16,
    matcher_count: u32,
    action_count: u32,
    fields_offset: u32,
    policies_offset: u32,
    matchers_offset: u32,
    actions_offset: u32,
    strings_offset: u32,
    strings_bytes: u32,
    seed: u64,
    image_hash: [hash_bytes]u8,
};

pub const PolicyImageHeader = Header;

pub const Field = struct {
    signal: Signal = .log,
    value_kind: ValueKind,
    selector_id: u32,
    name_offset: u32,
    name_len: u32,
};

pub const Policy = struct {
    signal: Signal = .log,
    required_matches: u16,
    verdict: Verdict,
    flags: u8,
    priority: i32,
    matcher_start: u32,
    matcher_count: u32,
    action_start: u32,
    action_count: u32,
    sampling_mode: SamplingMode,
    sampling_precision: u8,
    sampling_enabled: bool,
    sampling_fail_closed: bool,
    rate_limit_per_second: u32,
    sampling_threshold: u64,
    sampling_hash_seed: u32,
    rate_window_seconds: u32 = 1,
};

pub const Matcher = struct {
    field_index: u16,
    opcode: MatchOpcode,
    flags: u8,
    policy_index: u16,
    constant_offset: u32,
    constant_len: u32,
    value_lo: u64,
    value_hi: u64,
    stable_hash: u64,

    pub fn negated(self: Matcher) bool {
        return self.flags & 1 != 0;
    }

    pub fn caseInsensitive(self: Matcher) bool {
        return self.flags & 2 != 0;
    }
};

pub const Action = struct {
    opcode: ActionOpcode,
    flags: u8,
    field_index: u16,
    value_offset: u32,
    value_len: u32,
    binding_id: u32,
};

pub const ValidationError = error{
    Truncated,
    BadMagic,
    UnsupportedAbi,
    BadImageSize,
    BadSection,
    BadEnum,
    BadReference,
    BadHash,
    BadSampling,
    PolicyMatcherMismatch,
};

/// A validated view over one caller-owned immutable byte region.
pub const PolicyImage = struct {
    bytes: []const u8,
    header: Header,

    pub fn open(bytes: []const u8) ValidationError!PolicyImage {
        if (bytes.len < header_bytes) return error.Truncated;
        if (readU32(bytes, 0) != magic) return error.BadMagic;
        if (readU16(bytes, 4) != abi_version) return error.UnsupportedAbi;

        const header: Header = .{
            .flags = readU16(bytes, 6),
            .image_bytes = readU32(bytes, 8),
            .policy_count = readU16(bytes, 12),
            .field_count = readU16(bytes, 14),
            .matcher_count = readU32(bytes, 16),
            .action_count = readU32(bytes, 20),
            .fields_offset = readU32(bytes, 24),
            .policies_offset = readU32(bytes, 28),
            .matchers_offset = readU32(bytes, 32),
            .actions_offset = readU32(bytes, 36),
            .strings_offset = readU32(bytes, 40),
            .strings_bytes = readU32(bytes, 44),
            .seed = readU64(bytes, 48),
            .image_hash = bytes[hash_offset..][0..hash_bytes].*,
        };
        if (header.image_bytes != bytes.len) return error.BadImageSize;
        try validateSection(bytes.len, header.fields_offset, header.field_count, field_bytes);
        try validateSection(bytes.len, header.policies_offset, header.policy_count, policy_bytes);
        try validateSection(bytes.len, header.matchers_offset, header.matcher_count, matcher_bytes);
        try validateSection(bytes.len, header.actions_offset, header.action_count, action_bytes);
        try validateSection(bytes.len, header.strings_offset, header.strings_bytes, 1);
        const expected_policies = header.fields_offset + @as(u64, header.field_count) * field_bytes;
        const expected_matchers = expected_policies + @as(u64, header.policy_count) * policy_bytes;
        const expected_actions = expected_matchers + @as(u64, header.matcher_count) * matcher_bytes;
        const expected_strings = expected_actions + @as(u64, header.action_count) * action_bytes;
        const expected_end = expected_strings + header.strings_bytes;
        if (header.fields_offset != header_bytes or
            header.policies_offset != expected_policies or
            header.matchers_offset != expected_matchers or
            header.actions_offset != expected_actions or
            header.strings_offset != expected_strings or
            header.image_bytes != expected_end)
        {
            return error.BadSection;
        }

        var actual: [hash_bytes]u8 = undefined;
        hashImage(bytes, &actual);
        if (!std.mem.eql(u8, &actual, &header.image_hash)) return error.BadHash;

        const image: PolicyImage = .{ .bytes = bytes, .header = header };
        try image.validateReferences();
        return image;
    }

    pub fn identity(self: PolicyImage) [hash_bytes]u8 {
        return self.header.image_hash;
    }

    pub fn field(self: PolicyImage, index: u16) ValidationError!Field {
        if (index >= self.header.field_count) return error.BadReference;
        const offset = @as(usize, self.header.fields_offset) + @as(usize, index) * field_bytes;
        return .{
            .signal = std.enums.fromInt(Signal, self.bytes[offset]) orelse return error.BadEnum,
            .value_kind = std.enums.fromInt(ValueKind, self.bytes[offset + 1]) orelse return error.BadEnum,
            .selector_id = readU32(self.bytes, offset + 4),
            .name_offset = readU32(self.bytes, offset + 8),
            .name_len = readU32(self.bytes, offset + 12),
        };
    }

    pub fn fieldName(self: PolicyImage, index: u16) ValidationError![]const u8 {
        const item = try self.field(index);
        return self.string(item.name_offset, item.name_len);
    }

    pub fn policy(self: PolicyImage, index: u16) ValidationError!Policy {
        if (index >= self.header.policy_count) return error.BadReference;
        const offset = @as(usize, self.header.policies_offset) + @as(usize, index) * policy_bytes;
        return .{
            .signal = std.enums.fromInt(Signal, self.bytes[offset + 27]) orelse return error.BadEnum,
            .required_matches = readU16(self.bytes, offset),
            .verdict = std.enums.fromInt(Verdict, self.bytes[offset + 2]) orelse return error.BadEnum,
            .flags = self.bytes[offset + 3],
            .priority = decodeI32(readU32(self.bytes, offset + 4)),
            .matcher_start = readU32(self.bytes, offset + 8),
            .matcher_count = readU32(self.bytes, offset + 12),
            .action_start = readU32(self.bytes, offset + 16),
            .action_count = readU32(self.bytes, offset + 20),
            .sampling_mode = std.enums.fromInt(SamplingMode, self.bytes[offset + 24]) orelse return error.BadEnum,
            .sampling_precision = self.bytes[offset + 25],
            .sampling_enabled = self.bytes[offset + 26] & 1 != 0,
            .sampling_fail_closed = self.bytes[offset + 26] & 2 != 0,
            .rate_limit_per_second = readU32(self.bytes, offset + 28),
            .sampling_threshold = readU64(self.bytes, offset + 32),
            .sampling_hash_seed = readU32(self.bytes, offset + 40),
            .rate_window_seconds = readU32(self.bytes, offset + 44),
        };
    }

    pub fn matcher(self: PolicyImage, index: u32) ValidationError!Matcher {
        if (index >= self.header.matcher_count) return error.BadReference;
        const offset = @as(usize, self.header.matchers_offset) + @as(usize, index) * matcher_bytes;
        return .{
            .field_index = readU16(self.bytes, offset),
            .opcode = std.enums.fromInt(MatchOpcode, self.bytes[offset + 2]) orelse return error.BadEnum,
            .flags = self.bytes[offset + 3],
            .policy_index = readU16(self.bytes, offset + 4),
            .constant_offset = readU32(self.bytes, offset + 8),
            .constant_len = readU32(self.bytes, offset + 12),
            .value_lo = readU64(self.bytes, offset + 16),
            .value_hi = readU64(self.bytes, offset + 24),
            .stable_hash = readU64(self.bytes, offset + 32),
        };
    }

    pub fn matcherConstant(self: PolicyImage, index: u32) ValidationError![]const u8 {
        const item = try self.matcher(index);
        return self.string(item.constant_offset, item.constant_len);
    }

    pub fn action(self: PolicyImage, index: u32) ValidationError!Action {
        if (index >= self.header.action_count) return error.BadReference;
        const offset = @as(usize, self.header.actions_offset) + @as(usize, index) * action_bytes;
        return .{
            .opcode = std.enums.fromInt(ActionOpcode, self.bytes[offset]) orelse return error.BadEnum,
            .flags = self.bytes[offset + 1],
            .field_index = readU16(self.bytes, offset + 2),
            .value_offset = readU32(self.bytes, offset + 4),
            .value_len = readU32(self.bytes, offset + 8),
            .binding_id = readU32(self.bytes, offset + 12),
        };
    }

    pub fn actionValue(self: PolicyImage, index: u32) ValidationError![]const u8 {
        const item = try self.action(index);
        return self.string(item.value_offset, item.value_len);
    }

    pub fn string(self: PolicyImage, relative_offset: u32, len: u32) ValidationError![]const u8 {
        const start = std.math.add(u32, self.header.strings_offset, relative_offset) catch return error.BadReference;
        const end = std.math.add(u32, start, len) catch return error.BadReference;
        const strings_end = std.math.add(
            u32,
            self.header.strings_offset,
            self.header.strings_bytes,
        ) catch return error.BadReference;
        if (end > strings_end or end > self.bytes.len) return error.BadReference;
        return self.bytes[start..end];
    }

    fn validateReferences(self: PolicyImage) ValidationError!void {
        for (0..self.header.field_count) |i| _ = try self.fieldName(@intCast(i));
        for (0..self.header.policy_count) |i| {
            const item = try self.policy(@intCast(i));
            if (item.matcher_start +| item.matcher_count > self.header.matcher_count) return error.BadReference;
            if (item.action_start +| item.action_count > self.header.action_count) return error.BadReference;
            if (item.required_matches > item.matcher_count) return error.PolicyMatcherMismatch;
            if (item.sampling_enabled and
                (item.sampling_precision < 1 or
                    item.sampling_precision > 14 or
                    item.sampling_threshold > (@as(u64, 1) << 56))) return error.BadSampling;
        }
        for (0..self.header.matcher_count) |i| {
            const item = try self.matcher(@intCast(i));
            if (item.field_index >= self.header.field_count or
                item.policy_index >= self.header.policy_count) return error.BadReference;
            _ = try self.matcherConstant(@intCast(i));
        }
        for (0..self.header.action_count) |i| {
            const item = try self.action(@intCast(i));
            if (item.field_index != std.math.maxInt(u16) and
                item.field_index >= self.header.field_count) return error.BadReference;
            _ = try self.actionValue(@intCast(i));
        }
    }
};

pub fn writeHeader(bytes: []u8, header: Header) void {
    std.debug.assert(bytes.len >= header_bytes);
    @memset(bytes[0..header_bytes], 0);
    writeU32(bytes, 0, magic);
    writeU16(bytes, 4, abi_version);
    writeU16(bytes, 6, header.flags);
    writeU32(bytes, 8, header.image_bytes);
    writeU16(bytes, 12, header.policy_count);
    writeU16(bytes, 14, header.field_count);
    writeU32(bytes, 16, header.matcher_count);
    writeU32(bytes, 20, header.action_count);
    writeU32(bytes, 24, header.fields_offset);
    writeU32(bytes, 28, header.policies_offset);
    writeU32(bytes, 32, header.matchers_offset);
    writeU32(bytes, 36, header.actions_offset);
    writeU32(bytes, 40, header.strings_offset);
    writeU32(bytes, 44, header.strings_bytes);
    writeU64(bytes, 48, header.seed);
    @memcpy(bytes[hash_offset..][0..hash_bytes], &header.image_hash);
}

pub fn seal(bytes: []u8) void {
    @memset(bytes[hash_offset..][0..hash_bytes], 0);
    var digest: [hash_bytes]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    @memcpy(bytes[hash_offset..][0..hash_bytes], &digest);
}

pub fn writeField(bytes: []u8, offset: usize, item: Field) void {
    @memset(bytes[offset..][0..field_bytes], 0);
    bytes[offset] = @intFromEnum(item.signal);
    bytes[offset + 1] = @intFromEnum(item.value_kind);
    writeU32(bytes, offset + 4, item.selector_id);
    writeU32(bytes, offset + 8, item.name_offset);
    writeU32(bytes, offset + 12, item.name_len);
}

pub fn writePolicy(bytes: []u8, offset: usize, item: Policy) void {
    @memset(bytes[offset..][0..policy_bytes], 0);
    writeU16(bytes, offset, item.required_matches);
    bytes[offset + 2] = @intFromEnum(item.verdict);
    bytes[offset + 3] = item.flags;
    writeU32(bytes, offset + 4, encodeI32(item.priority));
    writeU32(bytes, offset + 8, item.matcher_start);
    writeU32(bytes, offset + 12, item.matcher_count);
    writeU32(bytes, offset + 16, item.action_start);
    writeU32(bytes, offset + 20, item.action_count);
    bytes[offset + 24] = @intFromEnum(item.sampling_mode);
    bytes[offset + 25] = item.sampling_precision;
    bytes[offset + 26] = @intFromBool(item.sampling_enabled) |
        (@as(u8, @intFromBool(item.sampling_fail_closed)) << 1);
    bytes[offset + 27] = @intFromEnum(item.signal);
    writeU32(bytes, offset + 28, item.rate_limit_per_second);
    writeU64(bytes, offset + 32, item.sampling_threshold);
    writeU32(bytes, offset + 40, item.sampling_hash_seed);
    writeU32(bytes, offset + 44, item.rate_window_seconds);
}

pub fn writeMatcher(bytes: []u8, offset: usize, item: Matcher) void {
    @memset(bytes[offset..][0..matcher_bytes], 0);
    writeU16(bytes, offset, item.field_index);
    bytes[offset + 2] = @intFromEnum(item.opcode);
    bytes[offset + 3] = item.flags;
    writeU16(bytes, offset + 4, item.policy_index);
    writeU32(bytes, offset + 8, item.constant_offset);
    writeU32(bytes, offset + 12, item.constant_len);
    writeU64(bytes, offset + 16, item.value_lo);
    writeU64(bytes, offset + 24, item.value_hi);
    writeU64(bytes, offset + 32, item.stable_hash);
}

pub fn writeAction(bytes: []u8, offset: usize, item: Action) void {
    @memset(bytes[offset..][0..action_bytes], 0);
    bytes[offset] = @intFromEnum(item.opcode);
    bytes[offset + 1] = item.flags;
    writeU16(bytes, offset + 2, item.field_index);
    writeU32(bytes, offset + 4, item.value_offset);
    writeU32(bytes, offset + 8, item.value_len);
    writeU32(bytes, offset + 12, item.binding_id);
}

fn hashImage(bytes: []const u8, out: *[hash_bytes]u8) void {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(bytes[0..hash_offset]);
    hash.update(&([_]u8{0} ** hash_bytes));
    hash.update(bytes[hash_offset + hash_bytes ..]);
    hash.final(out);
}

fn validateSection(image_len: usize, offset: u32, count: anytype, stride: u32) ValidationError!void {
    const section_bytes = std.math.mul(u64, @as(u64, count), stride) catch return error.BadSection;
    const end = std.math.add(u64, offset, section_bytes) catch return error.BadSection;
    if (offset < header_bytes or end > image_len) return error.BadSection;
}

fn readU16(bytes: []const u8, offset: usize) u16 {
    return std.mem.readInt(u16, bytes[offset..][0..2], .little);
}

fn readU32(bytes: []const u8, offset: usize) u32 {
    return std.mem.readInt(u32, bytes[offset..][0..4], .little);
}

fn readU64(bytes: []const u8, offset: usize) u64 {
    return std.mem.readInt(u64, bytes[offset..][0..8], .little);
}

fn writeU16(bytes: []u8, offset: usize, value: u16) void {
    std.mem.writeInt(u16, bytes[offset..][0..2], value, .little);
}

fn writeU32(bytes: []u8, offset: usize, value: u32) void {
    std.mem.writeInt(u32, bytes[offset..][0..4], value, .little);
}

fn writeU64(bytes: []u8, offset: usize, value: u64) void {
    std.mem.writeInt(u64, bytes[offset..][0..8], value, .little);
}

fn encodeI32(value: i32) u32 {
    if (value >= 0) return @intCast(value);
    const magnitude: u32 = @intCast(-(value + 1));
    return std.math.maxInt(u32) - magnitude;
}

fn decodeI32(value: u32) i32 {
    if (value <= std.math.maxInt(i32)) return @intCast(value);
    const magnitude_minus_one = std.math.maxInt(u32) - value;
    return -@as(i32, @intCast(magnitude_minus_one)) - 1;
}

test "explicit image encoding is deterministic and detects corruption" {
    var bytes: [header_bytes + field_bytes + policy_bytes + matcher_bytes + 3]u8 = undefined;
    const header: Header = .{
        .flags = 0,
        .image_bytes = bytes.len,
        .policy_count = 1,
        .field_count = 1,
        .matcher_count = 1,
        .action_count = 0,
        .fields_offset = header_bytes,
        .policies_offset = header_bytes + field_bytes,
        .matchers_offset = header_bytes + field_bytes + policy_bytes,
        .actions_offset = header_bytes + field_bytes + policy_bytes + matcher_bytes,
        .strings_offset = header_bytes + field_bytes + policy_bytes + matcher_bytes,
        .strings_bytes = 3,
        .seed = 7,
        .image_hash = [_]u8{0} ** hash_bytes,
    };
    writeHeader(&bytes, header);
    writeField(&bytes, header.fields_offset, .{
        .signal = .log,
        .value_kind = .string,
        .selector_id = 1,
        .name_offset = 0,
        .name_len = 3,
    });
    writePolicy(&bytes, header.policies_offset, .{
        .required_matches = 1,
        .verdict = .drop,
        .flags = 0,
        .priority = 1,
        .matcher_start = 0,
        .matcher_count = 1,
        .action_start = 0,
        .action_count = 0,
        .sampling_mode = .hash_seed,
        .sampling_precision = 4,
        .sampling_enabled = false,
        .sampling_fail_closed = true,
        .rate_limit_per_second = 0,
        .sampling_threshold = 0,
        .sampling_hash_seed = 0,
    });
    writeMatcher(&bytes, header.matchers_offset, .{
        .field_index = 0,
        .opcode = .exists,
        .flags = 0,
        .policy_index = 0,
        .constant_offset = 0,
        .constant_len = 0,
        .value_lo = 0,
        .value_hi = 0,
        .stable_hash = 0,
    });
    @memcpy(bytes[header.strings_offset..], "msg");
    seal(&bytes);

    const image = try PolicyImage.open(&bytes);
    try std.testing.expectEqualStrings("msg", try image.fieldName(0));
    bytes[header.strings_offset] ^= 1;
    try std.testing.expectError(error.BadHash, PolicyImage.open(&bytes));
}

test "every single-byte image corruption is rejected" {
    var bytes: [header_bytes]u8 = undefined;
    writeHeader(&bytes, .{
        .flags = 0,
        .image_bytes = bytes.len,
        .policy_count = 0,
        .field_count = 0,
        .matcher_count = 0,
        .action_count = 0,
        .fields_offset = header_bytes,
        .policies_offset = header_bytes,
        .matchers_offset = header_bytes,
        .actions_offset = header_bytes,
        .strings_offset = header_bytes,
        .strings_bytes = 0,
        .seed = 1,
        .image_hash = [_]u8{0} ** hash_bytes,
    });
    seal(&bytes);
    _ = try PolicyImage.open(&bytes);
    for (0..bytes.len) |index| {
        const original = bytes[index];
        bytes[index] ^= 1;
        if (PolicyImage.open(&bytes)) |_| return error.TestExpectedError else |_| {}
        bytes[index] = original;
    }
}
