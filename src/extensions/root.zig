//! Policy extensions (spec v1.6.0): concrete extension handlers and the
//! adapters that plug them into policy_zig's resolver/sink seams.
//!
//! Handlers are a tagged union, not a vtable (see Claude.md "Encoding Instead
//! of Polymorphism") — extension types are a closed set the implementation
//! must declare anyway (spec rule 4). Adding a type = one enum tag + one
//! union arm; the compiler enforces exhaustiveness everywhere.

const std = @import("std");
const policy = @import("policy_zig");
const proto = @import("proto");

const s3_dump_mod = @import("./s3_dump.zig");
pub const S3Dump = s3_dump_mod.S3Dump;
pub const EncodeFn = s3_dump_mod.EncodeFn;
pub const TeroS3DumpTag = "com.usetero/s3-dump";

pub const ExtensionTag = enum(u8) {
    s3_dump,

    pub fn typeId(tag: ExtensionTag) []const u8 {
        return switch (tag) {
            .s3_dump => TeroS3DumpTag,
        };
    }

    /// Highest supported major version per type (semver gate: an extension
    /// declaring a different major is unsupported).
    pub fn supportedMajor(tag: ExtensionTag) usize {
        return switch (tag) {
            .s3_dump => 1,
        };
    }

    fn fromTypeId(type_id: []const u8) ?ExtensionTag {
        inline for (comptime std.enums.values(ExtensionTag)) |tag| {
            if (std.mem.eql(u8, type_id, comptime tag.typeId())) return tag;
        }
        return null;
    }
};

pub const ExtensionHandler = union(ExtensionTag) {
    s3_dump: S3Dump,

    pub fn deinit(self: *ExtensionHandler) void {
        switch (self.*) {
            .s3_dump => |*h| h.deinit(),
        }
    }
};

/// Owns the enabled handlers and adapts them to policy_zig's fn-pointer
/// seams (`ExtensionResolver` at snapshot compile time, `ExtensionSink` at
/// evaluate time). Encoders are wired per signal at construction because the
/// record types behind `*const anyopaque` are the consumer's.
///
/// Usage:
///   var exts = Extensions.init(allocator, .{ .log = encodeLog });
///   defer exts.deinit();
///   const s3 = exts.enableS3Dump(allocator, .{}, creds);
///   try s3.addTarget(io, "eu-bucket", target_json);
///   exts.register(&registry);              // resolver + sync hooks, once
///   try registry.subscribe(.{ .http = http_provider }); // hooks auto-pushed
///   // per evaluate call: .{ .io = io, .extension_sink = exts.sink() }
///   // periodically: exts.flush(io, .{});
pub const Extensions = struct {
    pub const Encoders = struct {
        log: ?EncodeFn = null,
        metric: ?EncodeFn = null,
        trace: ?EncodeFn = null,
    };

    allocator: std.mem.Allocator,
    handlers: std.EnumArray(ExtensionTag, ?ExtensionHandler),
    encoders: Encoders,

    pub fn init(allocator: std.mem.Allocator, encoders: Encoders) Extensions {
        return .{
            .allocator = allocator,
            .handlers = .initFill(null),
            .encoders = encoders,
        };
    }

    pub fn deinit(self: *Extensions) void {
        defer self.* = undefined;
        var it = self.handlers.iterator();
        while (it.next()) |entry| {
            if (entry.value.*) |*handler| handler.deinit();
        }
    }

    /// Enable a handler. Takes ownership; replaces (and deinits) any handler
    /// already enabled for the same tag.
    pub fn enable(self: *Extensions, handler: ExtensionHandler) void {
        const tag = std.meta.activeTag(handler);
        if (self.handlers.getPtr(tag).*) |*old| old.deinit();
        self.handlers.set(tag, handler);
    }

    /// Enable the s3-dump handler, constructing it directly in place, and
    /// return a stable pointer so targets are configured on the handler
    /// itself — no move, no `s3Dump().?` reach-back:
    ///   const s3 = exts.enableS3Dump(allocator, .{}, creds);
    ///   try s3.addTarget(io, "eu-bucket", target_json);
    /// The pointer is valid for the life of this `Extensions` (don't move it).
    pub fn enableS3Dump(
        self: *Extensions,
        allocator: std.mem.Allocator,
        options: S3Dump.Options,
        credentials: ?S3Dump.Credentials,
    ) *S3Dump {
        self.enable(.{ .s3_dump = S3Dump.init(allocator, options, credentials) });
        return self.s3Dump().?;
    }

    pub fn s3Dump(self: *Extensions) ?*S3Dump {
        if (self.handlers.getPtr(.s3_dump).*) |*handler| return &handler.s3_dump;
        return null;
    }

    /// Wire this Extensions into a registry in one call: the resolver (used
    /// at snapshot compile) and the sync hooks (pushed to providers on
    /// subscribe). Call before `registry.subscribe(...)`. The per-evaluate
    /// `sink()` and the background `flush()` are still the consumer's to wire.
    pub fn register(self: *Extensions, reg: *policy.Registry) void {
        reg.setExtensionResolver(self.resolver());
        reg.setExtensionSyncHooks(self.syncHooks());
    }

    // =========================================================================
    // policy_zig seams
    // =========================================================================

    pub fn resolver(self: *Extensions) policy.ExtensionResolver {
        return .{ .ctx = self, .resolve = resolveFn };
    }

    pub fn sink(self: *Extensions) policy.ExtensionSink {
        return .{ .ctx = self, .deliver = deliverFn };
    }

    fn resolveFn(
        io: std.Io,
        ctx: *anyopaque,
        signal: policy.TelemetryType,
        policy_id: []const u8,
        extension: *const proto.policy.Extension,
    ) ?policy.ExtensionResolution {
        const self: *Extensions = @ptrCast(@alignCast(ctx));
        const tag = ExtensionTag.fromTypeId(extension.type) orelse return null;
        const version = std.SemanticVersion.parse(extension.version) catch return null;
        if (version.major != tag.supportedMajor()) return null;

        switch (tag) {
            .s3_dump => {
                const handler = self.s3Dump() orelse return null;
                const slot = handler.resolve(io, signal, policy_id, extension.config) orelse return null;
                return .{ .handler = @intFromEnum(tag), .slot = slot };
            },
        }
    }

    fn deliverFn(
        ctx: *anyopaque,
        io: ?std.Io,
        signal: policy.TelemetryType,
        record: *const anyopaque,
        binding: *const policy.ExtensionBinding,
        slice: policy.ExtensionSlice,
    ) void {
        _ = slice; // mode selection already applied by the engine
        const self: *Extensions = @ptrCast(@alignCast(ctx));
        const encode = switch (signal) {
            .log => self.encoders.log,
            .metric => self.encoders.metric,
            .trace => self.encoders.trace,
        } orelse return;
        const tag = std.enums.fromInt(ExtensionTag, binding.handler) orelse return;
        switch (tag) {
            .s3_dump => if (self.s3Dump()) |handler| {
                handler.deliver(io, binding.slot, record, encode);
            },
        }
    }

    // =========================================================================
    // Sync plumbing helpers
    // =========================================================================

    /// Adapter for HttpProvider.setExtensionSyncHooks: advertises
    /// capabilities in sync requests and routes broadcast extension configs
    /// from sync responses.
    pub fn syncHooks(self: *Extensions) policy.ExtensionSyncHooks {
        return .{
            .ctx = self,
            .capabilities = capabilitiesHook,
            .apply_configs = applyConfigsHook,
        };
    }

    fn capabilitiesHook(
        io: std.Io,
        ctx: *anyopaque,
        arena: std.mem.Allocator,
    ) anyerror![]proto.policy.ExtensionCapability {
        const self: *Extensions = @ptrCast(@alignCast(ctx));
        return self.supportedExtensions(io, arena);
    }

    fn applyConfigsHook(
        io: std.Io,
        ctx: *anyopaque,
        configs: []const proto.policy.ExtensionConfig,
    ) void {
        const self: *Extensions = @ptrCast(@alignCast(ctx));
        self.applyExtensionConfigs(io, configs);
    }

    /// Route `SyncResponse.extension_configs` entries to their handlers.
    pub fn applyExtensionConfigs(self: *Extensions, io: std.Io, configs: []const proto.policy.ExtensionConfig) void {
        for (configs) |config| {
            const tag = ExtensionTag.fromTypeId(config.type) orelse continue;
            switch (tag) {
                .s3_dump => if (self.s3Dump()) |handler| {
                    handler.configure(io, config.config.items);
                },
            }
        }
    }

    /// Build `ClientMetadata.supported_extensions` for the enabled handlers.
    /// All memory (including descriptor bytes) is allocated with `arena` —
    /// pass an arena allocator and free it wholesale.
    pub fn supportedExtensions(self: *Extensions, io: std.Io, arena: std.mem.Allocator) ![]proto.policy.ExtensionCapability {
        var out: std.ArrayList(proto.policy.ExtensionCapability) = .empty;
        var it = self.handlers.iterator();
        while (it.next()) |entry| {
            if (entry.value.* == null) continue;
            const descriptors: []const []const u8 = switch (entry.key) {
                .s3_dump => try self.s3Dump().?.capabilities(io, arena),
            };
            var config_list: std.ArrayList([]const u8) = .empty;
            try config_list.appendSlice(arena, descriptors);
            try out.append(arena, .{
                .type = entry.key.typeId(),
                .min_version = "1.0.0",
                .config = config_list,
            });
        }
        return out.toOwnedSlice(arena);
    }

    /// Flush all handlers that buffer for upload. Forward to the consumer's
    /// background loop.
    pub fn flush(self: *Extensions, io: std.Io, opts: S3Dump.FlushOptions) S3Dump.FlushResult {
        if (self.s3Dump()) |handler| return handler.flush(io, opts);
        return .{};
    }
};

test {
    _ = @import("./s3_dump.zig");
    _ = @import("./s3_stub_test.zig");
}

// =============================================================================
// Integration test: engine → resolver → sink → batch
// =============================================================================

const testing = std.testing;
const test_io = std.Options.debug_io;

const TestLogRecord = struct {
    body: []const u8,

    fn typedValue(ctx: *const anyopaque, field: policy.FieldRef) ?policy.TypedValue {
        const self: *const TestLogRecord = @ptrCast(@alignCast(ctx));
        return switch (field) {
            .log_field => |lf| if (lf == .LOG_FIELD_BODY) .{ .string = self.body } else null,
            else => null,
        };
    }

    const accessor: policy.LogAccessor = .{ .typed_value = typedValue };

    fn encode(record: *const anyopaque, writer: *std.Io.Writer) anyerror!void {
        const self: *const TestLogRecord = @ptrCast(@alignCast(record));
        try writer.print("{{\"body\":\"{s}\"}}", .{self.body});
    }
};

fn encodeTargetRefAlloc(allocator: std.mem.Allocator, kind: []const u8, name: []const u8) ![]u8 {
    var aw = std.Io.Writer.Allocating.init(allocator);
    errdefer aw.deinit();
    const ref: proto.policy.ExtensionTargetRef = .{ .kind = kind, .name = name };
    try ref.encode(&aw.writer, allocator);
    var list = aw.toArrayList();
    return list.toOwnedSlice(allocator);
}

test "end to end: dropped records land in the s3-dump batch as ndjson" {
    const allocator = testing.allocator;
    const o11y = policy.observability;

    var exts = Extensions.init(allocator, .{ .log = TestLogRecord.encode });
    defer exts.deinit();
    // Configure the target directly on the handler pointer — no reach-back.
    const s3 = exts.enableS3Dump(allocator, .{}, null);
    try s3.addTarget(
        test_io,
        "eu-bucket",
        \\{"bucket": "waste", "region": "eu-west-1"}
        ,
    );

    // Policy: drop payment logs, dump the waste to eu-bucket.
    const ref_bytes = try encodeTargetRefAlloc(allocator, "s3", "eu-bucket");
    defer allocator.free(ref_bytes);
    var pol: proto.policy.Policy = .{
        .id = try allocator.dupe(u8, "drop-payments"),
        .name = try allocator.dupe(u8, "drop-payments"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try pol.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "payment") },
    });
    try pol.extensions.append(allocator, .{
        .type = try allocator.dupe(u8, "com.usetero/s3-dump"),
        .version = try allocator.dupe(u8, "1.0.0"),
        .config = try allocator.dupe(u8, ref_bytes),
        .mode = .EXTENSION_MODE_DROPPED,
    });
    defer pol.deinit(allocator);

    var noop_bus: o11y.NoopEventBus = undefined;
    noop_bus.init(test_io);
    var registry = policy.Registry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    exts.register(&registry); // resolver + sync hooks in one call
    try registry.updatePolicies(&.{pol}, "test", .file);

    const engine = policy.PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    var dropped_record: TestLogRecord = .{ .body = "payment failed" };
    const r1 = engine.evaluate(.log, &TestLogRecord.accessor, &dropped_record, &policy_id_buf, .{
        .io = test_io,
        .extension_sink = exts.sink(),
    });
    try testing.expectEqual(policy.FilterDecision.drop, r1.decision);

    var kept_record: TestLogRecord = .{ .body = "healthcheck" };
    _ = engine.evaluate(.log, &TestLogRecord.accessor, &kept_record, &policy_id_buf, .{
        .io = test_io,
        .extension_sink = exts.sink(),
    });

    // Only the dropped record was batched, encoded by the consumer encoder.
    const dump = exts.s3Dump().?;
    try testing.expectEqual(@as(usize, 1), dump.batches.items.len);
    try testing.expectEqualStrings(
        "{\"body\":\"payment failed\"}\n",
        dump.batches.items[0].buf.items,
    );

    // Capability advertisement covers the configured target.
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const caps = try exts.supportedExtensions(test_io, arena.allocator());
    try testing.expectEqual(@as(usize, 1), caps.len);
    try testing.expectEqualStrings(TeroS3DumpTag, caps[0].type);
    try testing.expectEqual(@as(usize, 1), caps[0].config.items.len);
}

test "Extensions: applyExtensionConfigs routes broadcast targets by type" {
    const allocator = testing.allocator;
    var exts = Extensions.init(allocator, .{});
    defer exts.deinit();
    exts.enable(.{ .s3_dump = S3Dump.init(allocator, .{}, null) });

    var aw = std.Io.Writer.Allocating.init(allocator);
    defer aw.deinit();
    const target: proto.policy.ExtensionTarget = .{
        .kind = "s3",
        .name = "bcast-bucket",
        .config = "{\"bucket\": \"waste\"}",
    };
    try target.encode(&aw.writer, allocator);
    var list = aw.toArrayList();
    const target_bytes = try list.toOwnedSlice(allocator);
    defer allocator.free(target_bytes);

    var entries: std.ArrayList([]const u8) = .empty;
    defer entries.deinit(allocator);
    try entries.append(allocator, target_bytes);

    // A config for an unknown type is ignored; the s3-dump one lands.
    const configs = [_]proto.policy.ExtensionConfig{
        .{ .type = "vendor/unknown", .config = entries },
        .{ .type = TeroS3DumpTag, .config = entries },
    };
    exts.applyExtensionConfigs(test_io, &configs);

    try testing.expectEqual(@as(usize, 1), exts.s3Dump().?.targets.items.len);
    try testing.expectEqualStrings("bcast-bucket", exts.s3Dump().?.targets.items[0].name);
}

test "Extensions.register wires resolver + sync hooks; subscribe pushes hooks per provider" {
    const allocator = testing.allocator;
    const o11y = policy.observability;

    var exts = Extensions.init(allocator, .{ .log = TestLogRecord.encode });
    defer exts.deinit();
    _ = exts.enableS3Dump(allocator, .{}, null);

    var noop_bus: o11y.NoopEventBus = undefined;
    noop_bus.init(test_io);
    var registry = policy.Registry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // One call wires both seams onto the registry.
    exts.register(&registry);
    try testing.expect(registry.extension_resolver != null);
    try testing.expect(registry.extension_sync_hooks != null);

    // A file provider accepts the hooks and ignores them (no control plane):
    // the union dispatch must not crash and leaves nothing to observe.
    const file_provider = try policy.FileProvider.init(allocator, test_io, noop_bus.eventBus(), .{
        .id = "local",
        .path = "does-not-exist.json",
    });
    defer file_provider.deinit();
    const file_prov: policy.Provider = .{ .file = file_provider };
    file_prov.setExtensionSyncHooks(registry.extension_sync_hooks.?);

    // An HTTP provider actually stores them — this is what `subscribe` pushes.
    const http_provider = try policy.HttpProvider.init(allocator, test_io, noop_bus.eventBus(), .{
        .id = "control-plane",
        .url = "http://127.0.0.1:1/policies",
    });
    defer http_provider.deinit();
    try testing.expect(http_provider.extension_hooks == null);
    const http_prov: policy.Provider = .{ .http = http_provider };
    http_prov.setExtensionSyncHooks(registry.extension_sync_hooks.?);
    try testing.expect(http_provider.extension_hooks != null);
}
