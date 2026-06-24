const std = @import("std");
const builtin = @import("builtin");
const proto = @import("proto");
const policy_provider = @import("./provider.zig");
const parser = @import("./parser.zig");
const o11y = @import("observability");

const Policy = proto.policy.Policy;
const PolicyCallback = policy_provider.PolicyCallback;
const EventBus = o11y.EventBus;

const Sha256 = std.crypto.hash.sha2.Sha256;

/// Default interval between file-change polls. Also bounds change-detection
/// latency: a modification is noticed within at most this long.
const default_poll_interval_ns: i96 = 1 * std.time.ns_per_s;

// =============================================================================
// Observability Events
// =============================================================================

const PoliciesLoading = struct { path: []const u8 };
const PoliciesLoaded = struct { count: usize, path: []const u8 };
const PoliciesUnchanged = struct { hash: []const u8 };
const FileWatcherError = struct { err: []const u8 };
const FileWatcherUnsupported = struct {};
const PolicyReloadFailed = struct { err: []const u8 };

/// File-based policy provider that watches a config file for changes
pub const FileProvider = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    /// Unique identifier for this provider
    id: []const u8,
    config_path: []const u8,
    callback: ?PolicyCallback,
    watch_thread: ?std.Thread,
    shutdown_event: std.Io.Event,
    /// SHA256 hash of the last loaded file contents
    content_hash: ?[Sha256.digest_length]u8,
    /// Event bus for observability
    bus: *EventBus,
    /// Interval between file-change polls, in nanoseconds.
    poll_interval_ns: i96,

    pub const Config = struct {
        id: []const u8,
        path: []const u8,
        /// Interval between file-change polls. Bounds change-detection latency.
        poll_interval_ns: i96 = default_poll_interval_ns,
    };

    pub fn init(allocator: std.mem.Allocator, io: std.Io, bus: *EventBus, config: Config) !*FileProvider {
        const self = try allocator.create(FileProvider);
        errdefer allocator.destroy(self);

        const id_copy = try allocator.dupe(u8, config.id);
        errdefer allocator.free(id_copy);

        const path_copy = try allocator.dupe(u8, config.path);
        errdefer allocator.free(path_copy);

        self.* = .{
            .allocator = allocator,
            .io = io,
            .id = id_copy,
            .config_path = path_copy,
            .callback = null,
            .watch_thread = null,
            .shutdown_event = .unset,
            .content_hash = null,
            .bus = bus,
            .poll_interval_ns = config.poll_interval_ns,
        };

        return self;
    }

    /// Get the unique identifier for this provider
    pub fn getId(self: *FileProvider) []const u8 {
        return self.id;
    }

    pub fn subscribe(self: *FileProvider, callback: PolicyCallback) !void {
        self.callback = callback;

        // Initial load and notify
        try self.loadAndNotify();

        // Start watching for changes
        self.watch_thread = try std.Thread.spawn(.{}, watchLoop, .{self});
    }

    pub fn shutdown(self: *FileProvider) void {
        self.shutdown_event.set(self.io);

        if (self.watch_thread) |thread| {
            thread.join();
            self.watch_thread = null;
        }
    }

    pub fn deinit(self: *FileProvider) void {
        const allocator = self.allocator;
        // LIFO defer order: self.* = undefined runs first (while memory is
        // still valid), then destroy frees it.
        defer allocator.destroy(self);
        defer self.* = undefined;

        // Ensure shutdown is called first
        self.shutdown();

        allocator.free(self.id);
        allocator.free(self.config_path);
    }

    fn loadAndNotify(self: *FileProvider) !void {
        const loading_event: PoliciesLoading = .{ .path = self.config_path };
        self.bus.info(loading_event);

        // Read file contents and compute hash
        const contents = try std.Io.Dir.cwd().readFileAlloc(
            self.io,
            self.config_path,
            self.allocator,
            .limited(10 * 1024 * 1024),
        );
        defer self.allocator.free(contents);

        var new_hash: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(contents, &new_hash, .{});

        // Check if content has changed
        if (self.content_hash) |old_hash| {
            if (std.mem.eql(u8, &old_hash, &new_hash)) {
                const unchanged_event: PoliciesUnchanged = .{ .hash = &new_hash };
                self.bus.debug(unchanged_event);
                return;
            }
        }

        // Update stored hash
        self.content_hash = new_hash;

        const policies = try parser.parsePoliciesBytes(self.allocator, contents);
        defer {
            // Registry duplicates policies, so we must free our parsed copies
            for (policies) |*policy| {
                @constCast(policy).deinit(self.allocator);
            }
            self.allocator.free(policies);
        }

        if (self.callback) |cb| {
            try cb.call(.{
                .policies = policies,
                .provider_id = self.id,
            });
        }

        const loaded_event: PoliciesLoaded = .{
            .count = policies.len,
            .path = self.config_path,
        };
        self.bus.info(loaded_event);
    }

    fn watchLoop(self: *FileProvider) void {
        if (builtin.os.tag == .linux or builtin.os.tag == .macos) {
            self.watchLoopPoll() catch |err| {
                const event: FileWatcherError = .{ .err = @errorName(err) };
                self.bus.err(event);
            };
        } else {
            const event: FileWatcherUnsupported = .{};
            self.bus.warn(event);
        }
    }

    fn watchLoopPoll(self: *FileProvider) !void {
        var last_mtime: i96 = 0;

        while (true) {
            // Park up to the poll interval, but wake instantly when shutdown()
            // sets the event. waitTimeout returns error.Timeout on interval
            // expiry (the normal poll case) or a spurious wakeup, and returns
            // void once the event is set; either way we recheck isSet() below.
            self.shutdown_event.waitTimeout(self.io, .{ .duration = .{
                .raw = .{ .nanoseconds = self.poll_interval_ns },
                .clock = .awake,
            } }) catch |err| switch (err) {
                // Expected: the interval elapsed (normal poll) or a spurious
                // wakeup occurred. Fall through to the isSet()/stat below.
                error.Timeout => {},
                else => {
                    const event: FileWatcherError = .{ .err = @errorName(err) };
                    self.bus.warn(event);
                },
            };
            if (self.shutdown_event.isSet()) break;

            const file = std.Io.Dir.cwd().openFile(self.io, self.config_path, .{}) catch continue;
            defer file.close(self.io);

            const stat = file.stat(self.io) catch continue;

            // Only attempt reload if mtime changed (optimization to avoid reading file every second)
            if (stat.mtime.nanoseconds != last_mtime) {
                last_mtime = stat.mtime.nanoseconds;
                // loadAndNotify will check content hash and skip if unchanged
                self.loadAndNotify() catch |err| {
                    const event: PolicyReloadFailed = .{ .err = @errorName(err) };
                    self.bus.err(event);
                };
            }
        }
    }
};

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;
const Registry = @import("./registry.zig").PolicyRegistry;
const NoopEventBus = o11y.NoopEventBus;

/// Write `contents` to `filename` inside `tmp_dir` and return a path string
/// (relative to cwd: ".zig-cache/tmp/<sub_path>/<filename>") that FileProvider
/// can open via Io.Dir.cwd().
fn writeTmpFile(
    allocator: std.mem.Allocator,
    tmp_dir: *testing.TmpDir,
    filename: []const u8,
    contents: []const u8,
) ![]u8 {
    const io = std.Options.debug_io;
    try tmp_dir.dir.writeFile(io, .{ .sub_path = filename, .data = contents });
    return std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", &tmp_dir.sub_path, filename });
}

test "FileProvider: init and deinit" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    const provider = try FileProvider.init(
        allocator,
        std.Options.debug_io,
        noop_bus.eventBus(),
        .{ .id = "test-provider", .path = "/nonexistent/path/policies.json" },
    );
    defer provider.deinit();

    try testing.expectEqualStrings("test-provider", provider.getId());
}

test "FileProvider: subscribe fails when file does not exist" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    const provider = try FileProvider.init(
        allocator,
        std.Options.debug_io,
        noop_bus.eventBus(),
        .{ .id = "test-provider", .path = "/nonexistent/path/policies.json" },
    );
    defer provider.deinit();

    // Subscribe should fail because file doesn't exist
    const result = provider.subscribe(.{
        .context = undefined,
        .onUpdate = struct {
            fn cb(_: *anyopaque, _: policy_provider.PolicyUpdate) !void {}
        }.cb,
    });

    try testing.expectError(error.FileNotFound, result);
}

test "FileProvider: subscribe fails with invalid JSON" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    // Create a temporary file with invalid JSON
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const tmp_path = try writeTmpFile(allocator, &tmp_dir, "invalid.json", "{ this is not valid json }");
    defer allocator.free(tmp_path);

    const provider = try FileProvider.init(
        allocator,
        std.Options.debug_io,
        noop_bus.eventBus(),
        .{ .id = "test-provider", .path = tmp_path },
    );
    defer provider.deinit();

    // Subscribe should fail because JSON is invalid
    const result = provider.subscribe(.{
        .context = undefined,
        .onUpdate = struct {
            fn cb(_: *anyopaque, _: policy_provider.PolicyUpdate) !void {}
        }.cb,
    });

    try testing.expectError(error.SyntaxError, result);
}

test "FileProvider: subscribe fails with invalid policy structure" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    // Create a temporary file with valid JSON but invalid policy structure
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const tmp_path = try writeTmpFile(allocator, &tmp_dir, "bad_policy.json",
        \\{
        \\  "policies": [
        \\    {
        \\      "name": "missing-id-policy",
        \\      "log": {
        \\        "match": [{ "log_field": "body", "regex": "test" }]
        \\      }
        \\    }
        \\  ]
        \\}
    );
    defer allocator.free(tmp_path);

    const provider = try FileProvider.init(
        allocator,
        std.Options.debug_io,
        noop_bus.eventBus(),
        .{ .id = "test-provider", .path = tmp_path },
    );
    defer provider.deinit();

    // Subscribe should fail because policy structure is invalid
    const result = provider.subscribe(.{
        .context = undefined,
        .onUpdate = struct {
            fn cb(_: *anyopaque, _: policy_provider.PolicyUpdate) !void {}
        }.cb,
    });

    try testing.expectError(error.MissingField, result);
}

test "FileProvider: registry remains usable after provider fails to load" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    // Create registry
    var registry = Registry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Try to load a provider with a non-existent file
    const provider = try FileProvider.init(
        allocator,
        std.Options.debug_io,
        noop_bus.eventBus(),
        .{ .id = "failing-provider", .path = "/nonexistent/path/policies.json" },
    );
    defer provider.deinit();

    // This should fail
    const subscribe_result = provider.subscribe(.{
        .context = undefined,
        .onUpdate = struct {
            fn cb(_: *anyopaque, _: policy_provider.PolicyUpdate) !void {}
        }.cb,
    });
    try testing.expectError(error.FileNotFound, subscribe_result);

    // Registry should still be usable - no policies loaded
    try testing.expectEqual(@as(usize, 0), registry.getPolicyCount());
    try testing.expect(registry.getSnapshot() == null);

    // Now load a valid policy file and verify registry works
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const tmp_path = try writeTmpFile(allocator, &tmp_dir, "valid.json",
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "test-policy",
        \\      "name": "test-policy",
        \\      "log": {
        \\        "match": [{ "log_field": "body", "regex": "test" }],
        \\        "keep": "all"
        \\      }
        \\    }
        \\  ]
        \\}
    );
    defer allocator.free(tmp_path);

    const good_provider = try FileProvider.init(
        allocator,
        std.Options.debug_io,
        noop_bus.eventBus(),
        .{ .id = "good-provider", .path = tmp_path },
    );
    defer good_provider.deinit();

    // Create callback that updates registry
    const CallbackContext = struct {
        const Self = @This();

        registry: *Registry,

        fn handleUpdate(ctx: *anyopaque, update: policy_provider.PolicyUpdate) !void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            try self.registry.updatePolicies(update.policies, update.provider_id, .file);
        }
    };

    var ctx: CallbackContext = .{ .registry = &registry };

    try good_provider.subscribe(.{
        .context = @ptrCast(&ctx),
        .onUpdate = CallbackContext.handleUpdate,
    });

    // Registry should now have the policy
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);
    try testing.expectEqual(@as(usize, 1), snapshot.?.policies.len);
    try testing.expectEqualStrings("test-policy", snapshot.?.policies[0].name);
}

test "FileProvider: shutdown returns promptly while watch thread is mid-interval" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const tmp_path = try writeTmpFile(allocator, &tmp_dir, "policies.json",
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "test-policy",
        \\      "name": "test-policy",
        \\      "log": {
        \\        "match": [{ "log_field": "body", "regex": "test" }],
        \\        "keep": "all"
        \\      }
        \\    }
        \\  ]
        \\}
    );
    defer allocator.free(tmp_path);

    // A deliberately long poll interval: the watch thread parks for ~60s on
    // its first wait. With a non-interruptible sleep, shutdown() would have to
    // wait out that whole interval before the thread could observe the event.
    const provider = try FileProvider.init(
        allocator,
        std.Options.debug_io,
        noop_bus.eventBus(),
        .{ .id = "test-provider", .path = tmp_path, .poll_interval_ns = 60 * std.time.ns_per_s },
    );
    defer provider.deinit();

    try provider.subscribe(.{
        .context = undefined,
        .onUpdate = struct {
            fn cb(_: *anyopaque, _: policy_provider.PolicyUpdate) !void {}
        }.cb,
    });

    const io = std.Options.debug_io;
    const start = std.Io.Clock.Timestamp.now(io, .awake);
    provider.shutdown();
    const elapsed_ns = start.untilNow(io).raw.nanoseconds;

    // Must wake well within the 60s interval. Generous bound to avoid flaking
    // on loaded CI while still catching a regression to full-interval blocking.
    try testing.expect(elapsed_ns < 5 * std.time.ns_per_s);
}

test "FileProvider: registry retains policies after reload with invalid JSON" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    var registry = Registry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a valid policy file
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const tmp_path = try writeTmpFile(allocator, &tmp_dir, "policies.json",
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "test-policy",
        \\      "name": "test-policy",
        \\      "log": {
        \\        "match": [{ "log_field": "body", "regex": "test" }],
        \\        "keep": "all"
        \\      }
        \\    }
        \\  ]
        \\}
    );
    defer allocator.free(tmp_path);

    const provider = try FileProvider.init(
        allocator,
        std.Options.debug_io,
        noop_bus.eventBus(),
        .{ .id = "test-provider", .path = tmp_path },
    );
    defer provider.deinit();

    // Create callback that updates registry
    const CallbackContext = struct {
        const Self = @This();

        registry: *Registry,

        fn handleUpdate(ctx: *anyopaque, update: policy_provider.PolicyUpdate) !void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            try self.registry.updatePolicies(update.policies, update.provider_id, .file);
        }
    };

    var ctx: CallbackContext = .{ .registry = &registry };

    // Subscribe - this should load the valid policy
    try provider.subscribe(.{
        .context = @ptrCast(&ctx),
        .onUpdate = CallbackContext.handleUpdate,
    });

    // Verify the policy was loaded
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());
    {
        const snapshot = registry.getSnapshot();
        try testing.expect(snapshot != null);
        try testing.expectEqual(@as(usize, 1), snapshot.?.policies.len);
        try testing.expectEqualStrings("test-policy", snapshot.?.policies[0].name);
    }

    // Now overwrite the file with invalid JSON
    try tmp_dir.dir.writeFile(std.Options.debug_io, .{
        .sub_path = "policies.json",
        .data = "{ this is not valid json }",
    });

    // Manually trigger a reload (simulates what the watch loop does)
    // This should fail but not crash
    const reload_result = provider.loadAndNotify();
    try testing.expectError(error.SyntaxError, reload_result);

    // Registry should still have the original policy - reload failure doesn't clear it
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());
    {
        const snapshot = registry.getSnapshot();
        try testing.expect(snapshot != null);
        try testing.expectEqual(@as(usize, 1), snapshot.?.policies.len);
        try testing.expectEqualStrings("test-policy", snapshot.?.policies[0].name);
    }

    // Now overwrite with valid JSON but invalid policy structure (missing "id" field)
    try tmp_dir.dir.writeFile(std.Options.debug_io, .{ .sub_path = "policies.json", .data =
        \\{
        \\  "policies": [
        \\    {
        \\      "name": "missing-id-policy",
        \\      "log": {
        \\        "match": [{ "log_field": "body", "regex": "test" }]
        \\      }
        \\    }
        \\  ]
        \\}
    });

    // Reload should fail due to missing required field
    const reload_result2 = provider.loadAndNotify();
    try testing.expectError(error.MissingField, reload_result2);

    // Registry should still have the original policy
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());
    {
        const snapshot = registry.getSnapshot();
        try testing.expect(snapshot != null);
        try testing.expectEqual(@as(usize, 1), snapshot.?.policies.len);
        try testing.expectEqualStrings("test-policy", snapshot.?.policies[0].name);
    }

    // Fix the file with valid JSON again
    try tmp_dir.dir.writeFile(std.Options.debug_io, .{ .sub_path = "policies.json", .data =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "updated-policy",
        \\      "name": "updated-policy",
        \\      "log": {
        \\        "match": [{ "log_field": "body", "regex": "updated" }],
        \\        "keep": "all"
        \\      }
        \\    }
        \\  ]
        \\}
    });

    // Reload should now succeed
    try provider.loadAndNotify();

    // Registry should now have the updated policy
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());
    {
        const snapshot = registry.getSnapshot();
        try testing.expect(snapshot != null);
        try testing.expectEqual(@as(usize, 1), snapshot.?.policies.len);
        try testing.expectEqualStrings("updated-policy", snapshot.?.policies[0].name);
    }
}

test "FileProvider: multiple providers, one fails, registry has policies from successful one" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);

    var registry = Registry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a valid policy file
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const tmp_path = try writeTmpFile(allocator, &tmp_dir, "valid.json",
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "policy-from-valid-provider",
        \\      "name": "policy-from-valid-provider",
        \\      "log": {
        \\        "match": [{ "log_field": "body", "regex": "info" }],
        \\        "keep": "all"
        \\      }
        \\    }
        \\  ]
        \\}
    );
    defer allocator.free(tmp_path);

    // First provider - will fail
    const failing_provider = try FileProvider.init(
        allocator,
        std.Options.debug_io,
        noop_bus.eventBus(),
        .{ .id = "failing-provider", .path = "/nonexistent/policies.json" },
    );
    defer failing_provider.deinit();

    const fail_result = failing_provider.subscribe(.{
        .context = undefined,
        .onUpdate = struct {
            fn cb(_: *anyopaque, _: policy_provider.PolicyUpdate) !void {}
        }.cb,
    });
    try testing.expectError(error.FileNotFound, fail_result);

    // Second provider - will succeed
    const good_provider = try FileProvider.init(
        allocator,
        std.Options.debug_io,
        noop_bus.eventBus(),
        .{ .id = "good-provider", .path = tmp_path },
    );
    defer good_provider.deinit();

    const CallbackContext = struct {
        const Self = @This();

        registry: *Registry,

        fn handleUpdate(ctx: *anyopaque, update: policy_provider.PolicyUpdate) !void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            try self.registry.updatePolicies(update.policies, update.provider_id, .file);
        }
    };

    var ctx: CallbackContext = .{ .registry = &registry };

    try good_provider.subscribe(.{
        .context = @ptrCast(&ctx),
        .onUpdate = CallbackContext.handleUpdate,
    });

    // Registry should have policy from the successful provider only
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);
    try testing.expectEqualStrings("policy-from-valid-provider", snapshot.?.policies[0].name);
}
