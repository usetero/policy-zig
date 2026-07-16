//! Async Policy Loader
//!
//! Provides shared logic for loading policy providers asynchronously,
//! allowing the server to start responding to requests immediately
//! while policies are loaded in the background.
//!
//! ## Usage
//!
//! ```zig
//! var loader = try PolicyLoader.init(allocator, bus, &registry, config.policy_providers);
//! defer loader.deinit();
//!
//! // Start loading providers asynchronously (non-blocking)
//! try loader.startAsync(io);
//!
//! // Server can now start handling requests...
//!
//! // Optionally wait for initial load to complete
//! loader.waitForInitialLoad();
//! ```

const std = @import("std");
const policy = @import("./root.zig");
const policy_types = @import("./types.zig");

const Registry = policy.Registry;
const Provider = policy_types.Provider;
const FileProvider = policy.FileProvider;
const HttpProvider = policy.HttpProvider;
const ProviderConfig = policy.ProviderConfig;
const ServiceMetadata = policy.ServiceMetadata;

const o11y = @import("observability");
const EventBus = o11y.EventBus;

// =============================================================================
// Observability Events
// =============================================================================

const PolicyLoaderStarting = struct { provider_count: usize };
const PolicyLoaderReady = struct { loaded_count: usize, failed_count: usize };
const ProviderLoadStarted = struct { provider_id: []const u8, provider_type: []const u8 };
const ProviderLoadCompleted = struct { provider_id: []const u8, policy_count: usize };
const ProviderLoadFailed = struct { provider_id: []const u8, err: []const u8 };
const FileProviderConfigured = struct { path: []const u8 };
const HttpProviderConfigured = struct { url: []const u8, poll_interval: u64 };

// =============================================================================
// Provider State
// =============================================================================

const ProviderState = struct {
    config: ProviderConfig,
    provider: ?Provider = null,
    load_error: ?[]const u8 = null,
    loaded: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn deinitProvider(self: *ProviderState) void {
        if (self.provider) |prov| {
            prov.deinit();
        }
    }
};

// =============================================================================
// Policy Loader
// =============================================================================

pub const PolicyLoader = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    bus: *EventBus,
    registry: *Registry,
    service: ServiceMetadata,

    /// Provider states (one per configured provider)
    provider_states: []ProviderState,

    /// Background loading thread
    load_thread: ?std.Thread = null,

    /// Shutdown flag for clean termination
    shutdown_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    /// Signal when initial load is complete
    initial_load_complete: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    /// Initialize the policy loader with provider configurations.
    /// Does not start loading - call `startAsync()` or `loadSync()` to begin.
    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        bus: *EventBus,
        registry: *Registry,
        provider_configs: []const ProviderConfig,
        service: ServiceMetadata,
    ) !*PolicyLoader {
        const self = try allocator.create(PolicyLoader);
        errdefer allocator.destroy(self);

        // Allocate provider states
        const states = try allocator.alloc(ProviderState, provider_configs.len);
        errdefer allocator.free(states);

        for (provider_configs, 0..) |config, i| {
            states[i] = .{ .config = config };
        }

        self.* = .{
            .allocator = allocator,
            .io = io,
            .bus = bus,
            .registry = registry,
            .service = service,
            .provider_states = states,
        };

        return self;
    }

    /// Start loading providers asynchronously in a background thread.
    /// Returns immediately, allowing the server to start handling requests.
    pub fn startAsync(self: *PolicyLoader, io: std.Io) !void {
        const event: PolicyLoaderStarting = .{ .provider_count = self.provider_states.len };
        self.bus.info(event);
        self.load_thread = try std.Thread.spawn(.{}, loadProvidersThread, .{ self, io });
    }

    /// Load all providers synchronously (blocks until complete).
    /// Use this if you need policies loaded before accepting requests.
    pub fn loadSync(self: *PolicyLoader, io: std.Io) void {
        const event: PolicyLoaderStarting = .{ .provider_count = self.provider_states.len };
        self.bus.info(event);
        self.loadAllProviders(io);
    }

    /// Wait for the initial load to complete.
    /// Call this after `startAsync()` if you need to block until ready.
    pub fn waitForInitialLoad(self: *PolicyLoader) !void {
        while (!self.initial_load_complete.load(.acquire)) {
            try self.io.sleep(.fromNanoseconds(10 * std.time.ns_per_ms), .awake);
        }
    }

    /// Check if initial load is complete (non-blocking).
    pub fn isReady(self: *PolicyLoader) bool {
        return self.initial_load_complete.load(.acquire);
    }

    /// Get the number of successfully loaded providers.
    pub fn getLoadedCount(self: *PolicyLoader) usize {
        var count: usize = 0;
        for (self.provider_states) |state| {
            if (state.loaded.load(.acquire) and state.load_error == null) {
                count += 1;
            }
        }
        return count;
    }

    /// Get the number of providers that failed to load.
    pub fn getFailedCount(self: *PolicyLoader) usize {
        var count: usize = 0;
        for (self.provider_states) |state| {
            if (state.load_error != null) {
                count += 1;
            }
        }
        return count;
    }

    /// Flush every subscribed provider before teardown: each HTTP provider does
    /// one final synchronous sync so tail stats reach the control plane
    /// (file/testing are no-ops). Every provider is attempted even if an earlier
    /// one fails; the first error is returned so a partial-flush shutdown is
    /// still visible to the caller. Call this before the io is torn down (e.g. a
    /// Lambda shutdown window), then `deinit`; `deinit` does not flush on its own.
    pub fn close(self: *PolicyLoader) !void {
        var first_err: ?anyerror = null;
        for (self.provider_states) |state| {
            if (state.provider) |prov| prov.close() catch |err| {
                if (first_err == null) first_err = err;
            };
        }
        if (first_err) |err| return err;
    }

    /// Shutdown all providers and clean up resources.
    pub fn deinit(self: *PolicyLoader) void {
        const allocator = self.allocator;
        // LIFO defer order: self.* = undefined runs first (while memory is
        // still valid), then destroy frees it.
        defer allocator.destroy(self);
        defer self.* = undefined;

        // Signal shutdown
        self.shutdown_flag.store(true, .release);

        // Wait for load thread to finish
        if (self.load_thread) |thread| {
            thread.join();
            self.load_thread = null;
        }

        // Deinit all providers
        for (self.provider_states) |*state| {
            state.deinitProvider();
            if (state.load_error) |err| {
                allocator.free(err);
            }
        }

        allocator.free(self.provider_states);
    }

    // =========================================================================
    // Private Implementation
    // =========================================================================

    fn loadProvidersThread(self: *PolicyLoader, io: std.Io) void {
        self.loadAllProviders(io);
    }

    fn loadAllProviders(self: *PolicyLoader, io: std.Io) void {
        var loaded_count: usize = 0;
        var failed_count: usize = 0;

        for (self.provider_states) |*state| {
            if (self.shutdown_flag.load(.acquire)) break;

            self.loadProvider(io, state) catch |err| {
                const err_str = self.allocator.dupe(u8, @errorName(err)) catch "allocation_failed";
                state.load_error = err_str;
                const event: ProviderLoadFailed = .{
                    .provider_id = state.config.id,
                    .err = err_str,
                };
                self.bus.err(event);
                failed_count += 1;
                continue;
            };

            loaded_count += 1;
        }

        self.initial_load_complete.store(true, .release);
        const event: PolicyLoaderReady = .{
            .loaded_count = loaded_count,
            .failed_count = failed_count,
        };
        self.bus.info(event);
    }

    fn loadProvider(self: *PolicyLoader, io: std.Io, state: *ProviderState) !void {
        const config = state.config;
        const provider_type_str = switch (config.type) {
            .file => "file",
            .http => "http",
        };

        const started_event: ProviderLoadStarted = .{
            .provider_id = config.id,
            .provider_type = provider_type_str,
        };
        self.bus.debug(started_event);

        switch (config.type) {
            .file => {
                const path = config.path orelse return error.FileProviderRequiresPath;
                const configured_event: FileProviderConfigured = .{ .path = path };
                self.bus.info(configured_event);

                const file_provider = try FileProvider.init(
                    self.allocator,
                    io,
                    self.bus,
                    .{ .id = config.id, .path = path },
                );
                errdefer file_provider.deinit();

                const prov: Provider = .{ .file = file_provider };
                try self.registry.subscribe(prov);
                state.provider = prov;
                state.loaded.store(true, .release);

                const completed_event: ProviderLoadCompleted = .{
                    .provider_id = config.id,
                    .policy_count = self.registry.getPolicyCount(),
                };
                self.bus.debug(completed_event);
            },
            .http => {
                const url = config.url orelse return error.HttpProviderRequiresUrl;
                const poll_interval = config.poll_interval orelse 60;
                const configured_event: HttpProviderConfigured = .{
                    .url = url,
                    .poll_interval = poll_interval,
                };
                self.bus.info(configured_event);

                const http_provider = try HttpProvider.init(
                    self.allocator,
                    io,
                    self.bus,
                    .{
                        .id = config.id,
                        .url = url,
                        .poll_interval_seconds = poll_interval,
                        .service = self.service,
                        .headers = config.headers,
                    },
                );
                errdefer http_provider.deinit();

                const prov: Provider = .{ .http = http_provider };
                try self.registry.subscribe(prov);
                state.provider = prov;
                state.loaded.store(true, .release);

                const completed_event: ProviderLoadCompleted = .{
                    .provider_id = config.id,
                    .policy_count = self.registry.getPolicyCount(),
                };
                self.bus.debug(completed_event);
            },
        }
    }
};

// =============================================================================
// Tests
// =============================================================================

test "PolicyLoader: init and deinit" {
    const allocator = std.testing.allocator;

    var stdio_bus: o11y.StdioEventBus = undefined;
    stdio_bus.init(std.Options.debug_io);
    const bus = stdio_bus.eventBus();

    var registry = Registry.init(allocator, bus);
    defer registry.deinit();

    const configs: [0]ProviderConfig = .{};

    var loader = try PolicyLoader.init(
        allocator,
        std.Options.debug_io,
        bus,
        &registry,
        &configs,
        .{
            .namespace = "test",
            .name = "test-service",
            .instance_id = "test-instance",
            .version = "1.0.0",
        },
    );
    defer loader.deinit();

    try std.testing.expect(!loader.isReady());
    try std.testing.expectEqual(@as(usize, 0), loader.getLoadedCount());
}
