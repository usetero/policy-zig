//! Policy management package for Tero Edge
//!
//! This package provides policy loading, management, and evaluation capabilities.
//! Policies can be loaded from multiple sources (file, HTTP) with priority-based
//! conflict resolution.
//!
//! ## Usage
//!
//! ```zig
//! const policy = @import("policy_zig");
//!
//! // Create a registry
//! var registry = policy.Registry.init(allocator, bus);
//! defer registry.deinit();
//!
//! // Create and register a file provider
//! const file_provider = try policy.FileProvider.init(allocator, bus, .{ .id = "local", .path = "policies.json" });
//! defer file_provider.deinit();
//!
//! try registry.registerProvider(.{ .file = file_provider });
//! ```

const std = @import("std");

// =============================================================================
// Proto Types (re-exported for consumers)
// =============================================================================

/// Generated protobuf types for the policy spec.
/// Consumers can use these directly instead of compiling their own protos.
pub const proto = @import("proto");

// =============================================================================
// Observability (re-exported for consumers)
// =============================================================================

/// Structured observability: event bus, spans, formatters, logging.
pub const observability = @import("observability");

// =============================================================================
// Core Types
// =============================================================================

/// Re-export source types
pub const source = @import("./source.zig");
pub const SourceType = source.SourceType;
pub const PolicyMetadata = source.PolicyMetadata;

/// Re-export provider interface
pub const provider = @import("./provider.zig");
pub const PolicyCallback = provider.PolicyCallback;
pub const PolicyUpdate = provider.PolicyUpdate;

/// Re-export registry
pub const registry = @import("./registry.zig");
pub const Registry = registry.PolicyRegistry;
pub const Snapshot = registry.PolicySnapshot;
pub const ConfigType = registry.PolicyConfigType;

// =============================================================================
// Provider Implementations
// =============================================================================

/// File-based policy provider
pub const FileProvider = @import("./provider_file.zig").FileProvider;

/// HTTP-based policy provider
pub const HttpProvider = @import("./provider_http.zig").HttpProvider;

/// Async policy loader for off-hot-path initialization
pub const Loader = @import("./loader.zig").PolicyLoader;

// =============================================================================
// Configuration Types
// =============================================================================

pub const types = @import("./types.zig");
pub const Provider = types.Provider;
pub const TestProvider = types.TestProvider;
pub const ServiceMetadata = types.ServiceMetadata;
pub const ProviderType = types.ProviderType;
pub const ProviderConfig = types.ProviderConfig;
pub const Header = types.Header;

// Field reference types (shared across policy engine and transforms)
pub const FieldRef = types.FieldRef;
pub const MetricFieldRef = types.MetricFieldRef;
pub const TraceFieldRef = types.TraceFieldRef;
pub const LogFieldAccessor = types.LogFieldAccessor;
pub const LogFieldMutator = types.LogFieldMutator;
pub const MetricFieldAccessor = types.MetricFieldAccessor;
pub const MetricFieldMutator = types.MetricFieldMutator;
pub const TraceFieldAccessor = types.TraceFieldAccessor;
pub const TraceFieldMutator = types.TraceFieldMutator;
pub const MutateOp = types.MutateOp;
pub const MetricMutateOp = types.MetricMutateOp;
pub const TraceMutateOp = types.TraceMutateOp;
pub const TelemetryType = types.TelemetryType;

// =============================================================================
// Matcher Index (Hyperscan-based pattern matching)
// =============================================================================

pub const matcher_index = @import("./matcher_index.zig");
pub const LogMatcherIndex = matcher_index.LogMatcherIndex;
pub const MetricMatcherIndex = matcher_index.MetricMatcherIndex;
pub const LogMatcherKey = matcher_index.LogMatcherKey;
pub const MetricMatcherKey = matcher_index.MetricMatcherKey;
pub const MAX_POLICIES = matcher_index.MAX_POLICIES;

// =============================================================================
// Sampling and Rate Limiting
// =============================================================================

pub const probabilistic_sampler = @import("./probabilistic_sampler.zig");
pub const ProbabilisticSampler = probabilistic_sampler.ProbabilisticSampler;

pub const rate_limiter = @import("./rate_limiter.zig");
pub const RateLimiter = rate_limiter.RateLimiter;

// =============================================================================
// Policy Engine
// =============================================================================

pub const policy_engine = @import("./policy_engine.zig");
pub const PolicyEngine = policy_engine.PolicyEngine;
pub const PolicyResult = policy_engine.PolicyResult;
pub const FilterDecision = policy_engine.FilterDecision;
pub const MAX_MATCHES_PER_SCAN = policy_engine.MAX_MATCHES_PER_SCAN;

// =============================================================================
// Parsing
// =============================================================================

pub const parser = @import("./parser.zig");

// =============================================================================
// Transforms
// =============================================================================

pub const log_transform = @import("./log_transform.zig");
pub const TransformResult = log_transform.TransformResult;
pub const applyTransforms = log_transform.applyTransforms;
pub const applyRemove = log_transform.applyRemove;
pub const applyRedact = log_transform.applyRedact;
pub const applyRename = log_transform.applyRename;
pub const applyAdd = log_transform.applyAdd;

pub const redact = @import("./redact.zig");

// =============================================================================
// Tests
// =============================================================================

test {
    // Run all tests in submodules
    std.testing.refAllDecls(@This());
}
