//! Compiler and fixed-storage execution runtime for Tero policies.
//!
//! Provider payloads are cold source data. Runtime callers project demanded
//! fields into `ValueRef` registers and evaluate an immutable `PolicyImage`.

const std = @import("std");

/// Generated provider schema. It is intentionally absent from runtime imports.
pub const proto = @import("proto");

pub const Capacity = @import("policy_capacity").Capacity;

pub const source = @import("policy_source");
pub const compiler = @import("policy_compiler");
pub const image = @import("policy_image");
pub const runtime = @import("policy_runtime");
const image_store = @import("policy_image_store");
pub const registry = image_store;
pub const policy_engine = runtime;

pub const PolicyCompiler = compiler.Compiler;
pub const SourceType = source.SourceType;
pub const PolicyMetadata = source.PolicyMetadata;
pub const PolicyImage = image.PolicyImage;
pub const ImageStore = image_store.ImageStore;
pub const ImageLease = image_store.ImageLease;
pub const Registry = image_store.ImageStore;
pub const Snapshot = image.PolicyImage;

pub const ValueRef = runtime.ValueRef;
pub const WorkerState = runtime.WorkerState;
pub const Decision = runtime.Decision;
pub const FilterDecision = image.Verdict;
pub const PolicyResult = runtime.PolicyResult;
pub const PolicyEngine = runtime.PolicyEngine;
pub const EvalContext = runtime.EvalContext;
pub const DecisionEvent = runtime.DecisionEvent;
pub const DecisionJournal = runtime.DecisionJournal;
pub const ActionIterator = runtime.ActionIterator;
pub const MatchedPolicyIterator = runtime.MatchedPolicyIterator;
pub const replay = @import("policy_replay");
pub const sampling = runtime.sampling;

test {
    std.testing.refAllDecls(@This());
}
