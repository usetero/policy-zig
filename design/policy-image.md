# PolicyImage architecture

The library is split into cold source normalization and compilation, immutable
image storage, and a provider-independent runtime:

```text
provider adapters -> normalized source -> fixed-workspace compiler
                                      -> immutable PolicyImage slot
projected ValueRef registers -> worker-owned runtime -> Decision / DecisionEvent
```

`policy_capacity` owns the single capacity contract. `policy_image` owns the
wire ABI and validation. `policy_compiler` writes fixed destinations without
heap ownership. `policy_runtime` imports only capacity and image modules.
`policy_image_store` owns three-slot atomic publication and exact worker epoch
announcements. Provider protobuf code stays in the cold source layer.

## Storage and ABI

An image is one byte slice containing a 96-byte header, interned field-demand
entries, policy columns, matcher instructions, action instructions, and a
string/constant blob. Every reference is an integer index or relative `u32`
offset. Readers decode integers explicitly as little-endian values; image code
contains no `@bitCast`. SHA-256 is calculated with the hash field treated as
zero, so serialized output is deterministic and self-validating.

`PolicyImage.open` verifies magic, ABI version, exact canonical section layout,
all ranges, enum tags, policy/matcher ownership, string references, and the
complete content hash before a byte can be published.

## Evaluation

The host projects only demanded fields into a `ValueRef` array. Native exact,
prefix, suffix, contains, existence, signed, unsigned, float, and boolean
operations execute directly. Exact byte matching hashes before comparison.
Regex instructions call an optional backend by numeric matcher ID and reject a
backend whose declared compatible scratch requirement exceeds the one worker
region.

`WorkerState` partitions one caller-owned byte slice into generation stamps,
match counts, active policy indices, non-atomic SoA statistics, rate windows,
regex scratch, and bounded match detail storage. Normal record evaluation only
touches active policy entries. OpenTelemetry sampling uses 56-bit trace-ID
randomness and supports hash-seed, proportional, and equalizing modes with
incoming `th`/`rv` tracestate. Rate limiting is worker-sharded or consistently
keyed unless the caller supplies a recorded centralized outcome.

The result carries verdict, stable reason, winning policy index, action range,
full image hash and epoch, match summary, action mask, sampling randomness and
threshold, and rate outcome. `ActionIterator` decodes transform and extension
commands outside the common kernel. `DecisionEvent` ABI v2 has an explicit
128-byte encoding, and the replay runner compares those bytes exactly using
recorded nondeterministic outcomes.

## Publication

Compilation targets an inactive slot. `publish` validates the finished image
and performs one release-store of the packed slot and epoch. A worker announces
the observed epoch before dereferencing a slot, verifies publication did not
change, and clears its announcement only at a safe boundary.

The familiar public name `Registry` aliases this image store; `Snapshot`,
`PolicyEngine`, and `PolicyResult` similarly name the immutable image, bound
runtime façade, and compact decision. They do not reintroduce legacy ownership.

## Build gates

`zig build check-kernel` links a production probe with function sections,
measures the evaluator symbol and page offset, and fails if its extent crosses a
4 KiB boundary. `scripts/stack-report.sh` invokes Zig's stack reporting for
ReleaseFast, ReleaseSafe, and ReleaseSmall and records linked symbol disposition
under `.zig-cache/policy-stack-reports`. `task bench:counters` records cycles,
instructions, L1I misses, and branch misses with Linux `perf`; on macOS it
captures Xcode's CPU delivery, discarded-work, processing, and useful-work
bottleneck counters.
