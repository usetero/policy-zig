# Extensions package + `com.usetero/s3-dump`

Design for implementing policy-spec v1.6.0 extensions in policy-zig, and the
first concrete extension: dumping telemetry to S3-compatible storage.

Status: **implemented** (see `src/extensions/`, engine dispatch in
`src/policy/policy_engine.zig`, bindings in `src/policy/matcher_index.zig`).
Deviations from the text below, made during implementation:

- The resolver seam passes `io` first (`resolve(io, ctx, signal, policy_id,
  ext)`) per ziglint's io-ordering rule, and resolution returns an opaque
  `{handler, slot}` pair — the slot is the s3-dump batch index, assigned at
  compile time so dispatch is an array lookup.
- Per-signal `encode` callbacks are registered once on `Extensions.init`
  rather than carried in each `DeliveredRecord` (the engine passes only
  `(signal, record ctx)` across the module seam).
- Credentials are consumer-provided at `S3Dump.init` (no built-in env
  discovery — z3 has none either, and the edge binary owns its env).
- Extension sync hooks (a two-fn seam like `StatsCollector`) live in the
  generic provider layer (`provider.zig`); `Provider.setExtensionSyncHooks`
  dispatches per variant (`.http` wires, `.file`/`.testing` no-op), and
  `registry.subscribe` pushes them to every provider automatically — the
  consumer wires them once via `registry.setExtensionSyncHooks` (or
  `Extensions.register`), not per provider.
- `Extensions.enableS3Dump(alloc, opts, creds) *S3Dump` constructs the
  handler in place and returns its pointer, so targets are configured on the
  handler directly (no move, no `s3Dump().?` reach-back).
- `Extensions.register(&registry)` wires resolver + sync hooks in one call.
- All batching knobs live in `S3Dump.Options`, a plain-data struct with
  defaults, deserializable from a config file.

## What the spec requires (v1.6.0)

From `spec.md` §Extensions and `extension.proto` / `tero_extensions.proto`:

- A policy MAY carry `extensions: [{type, version, config, mode}]`. `type` is
  reverse-FQDN (`com.usetero/s3-dump`), `version` is semver, `config` is
  **opaque bytes** the engine never interprets, `mode` selects a traffic slice.
- Pipeline order is `Match → Keep → Extension dispatch → Transform`. Extensions
  receive **pre-transform** records and MUST NOT change the keep or transform
  outcome. The keep verdict used for classification is the record's **final
  pipeline outcome** across all policies (that's what makes `mode: dropped` on
  a `keep: .01%` policy receive the ~99.99% waste).
- Modes, relative to the extension's policy: `kept`, `dropped`, `unmatched`
  (disjoint partition), `matched` = kept+dropped (default), `all` = everything.
- Handshake: the client advertises `ClientMetadata.supported_extensions`
  (`ExtensionCapability{type, min_version, repeated bytes config}`); the
  provider MAY broadcast `SyncResponse.extension_configs`
  (`ExtensionConfig{type, repeated bytes config}`). For s3-dump the capability
  descriptors are serialized `ExtensionTargetRef`s and the broadcast entries
  are serialized `ExtensionTarget`s.
- Rules: fail-open (an unsupported/unsatisfiable extension is skipped; core
  match/keep/transform still applies; SHOULD reject the policy only when the
  extension is *required* for its behavior — never true for a dump), execute
  off the hot path with non-blocking operations, and document supported
  `type`/`version` pairs (conformance item 9).
- `ExtensionTarget{kind, name, config}` is a pre-configured named destination;
  policies reference it by `ExtensionTargetRef{kind, name}` and never carry
  credentials or connection details inline.

## Goals / non-goals

**v1 goals**

- Generic extension mechanism: handler tagged union, engine dispatch hook,
  compile-stage validation, capability advertisement, config broadcast
  handling.
- One extension: `com.usetero/s3-dump` v1.0.0, all three signals, ndjson
  objects, S3-compatible endpoints (AWS, MinIO, R2) via the
  [z3](https://codeberg.org/fellowtraveler/z3) client.

**Non-goals (v1)**

- Columnar object formats (OTel Arrow, Vortex, Parquet) — see
  [Data format](#data-format-edge-native-rows-not-columnar); gzip; multipart
  upload (z3 supports it if batches ever need it); upload retry queues.
- Post-transform delivery (spec leaves it type-defined; we don't need it).
- Any second extension type. The mechanism is generic but we build exactly one.

## Prerequisite: proto update

We deliberately skipped the extension protos when updating to v1.6.0. First
step is finishing that:

1. Vendor `extension.proto`, `tero_extensions.proto`, and the v1.6.0
   `policy.proto` (adds `Policy.extensions = 20`,
   `ClientMetadata.supported_extensions = 4`,
   `SyncResponse.extension_configs = 7`) into `proto/tero/policy/v1/`.
2. `zig build -Dgen-proto=true gen-proto`.

No engine behavior changes from this alone — unknown fields were already
ignored on the wire.

## Package layout

A new module `extensions`, mirroring how `observability` is wired:

```
src/extensions/
  root.zig        // ExtensionHandler tagged union, dispatch fn, re-exports
  s3_dump.zig     // com.usetero/s3-dump handler
```

One new dependency in `build.zig.zon`:
[z3](https://codeberg.org/fellowtraveler/z3) — pure-Zig async S3 client (MIT,
min Zig 0.16, zero deps beyond std). It covers SigV4 signing, path- and
virtual-host-style requests, S3-compatible endpoints (tested against R2), and
multipart uploads if batches ever outgrow single PUTs. This replaces the
hand-rolled `sigv4.zig` + `std.http` plumbing from an earlier draft. Only the
`extensions` module imports it — `policy_zig` stays dependency-free.

`build.zig`:

```zig
const ext_mod = b.addModule("extensions", .{
    .root_source_file = b.path("src/extensions/root.zig"),
    .imports = &.{ proto, policy_zig, observability },
});
```

Rationale for a separate module rather than folding into `policy_zig`: the
engine stays free of I/O and of any knowledge of concrete extension types
(spec: config is opaque to the engine), and consumers that don't use
extensions link nothing new.

## Core mechanism

### 1. Engine dispatch hook (`policy_zig` change — the only one)

Dispatch must happen *inside* `evaluate`: after the final keep decision is
known but **before transforms run** (spec ordering). Post-`evaluate` dispatch
by the consumer would see redacted records, so that's out.

Add an optional sink to the per-call evaluate options, alongside `io`:

```zig
/// One function pointer + ctx — the same shape as the accessor primitives,
/// NOT a vtable (Claude.md: encoding over polymorphism; the fn pointer here
/// exists only to break the module cycle — policy_zig cannot import the
/// extensions module that implements it). All real dispatch happens behind
/// it via the ExtensionHandler tagged union.
pub const ExtensionSink = struct {
    ctx: *anyopaque,
    /// Called once per (record, policy-with-extensions) pair whose mode
    /// selects this record, between keep resolution and transforms.
    deliver: *const fn (
        ctx: *anyopaque,
        io: ?std.Io,
        telemetry: DeliveredRecord, // signal tag + consumer ctx + encode fn
        binding: *const ExtensionBinding, // policy index + resolved handler tag + config + mode
        slice: SliceTag, // kept | dropped | unmatched
    ) void,
};
```

- `evaluate(..., .{ .io = io, .extension_sink = null })` — a null sink is a
  single branch; zero cost for existing consumers.
- The engine classifies per binding using state it already has:
  `matched(policy)` (from `MatchState`) and the final decision. `kept` =
  matched ∧ keep, `dropped` = matched ∧ drop, `unmatched` = ¬matched;
  `matched`/`all` are unions resolved at compile time into "which slices fire".
- `UNMATCHED`/`ALL` bindings must be visited even when the record matched no
  policy, so the binding list is iterated unconditionally — but only when the
  snapshot has any bindings (one `bindings.len == 0` check keeps the common
  case free).
- Delivery passes the consumer `ctx` + accessor-adjacent `encode` fn (below),
  not bytes: the engine has no serialized form of the record.

### 2. Compile-stage bindings and validation

Per the "validate during compilation" convention, `IndexBuilder` grows an
extensions pass:

- Collect `ExtensionBinding{policy_index, handler: ExtensionTag, mode, config}`
  for every enabled policy into the snapshot (plain slice, iterated at
  dispatch). The `type` string is resolved to the `ExtensionTag` enum **once,
  here** — dispatch never compares strings (Claude.md: encode, don't point).
- Validation, fail-open per spec rule 5: an extension whose `type` has no
  registered handler, whose `version` exceeds the handler's supported range,
  or whose `config` the handler rejects (e.g. unknown target ref) is **skipped
  and reported** via the existing `recordError` path → `PolicySyncStatus.errors`.
  The policy itself stays valid — a dump extension is never "required for the
  policy's behavior".
- Handlers get a `validateConfig(config: []const u8) error{...}!void` chance at
  compile time so bad configs surface at sync, not at dispatch.

### 3. Handlers: tagged union, not a vtable

Extension types are a closed set the implementation must declare anyway (spec
rule 4), so runtime polymorphism buys nothing. Per Claude.md §"Encoding
Instead of Polymorphism", handlers are a tagged union with switch dispatch:

```zig
pub const ExtensionTag = enum { s3_dump };

pub const ExtensionHandler = union(ExtensionTag) {
    s3_dump: S3Dump,

    pub fn typeId(tag: ExtensionTag) []const u8 {
        return switch (tag) { .s3_dump => "com.usetero/s3-dump" };
    }

    pub fn validateConfig(self: *const ExtensionHandler, config: []const u8) !void {
        switch (self.*) { .s3_dump => |*h| try h.validateConfig(config) }
    }

    /// Hot-path entry. MUST be non-blocking: append to a batch and return.
    pub fn deliver(self: *ExtensionHandler, rec: DeliveredRecord, config: []const u8, slice: SliceTag) void {
        switch (self.*) { .s3_dump => |*h| h.deliver(rec, config, slice) }
    }

    /// SyncResponse.extension_configs entries for this type.
    pub fn configure(self: *ExtensionHandler, entries: []const []const u8) void { ... }

    /// Capability descriptors for ClientMetadata.supported_extensions.
    pub fn capabilities(self: *const ExtensionHandler, allocator: Allocator) ![]const []const u8 { ... }
};
```

There is no registry object: the consumer constructs an
`Extensions = struct { handlers: std.EnumArray(ExtensionTag, ?ExtensionHandler) }`
with the handlers it enables, and the dispatch path is an array index by the
binding's pre-resolved tag — no string lookup, no pointer chase. Adding a
second extension type = one new enum tag + one new union arm; the compiler
enforces exhaustiveness everywhere.

The only fn pointers in the design are the engine-side `ExtensionSink`
(one function, to break the policy_zig ↔ extensions module cycle — same
pattern as accessors) and the consumer's `encode` callback (unavoidable: the
record type is the consumer's).

### 4. Record encoding — consumer contract

The engine reads records through accessors and never owns bytes, so a dump
extension cannot serialize a record by itself. `DeliveredRecord` therefore
carries a consumer-wired encoder:

```zig
pub const DeliveredRecord = struct {
    signal: TelemetryType,
    /// Borrowed. Valid ONLY for the duration of the deliver() call.
    ctx: *const anyopaque,
    /// Render the record (pre-transform) to bytes, e.g. OTLP JSON.
    encode: *const fn (ctx: *const anyopaque, writer: *std.Io.Writer) anyerror!void,
};
```

Consumers that already hold OTLP protobuf can emit it directly; others emit
whatever textual form they want in the object. The library does not prescribe
the record schema inside the dump — the extension prescribes the *container*
(ndjson: one encoded record per line).

### Record lifetime and hot-path cost — copy at delivery, never hold

This is the load-bearing invariant of the whole design:

**Handlers encode synchronously inside `deliver()` and own only the encoded
bytes.** The batch buffer receives a self-contained ndjson line; the moment
`deliver()` returns, no extension holds any reference to the consumer's
record. Record memory has exactly the lifetime it has today — free/reuse it
when `evaluate` returns. Nothing is pinned until flush.

Deferring the copy isn't an optimization we declined — it's impossible to do
correctly:

1. **The spec requires pre-transform delivery**, and the engine applies
   transforms (redact/remove/rename) *in place, immediately after dispatch,
   in the same `evaluate` call*. A handler that stashed a reference and read
   it at flush time would observe redacted/renamed data.
2. Holding references until flush (up to `max_batch_age` = 30 s) would pin
   entire OTLP batches in memory on the edge — the exact memory-pressure
   failure this design exists to avoid.

This is also how we satisfy the spec's "dispatches copies" wording: the copy
is the encoded line; borrowing `ctx` for the duration of one synchronous call
is just how the copy gets made without a second intermediate allocation.

What the hot path actually pays, worst to best case:

| situation                              | cost per record                          |
| -------------------------------------- | ----------------------------------------- |
| no sink / no bindings in snapshot      | one null/len check                        |
| bindings exist, no mode selects record | slice classification (a few compares)     |
| record selected                        | one `encode` + append into batch buffer   |
| record selected, sealed backlog full   | capacity check only — **encode skipped**, drop counted |

The selected-record cost is a bounded, allocation-free serialize (µs-scale
for a typical log record) on the processing thread — a memcpy-class
operation, never I/O, never a lock held across I/O. The capacity check runs
*before* encoding, so a destination outage degrades to a counter increment,
not wasted serialization. And for the flagship `mode: dropped` use, the
records paying the encode are ones the pipeline was discarding anyway.

If that encode ever shows up in a profile, the knobs are consumer-side: a
cheaper `encode` (e.g. memcpy of pre-serialized bytes the consumer already
has), or narrower modes/matchers so fewer records are selected. A zero-copy
"raw bytes" fast path on `DeliveredRecord` is possible later without changing
this invariant.

### 5. Sync plumbing (`provider_http`)

- **Advertise**: when building `ClientMetadata`, iterate the enabled handlers
  in the `Extensions` enum array, ask each for `capabilities()`, and fill
  `supported_extensions` with
  `{type, min_version, config}`. For s3-dump each descriptor is a serialized
  `ExtensionTargetRef` for every target the client can currently reach.
- **Receive**: on `SyncResponse`, route each `extension_configs` entry to
  `handler.configure(entries)`. For s3-dump the entries are serialized
  `ExtensionTarget`s, merged with locally configured targets (broadcast wins
  on `(kind, name)` collision; spec says clients merge).

## `com.usetero/s3-dump` v1.0.0

### Policy-facing config

Exactly what the spec's example shows — a target reference, nothing else:

```yaml
extensions:
  - type: com.usetero/s3-dump
    version: 1.0.0
    mode: dropped
    config:
      target: { kind: s3, name: eu-bucket }
```

`config` bytes = serialized `ExtensionTargetRef`. `validateConfig` decodes it
and checks the target exists (locally configured or broadcast); unknown target
→ skip + sync error, per fail-open.

### Target config (`ExtensionTarget.config` for kind `s3`)

The spec leaves this kind-defined. Define it as JSON (matches the rest of the
repo's config surface and avoids another proto):

```json
{
  "endpoint": "https://s3.eu-west-1.amazonaws.com",  // any S3-compatible URL
  "region": "eu-west-1",
  "bucket": "tero-waste",
  "prefix": "dumps/",
  "force_path_style": false
}
```

**Credentials are never in the target or the policy.** The consumer supplies a
credentials callback at handler construction
(`fn () ?Credentials{access_key, secret_key, session_token}`); the default
reads `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`AWS_SESSION_TOKEN`. No
credentials → deliveries for that target are counted-and-dropped (fail-open).

### Batching — the core of the handler

Records are never uploaded individually. One S3 PUT per record would melt both
the pipeline and the S3 bill; the unit of upload is a **batch**, and the hot
path's only job is appending to one (spec rule 6: off the hot path,
non-blocking).

**Batch key**: `(target, signal, policy_id)`. Signal and policy separate
naturally in storage (waste analysis is per-policy), and the object key below
encodes both. The number of batches is bounded by
`configured targets × 3 signals × policies-with-s3-dump` — small, known at
snapshot compile time.

**Hot path** (`deliver()`): find the open batch — bindings are compiled per
snapshot, so each binding carries its batch index; array lookup, no hashing
per record — check capacity **first** (full backlog → count the drop and
return, no encode), then run the consumer `encode` into the batch's append
buffer, write the `\n`, bump the record count. Under a per-batch mutex; no
I/O, no allocation beyond the batch buffer. See
[Record lifetime](#record-lifetime-and-hot-path-cost--copy-at-delivery-never-hold)
for why the encode happens here and not later.

**Batch limits** (defaults, overridable at handler construction):

| limit               | default | on hit                                   |
| ------------------- | ------- | ---------------------------------------- |
| `max_batch_bytes`   | 4 MiB   | batch is sealed, ready for flush         |
| `max_batch_records` | 10 000  | batch is sealed, ready for flush         |
| `max_batch_age`     | 30 s    | checked in `flush()`, seals stale batches |
| `max_sealed_bytes`  | 32 MiB  | total sealed backlog — new records **drop** |

A record arriving when the sealed backlog is at `max_sealed_bytes` is dropped
and counted (`records_dropped` on the event bus). Backpressure never
propagates to telemetry processing — a dump destination outage costs waste
records, never pipeline latency.

**Flush** — the consumer drives I/O, per this repo's io-threading rule
(`std.Io` passed per call, never stored): `flush(io: std.Io) FlushResult`
seals any over-age open batches (age from `io.now`), uploads each sealed
batch as one object, and releases its buffer. The consumer calls it from a
background task/timer; the handler never spawns threads or sleeps.
Double-buffering (open batch swaps onto the sealed list) keeps `deliver()`
appending while `flush` uploads.

### Data format: edge-native rows, not columnar

Considered: dump in whatever form the edge already has (consumer-encoded
rows), vs. re-encoding into a columnar format (OTel Arrow / OTAP, Vortex,
Parquet). Decision: **edge-native rows at the edge; columnar belongs in a
downstream compaction job, if ever.**

- **No Zig implementation exists** for Arrow, OTAP, or Vortex. Adopting one
  means FFI to a Rust/C++ library or writing a columnar encoder — either
  dwarfs the rest of this design for a waste stream that is written often and
  read rarely.
- **Columnar encoding is a batch-side workload.** Good compression needs large
  row groups, dictionary state, and schema unification across records — CPU
  and memory spent on the edge, on the hot-adjacent path, for exactly the
  records the policy decided were not worth keeping. The edge's job is to get
  bytes out cheaply; fail-open dumping must stay near-free.
- **Rows rehydrate; columns analyze.** The primary consumer of a waste dump is
  "replay these records back into the pipeline" (incident retro, sampling
  regret). Consumer-encoded OTLP rows replay directly. If cheap analytics over
  the dumps becomes real, run a server-side compaction job
  (S3 → Parquet/Vortex) where cores are cheap and batches are huge — the
  standard lake pattern, and it needs zero changes at the edge.
- The consumer `encode` callback already exists because the engine reads
  records through accessors and owns no serialized form. A columnar format
  would force a much fatter contract (full typed schema per record) on every
  consumer.

So the object body is rows in whatever form the edge is working with —
recommended `encode` output is OTLP JSON, but the container doesn't care.

### Object format and key

One object per batch:

- Body: ndjson — each line is one record as produced by the consumer `encode`.
- Key: `{prefix}{signal}/{yyyy}/{mm}/{dd}/{hh}/{policy_id}-{unix_nanos}-{seq}.ndjson`
  Time from `io.now` at flush; `seq` is a per-process counter (no uuid dep).
- `Content-Type: application/x-ndjson`.

### Upload

- One `z3` `putObject(bucket, key, body, options)` per sealed batch, over the
  flush-supplied `io`. z3 handles SigV4, path- vs virtual-host-style (our
  `force_path_style` maps directly), and custom endpoints. The sealed batch is
  a contiguous buffer, so content length and payload hash are trivially
  available (z3's no-chunked-signing limitation doesn't bite us).
- z3 does not do credential discovery — fine, because our design already
  sources credentials from the consumer callback / env (see above) and passes
  them at client init. One z3 client per target per flush (lazily created),
  so std.http.Client's connection pool is reused across that flush's uploads.
- Target configs are snapshotted into a flush-local arena under the mutex;
  uploads never read live target state (a concurrent broadcast `configure`
  can therefore never invalidate memory mid-upload).
- Failure handling: z3's `max_attempts` only retries connection
  establishment — send/receive failures and 5xx responses are not retried by
  the client. So a failed upload is **requeued** onto the sealed backlog and
  retried on subsequent flushes, bounded by the same `max_sealed_bytes` cap
  (overflow drops, counted). The object key is fixed at seal time, so
  retries are idempotent same-key PUTs — a request that succeeded
  server-side before the failure surfaced overwrites itself instead of
  duplicating. Records are lost only when the backlog cap overflows; there
  is still no unbounded queue and no disk spill.
  <!-- ponytail: in-memory retry only; add disk spill if cap-overflow drops show up in practice -->

### Capability advertisement

`capabilities()` returns one serialized `ExtensionTargetRef{kind: "s3", name}`
per configured target, so the provider only sends policies whose extensions
this client can satisfy.

## Scale characteristics (measured)

`task bench:s3` runs scale benchmarks against a local MinIO container
(ReleaseFast, 191-byte records, Apple Silicon dev machine — treat as shape,
not absolutes):

| scenario | result |
| --- | --- |
| deliver, 1 thread | ~16M records/s (~2.9 GiB/s) — ~62ns/record |
| deliver, 4 threads | ~11.5M records/s aggregate — **slower than 1 thread** |
| flush, 64KiB objects | ~250–320 objects/s, ~16–20 MiB/s |
| flush, 1MiB objects | ~100 objects/s, ~100 MiB/s |
| flush, 4MiB objects | ~76–80 objects/s, ~135–142 MiB/s |
| fan-out, 64 policies × 128KiB | ~260 objects/s (one flush ≈ 0.25s) |
| outage flush, max_attempts=1 | ~1ms (connect-refused + requeue is free) |
| outage flush, max_attempts=3 | ~2.3–2.8s for 8 objects (~290ms/object of retry sleeps) |

What this says about scale:

1. **The hot path is not the bottleneck.** Deliver costs ~62ns/record —
   comparable to a whole engine evaluation (~40–60ns) and paid only by
   records a mode selects.
2. **The single dump-wide mutex is a real ceiling under concurrent
   delivery**: 4 threads are ~30% *slower* in aggregate than 1. Irrelevant at
   realistic waste rates (1M records/s is ~6% of the ceiling), but per-batch
   mutexes are the upgrade path if a many-threaded consumer attaches
   `mode: all` extensions to high-volume signals.
3. **Object size dominates upload throughput** (~3–4ms fixed cost per PUT:
   SigV4 + HTTP round trip). 64KiB objects move ~16 MiB/s; 4MiB objects move
   ~140 MiB/s. Keep `max_batch_bytes` ≥ 1MiB and avoid fragmenting batches
   across very many (policy × signal × target) combinations. Uploads within
   a flush are serial; hundreds of batches per flush cycle means seconds of
   flush latency.
4. **z3's in-request connect retries are redundant with our requeue** and
   serialize ~100ms sleeps per object into the flush during outages —
   hence `max_attempts` defaults to 1: a failed batch just waits for the
   next flush instead of stalling the current one.

## Conformance note

README gains a "Supported extensions" table — required by conformance item 9:

| type                  | versions | notes                              |
| --------------------- | -------- | ---------------------------------- |
| `com.usetero/s3-dump` | 1.0.x    | ndjson objects, z3 client, no retries |

## Testing

- **Classification**: engine-level table tests — one policy per mode × record
  {matched-kept, matched-dropped, unmatched}, assert exactly the spec's slice
  reaches a recording fake sink; assert transforms observe untouched records
  after a sink that mutates nothing; assert final decision is identical with
  and without a sink (MUST NOT change outcome).
- **Cross-policy drop**: policy A `keep: none`, policy B `keep: all` with
  `mode: dropped` extension — B's extension receives the record (final-outcome
  semantics).
- **Validation**: unknown type / bad version / unknown target → policy still
  active, extension skipped, error string in `PolicySyncStatus.errors`.
- **Upload (hermetic)**: `src/extensions/s3_stub_test.zig` runs flush against
  an in-process `std.http.Server` stub over a real socket — asserts method,
  path-style URL/key layout, the SigV4 auth header, the payload-sha256 header
  S3 uses for integrity verification, and exact ndjson body bytes; a second
  test scripts a 500 response and asserts the batch is requeued under the
  identical object key and the retry succeeds. Runs in every
  `zig build test`, no docker or network required.
- **Upload (real backend)**: `src/extensions/s3_minio_test.zig`, built as the
  separate `zig build test-s3-e2e` step (excluded from `test` — needs a live
  server) and driven end-to-end by `task test:s3-e2e`, which starts a MinIO
  container via docker, waits for its health check, runs the test, and tears
  the container down (`trap ... EXIT`). Skips itself (`error.SkipZigTest`) if
  the AWS_* / S3_ENDPOINT env vars aren't set, so it's inert when built
  without the task. Verifies against the real backend's own APIs — lists the
  uploaded prefix, fetches the object, and diffs its body byte-for-byte —
  rather than trusting our own response parsing.

## Rollout

1. Vendor v1.6.0 extension protos + regen (no behavior change).
2. `extensions` module: `ExtensionHandler` tagged union, sink, binding
   compilation + validation in `IndexBuilder`, engine dispatch hook.
   Fake-sink tests.
3. Vendor the z3 dependency; smoke-test `putObject` against MinIO.
4. `s3_dump.zig`: config/target parsing, batching, flush/upload, stub tests.
5. `provider_http`: capability advertisement + `extension_configs` routing.
6. README conformance table + consumer wiring example.

Each step lands independently; 1–2 are useful on their own (dispatch mechanism
with no handlers registered is inert).

## Open questions

1. **`mode: all`/`unmatched` cost**: these force sink calls (and encodes) for
   every record of the signal. Fine mechanically, but do we want a
   per-snapshot cap or a warning event when such a policy is loaded?
2. **S3 target JSON vs proto**: JSON chosen above for authoring ergonomics;
   if the tero backend already defines an S3 target proto, use that instead —
   the bytes are opaque to everything but the handler either way.
