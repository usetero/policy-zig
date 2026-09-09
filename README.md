# policy-zig

`policy-zig` compiles provider policies into immutable, relocatable images and
evaluates projected telemetry fields using caller-owned fixed storage.

The runtime does not depend on generated telemetry objects, JSON, transport,
allocators, locks, or observability I/O. Generated policy protobuf declarations
exist only at the cold source boundary.

## API

The architectural types are `PolicyCompiler`, `PolicyImage`, `WorkerState`, and
`Decision`. Familiar names from the original library remain as thin aliases:

- `Registry` is the exact-epoch, three-slot image registry.
- `Snapshot` is an immutable `PolicyImage`.
- `PolicyEngine` binds an image and one worker state.
- `PolicyResult` is the compact `Decision`.

```zig
const policy = @import("policy_zig");

var compiler = try policy.PolicyCompiler.init(capacity, compiler_workspace, image_slot);
const bytes = try compiler.compile(.{ .policies = normalized_policies, .seed = seed });
var snapshot = try policy.Snapshot.open(bytes);
var worker = try policy.WorkerState.init(worker_storage, capacity);
const engine = policy.PolicyEngine.init(&snapshot, &worker);

const values = [_]policy.ValueRef{.{ .string = record_body }};
const result = engine.evaluate(&values, .{
    .image_epoch = epoch,
    .worker_id = worker_id,
    .signal = .log,
    .record_key = stable_record_key,
});
```

OpenTelemetry consistent probability sampling is compiled into the image. It
supports 56-bit trace-ID randomness, `th`/`rv` tracestate propagation,
hash-seed, proportional, and equalizing modes. Tracestate output is materialized
outside the evaluator with `Decision.updateTraceState`.

Regex remains an optional runtime capability supplied by the host through one
worker-compatible backend and scratch region. The core library has no native
Hyperscan dependency.

## Checks

```sh
task lint
task test
task check:kernel
task report:stack
task bench
```

See [design/policy-image.md](design/policy-image.md) for the format and ownership
contract and [bench-results](bench-results/) for recorded measurements.
