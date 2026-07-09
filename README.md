# policy-zig

Zig library for the [Tero](https://usetero.com) Policy spec. Provides policy
loading, evaluation, and transformation for telemetry data (logs, metrics,
traces).

Extracted from [usetero/edge](https://github.com/usetero/edge) as a standalone
library so it can be consumed independently.

## Features

- **Policy Engine** - Hyperscan-based pattern matching for efficient policy
  evaluation against telemetry data
- **Multiple Providers** - Load policies from file or HTTP sources with
  priority-based conflict resolution
- **Async Loading** - Non-blocking policy loading so services can start handling
  requests immediately
- **Transforms** - Apply log transformations (redact, remove, rename, add
  fields) based on matched policies
- **Sampling & Rate Limiting** - Built-in support for log/trace sampling and
  rate limiting
- **Lock-free Reads** - Atomic snapshot pointer for concurrent policy access
  without locks

## Requirements

- [Zig](https://ziglang.org/) >= 0.16.0
- [Vectorscan](https://github.com/VectorCamp/vectorscan) (or Hyperscan) -
  high-performance regex matching

### Install Vectorscan

**macOS:**

```sh
brew install vectorscan pkg-config
```

**Debian/Ubuntu:**

```sh
sudo apt-get install -y libhyperscan-dev pkg-config
```

**RHEL/Fedora:**

```sh
sudo yum install -y hyperscan-devel pkg-config
```

Or run `task ci:setup` to install automatically.

## Quick Start

### Build

```sh
zig build
```

### Test

```sh
zig build test
```

### Using as a Dependency

Add to your `build.zig.zon`:

```zig
.dependencies = .{
    .policy_zig = .{
        .url = "git+https://github.com/usetero/policy-zig#<commit>",
        .hash = "<hash>",
    },
},
```

Then in your `build.zig`:

```zig
const policy_dep = b.dependency("policy_zig", .{
    .target = target,
    .optimize = optimize,
});
your_module.addImport("policy_zig", policy_dep.module("policy_zig"));
```

### Library Usage

```zig
const policy = @import("policy_zig");

// Create a registry — capability-agnostic; can serve multiple consumers.
var registry = policy.Registry.init(allocator, bus);
defer registry.deinit();

// Create a file provider and subscribe it to the registry (one step)
const file_provider = try policy.FileProvider.init(allocator, bus, .{
    .id = "local",
    .path = "policies.json",
});
defer file_provider.deinit();

try registry.subscribe(.{ .file = file_provider });

// Evaluate telemetry. The accessor is a comptime parameter: declare it as
// a module-scope const, then pass &my_log_accessor positionally. Each
// consumer (OTLP, Datadog, Prometheus, …) supplies its own accessor at
// its evaluate site, so one registry can serve many consumers.
const engine = policy.PolicyEngine.init(bus, &registry);
var policy_id_buf: [16][]const u8 = undefined;
const result = engine.evaluate(.log, &my_log_accessor, &my_log_ctx, &policy_id_buf, .{
    .scratch = arena.allocator(),
});

// Transforms whose required primitive (set/delete/move) is unwired on the
// accessor are *eliminated at compile time* for that callsite — no
// runtime branch, no code emitted. Different consumers can apply
// different subsets of a policy with zero per-call overhead.

// Periodically flush per-policy stats to providers
registry.flushStats();
```

## Architecture

```
src/
  policy/
    root.zig            # Public API - all exports
    policy_engine.zig   # Hyperscan-based policy evaluation
    matcher_index.zig   # Inverted index for pattern matching
    registry.zig        # Policy registry with atomic snapshots
    parser.zig          # Policy parsing
    loader.zig          # Async policy loader
    provider.zig        # Provider callback types
    provider_file.zig   # File-based provider
    provider_http.zig   # HTTP-based provider
    source.zig          # Source types and metadata
    types.zig           # Shared type definitions and Provider tagged union
    log_transform.zig   # Log transformation (redact, remove, rename, add)
    sampler.zig         # Log sampling
    trace_sampler.zig   # Trace sampling
    rate_limiter.zig    # Rate limiting
    hyperscan.zig       # Vectorscan/Hyperscan C bindings
  extensions/           # Policy extensions (spec v1.6.0): s3-dump handler
  observability/        # Event bus, spans, formatters
  proto/                # Generated protobuf definitions
```

### How Policy Evaluation Works

1. Policies are compiled into Hyperscan databases indexed by matcher key
2. At evaluation time, field values are scanned against the compiled databases
3. Match counts are aggregated per policy using O(1) array operations
4. The highest priority fully-matched policy determines the filter/transform
   result

This gives O(k \* n) performance where k = unique matcher keys and n = input
text length, independent of policy count.

## Supported Extensions

Per policy-spec conformance item 9, this implementation supports the following
extension `type`/`version` pairs (see `design/extensions.md` and the
`extensions` module):

| type                  | versions | notes                                                                                      |
| --------------------- | -------- | ------------------------------------------------------------------------------------------ |
| `com.usetero/s3-dump` | 1.0.x    | batched ndjson objects via z3; failed uploads retried in-memory (bounded), idempotent keys |

Extensions declared by a policy but not supported (or with an unresolvable
target) are skipped fail-open and reported via `PolicySyncStatus.errors`; the
policy's core match/keep/transform still applies.

Enabling extensions in a consumer (the `extensions` module owns the handlers
and adapts them to policy_zig's seams):

```zig
const ext = @import("extensions");

// One Extensions object owns every enabled handler. Encoders are per-signal
// because the engine hands the sink an opaque record it can't serialize.
var exts = ext.Extensions.init(allocator, .{ .log = encodeLog });
defer exts.deinit();

// Enable s3-dump and configure targets directly on the returned handle.
// Credentials come from the consumer (env/secrets) — never from policies.
const s3 = exts.enableS3Dump(allocator, .{}, .{
    .access_key_id = key,
    .secret_access_key = secret,
});
try s3.addTarget(io, "eu-bucket",
    \\{"bucket": "tero-waste", "region": "eu-west-1", "prefix": "dumps/"}
);

// One call wires the resolver (snapshot compile) + sync hooks (advertised on
// each provider). subscribe() then pushes the hooks to every provider — the
// HTTP provider advertises capabilities and receives broadcast targets; a
// file provider accepts and ignores them.
exts.register(&registry);
try registry.subscribe(.{ .http = http_provider });

// Per evaluate: pass the sink so selected records are delivered.
_ = engine.evaluate(.log, &accessor, &record, &buf, .{
    .io = io,
    .extension_sink = exts.sink(),
});

// From a background loop: flush uploads and read the result as metrics.
const r = exts.flush(io, .{});
// r.objects_uploaded / .records_dropped / .backlog_bytes → your metrics client
```

`com.usetero/s3-dump`'s upload path is verified two ways: `zig build test`
(covered by `task test`) includes a hermetic test against an in-process HTTP
stub — no network or docker needed — and `task test:s3-e2e` spins up a real
MinIO container via docker and round-trips an upload through it.

## Task Commands

This project uses [Task](https://taskfile.dev/) for common operations:

| Command              | Description                                                     |
| -------------------- | --------------------------------------------------------------- |
| `task`               | Build (debug)                                                   |
| `task test`          | Run all tests                                                   |
| `task test:s3-e2e`   | Real-storage s3-dump smoke test against MinIO (requires docker) |
| `task bench:s3`      | s3-dump scale benchmarks against MinIO (requires docker)        |
| `task build:release` | Build with ReleaseFast                                          |
| `task build:safe`    | Build with ReleaseSafe                                          |
| `task format`        | Format source files                                             |
| `task format:check`  | Check formatting                                                |
| `task lint`          | Run linting checks                                              |
| `task clean`         | Clean build artifacts                                           |
| `task do`            | Run all pre-commit checks (format + lint + test)                |
| `task signoff`       | Full signoff (do + build:safe + gh signoff)                     |
| `task ci:setup`      | Install CI/dev dependencies                                     |

## License

See [LICENSE](LICENSE).
