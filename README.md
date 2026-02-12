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

- [Zig](https://ziglang.org/) >= 0.15.2
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

// Create a registry
var registry = policy.Registry.init(allocator, bus);
defer registry.deinit();

// Create and register a file provider
const file_provider = try policy.FileProvider.init(allocator, bus, "local", "policies.json");
defer file_provider.deinit();

const provider_interface = policy.Provider.init(file_provider);
try registry.registerProvider(&provider_interface);
```

## Architecture

```
src/
  root.zig              # Public API - all exports
  policy_engine.zig     # Hyperscan-based policy evaluation
  matcher_index.zig     # Inverted index for pattern matching
  registry.zig          # Policy registry with atomic snapshots
  parser.zig            # Policy parsing
  loader.zig            # Async policy loader
  provider.zig          # Provider interface
  provider_file.zig     # File-based provider
  provider_http.zig     # HTTP-based provider
  source.zig            # Source types and metadata
  types.zig             # Shared type definitions
  log_transform.zig     # Log transformation (redact, remove, rename, add)
  sampler.zig           # Log sampling
  trace_sampler.zig     # Trace sampling
  rate_limiter.zig      # Rate limiting
  hyperscan.zig         # Vectorscan/Hyperscan C bindings
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

## Task Commands

This project uses [Task](https://taskfile.dev/) for common operations:

| Command              | Description                                      |
| -------------------- | ------------------------------------------------ |
| `task`               | Build (debug)                                    |
| `task test`          | Run all tests                                    |
| `task build:release` | Build with ReleaseFast                           |
| `task build:safe`    | Build with ReleaseSafe                           |
| `task format`        | Format source files                              |
| `task format:check`  | Check formatting                                 |
| `task lint`          | Run linting checks                               |
| `task clean`         | Clean build artifacts                            |
| `task do`            | Run all pre-commit checks (format + lint + test) |
| `task signoff`       | Full signoff (do + build:safe + gh signoff)      |
| `task ci:setup`      | Install CI/dev dependencies                      |

## License

See [LICENSE](LICENSE).
