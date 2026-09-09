#!/usr/bin/env bash
set -euo pipefail

zig build build-bench
benchmark=zig-out/bin/bench

if command -v perf >/dev/null 2>&1; then
  exec perf stat \
    -e cycles,instructions,L1-icache-load-misses,branch-misses \
    -- "$benchmark"
fi

if command -v xcrun >/dev/null 2>&1 && [[ $(xcrun xctrace list templates 2>/dev/null) == *"CPU Counters"* ]]; then
  trace=.zig-cache/policy-cpu-counters.trace
  rm -rf "$trace"
  exec xcrun xctrace record \
    --template 'CPU Counters' \
    --output "$trace" \
    --launch -- "$benchmark"
fi

echo "CPU counter collection requires perf or the Xcode CPU Counters template" >&2
exit 1
