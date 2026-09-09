#!/usr/bin/env bash
set -euo pipefail

mkdir -p .zig-cache/policy-stack-reports
for mode in ReleaseFast ReleaseSafe ReleaseSmall; do
  report=.zig-cache/policy-stack-reports/$mode.txt
  binary=.zig-cache/policy-stack-reports/probe-$mode
  zig build-exe \
    -O"$mode" \
    -fstack-report \
    -femit-bin="$binary" \
    --dep policy_runtime \
    -Mroot=src/bench/kernel_probe.zig \
    --dep policy_capacity \
    --dep policy_image \
    --dep policy_compiler \
    -Mpolicy_runtime=src/policy/runtime/root.zig \
    -Mpolicy_capacity=src/policy/capacity.zig \
    -Mpolicy_image=src/policy/image/root.zig \
    --dep policy_capacity \
    --dep policy_image \
    -Mpolicy_compiler=src/policy/compiler/root.zig \
    >"$report" 2>&1
  nm -n "$binary" | awk '/(_runtime\.root|_root)\.evaluate$/ { print "linked evaluator:", $0 }' >>"$report"
  if ! grep -q 'linked evaluator:' "$report"; then
    echo "linked evaluator: inlined or outlined by $mode" >>"$report"
  fi
  echo "$mode stack report: $report"
done
