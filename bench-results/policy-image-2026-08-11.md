# PolicyImage benchmark comparison

Date: 2026-08-11  
Platform: Apple arm64, macOS 26.5.2  
Compiler: Zig 0.16.0, `ReleaseFast` benchmark executable

Both runs used `zig build bench` under `/usr/bin/time -l`, 100,000 evaluations
per case. The final suite uses a volatile checksum so decisions cannot be
discarded. Setup and compilation happen outside timed zBench loops.

## Baseline compatibility runtime

The pre-change suite reported the following averages:

| Case | 1 policy | 10 policies | 100 policies | 1,000 policies |
|---|---:|---:|---:|---:|
| log regex | 45 ns | 64 ns | 66 ns | 67 ns |
| metric regex | 38 ns | 39 ns | 37 ns | 38 ns |
| trace regex | 36 ns | 37 ns | 37 ns | 37 ns |

Those numbers did not scale with policy count and were too small for actual
Hyperscan work. More importantly, the 1,000-policy cases exceeded the evaluator's
256-entry stack arrays. They are retained as the requested baseline but must not
be interpreted as valid 1,000-policy throughput. The compatibility compiler now
rejects policy 257 instead of permitting out-of-bounds evaluation.

Baseline whole-command counters were 15.00 s real, 14.49 s user, 0.50 s system,
737,446,202 retired instructions, 205,669,301 cycles, 669,007,872-byte maximum
RSS reported across the build tree, and a 15,958,520-byte peak process footprint.

## Immutable image runtime

The final native exact matcher deliberately scans every policy. Unmatched and
matched cases are separate:

| Policies | Unmatched average | Matched average |
|---:|---:|---:|
| 1 | 21 ns | 24 ns |
| 10 | 85 ns | — |
| 100 | 728 ns | 1.334 us |
| 256 | 1.842 us | — |
| 1,000 | 7.171 us | 13.261 us |

At 1,000 policies that is about 7.17 ns per failed exact condition and 13.26 ns
per full match including worker statistics, stable sampling, rate outcome, and
winner selection. The anti-elision checksum was
`6710871467962963328`.

For the 1,000-policy configuration, the actual serialized image is 85,116 bytes
and the complete worker storage upper bound is 48,672 bytes. Three configured
96,128-byte image slots plus one worker region total 337,056 bounded bytes;
there are no per-matcher 64-way scratch pools or runtime allocations.

The final, larger suite (12 compatibility and 8 image cases) took 18.26 s real,
17.76 s user, and 0.53 s system, with 735,141,046 retired instructions,
209,668,649 cycles, 666,730,496-byte build-tree max RSS, and a
16,957,944-byte peak process footprint. Because the final workload contains
eight additional cases, whole-command CPU and RSS are environmental checks, not
an apples-to-apples speedup claim. Relative to baseline, retired instructions
were 0.31% lower, cycles 1.94% higher, build-tree max RSS 0.34% lower, and peak
process footprint 6.26% higher.

The linked production evaluator measured 1,168 bytes at page offset 0, safely
inside its dedicated 4 KiB instruction-page budget.

The Xcode CPU Counters task was also verified against the installed `bench`
binary (exit status 0). Its trace, including cycle, instruction-delivery,
discarded-work/branch, processing, and useful-work samples, is generated at
`.zig-cache/policy-cpu-counters.trace`; the local capture was 141 MiB and is
intentionally not committed. Linux CI uses explicit `cycles`, `instructions`,
`L1-icache-load-misses`, and `branch-misses` perf events.

## Post-cleanup ABI v2 check

After removing the compatibility runtime and adding OTel threshold/tracestate
sampling to image ABI v2, the same machine measured 9.007 us for 1,000 failed
exact policies, 13.380 us for 1,000 fully matched policies, and 30 ns for one
matched policy with OTel sampling. The larger 48-byte policy descriptor makes
the 1,000-policy image 101,116 bytes; worker storage remains 48,672 bytes. The
ABI v2 evaluator measures 1,224 linked bytes at page offset zero.
