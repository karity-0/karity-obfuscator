# Literal Mosaic measurements and validation

Comparison: `3b8378f` → `d9873d2`, branch `future`. Fixture:
`test/scripts/01_helloWorld.lua` (20 bytes), seed 9300, `PYTHONHASHSEED=0`,
Windows 11, CPython 3.15.0 and the same native Lua 5.3 executable/dependencies.
The [raw report](literal-mosaic.json) contains every pass, compiler measurements,
metrics, runtime samples, environment, hashes and ordinary build measurements.
Baseline rows were retained from an earlier isolated serial run with the same
environment/input/seed; all final after rows were rerun serially without other
local builds. VM random choices change when upstream generation consumes a
different RNG sequence, even with the same initial seed. This is a single small
fixture and seed, not an across-project performance guarantee.

The existing packer uses `secrets`, and KAE blobs/wrapper tails use independent
cryptographic randomness. That behavior is preserved. Mosaic/source strategy
generation is seed-reproducible; fully packed files need not be byte-identical,
and slight max-output byte differences between profiled/ordinary runs are expected.

## Ordinary builds: diagnostics disabled

Both revisions use their normal default build path, without `--profile-report`.
Wall time includes Python/toolchain startup; runtime is one native execution,
including Lua startup. Each output was compared with original stdout.

| Build | Output bytes | Build seconds | Lua seconds | Peak child memory MiB |
|---|---:|---:|---:|---:|
| mov high | 2,038,461 → 2,287,884 | 9.84 → 8.53 | 4.358 → 2.795 | 295.0 → 239.7 |
| mov max | 2,994,090 → 1,385,802 | 15.79 → 11.30 | 7.963 → 5.774 | 396.3 → 250.8 |
| karity high | 12,073,215 → 12,382,076 | 81.28 → 86.10 | 3.273 → 2.088 | 2898.9 → 2532.6 |
| karity max | 10,666,932 → 8,217,296 | 128.70 → 119.01 | 20.124 → 16.108 | 4008.5 → 3013.7 |

## Profiled builds and source diagnostics

Both revisions enable their existing profiler. The new revision additionally
collects Mosaic lexical counters for every generated expression and bounded AST
samples. Therefore these timings include additional diagnostics. Runtime is the
median of three separate native executions, not timing the profiler. Peak memory
is the build child's Windows peak working set sampled every 50 ms; subprocess
memory is excluded. Source diagnostics retain every intermediate pass snapshot
and measure each prototype, so their memory differs from an ordinary build.
Source runtime is dominated by process startup at this fixture size.

| Build | Output bytes | Diagnostic wall seconds | Lua median seconds | Peak child memory MiB |
|---|---:|---:|---:|---:|
| source high | 227,556 → 150,780 | 3.35 → 3.19 | 0.024 → 0.022 | 68.8 → 77.1 |
| source max | 256,377 → 169,836 | 3.34 → 3.65 | 0.024 → 0.021 | 77.7 → 77.9 |
| mov high | 2,038,461 → 2,287,884 | 12.52 → 10.36 | 3.861 → 3.100 | 295.0 → 241.0 |
| mov max | 2,991,935 → 1,385,044 | 15.43 → 11.25 | 8.186 → 5.639 | 395.7 → 251.1 |
| karity high | 12,073,215 → 12,382,076 | 84.36 → 95.97 | 3.315 → 2.335 | 2898.4 → 2534.6 |
| karity max | 10,668,007 → 8,218,146 | 128.63 → 124.45 | 20.431 → 15.906 | 4008.5 → 3016.2 |

| Source stage | Pass seconds | Output bytes | Replacements |
|---|---:|---:|---:|
| high StringObfuscationPass | 0.001 → 0.061 | 6,825 → 12,121 | 4 → 4 |
| high FunctionObfuscationPass | 1.727 → 1.795 | 196,438 → 178,402 | 4 → 4 |
| high NumberObfuscationPass | 0.177 → 0.188 | 234,131 → 181,493 | 499 → 41 |
| high MemeStringsPass | 0.214 → 0.187 | 276,871 → 185,298 | 1045 → 91 |
| max StringObfuscationPass | 0.001 → 0.046 | 6,825 → 12,121 | 4 → 4 |
| max FunctionObfuscationPass | 1.632 → 1.976 | 227,527 → 178,402 | 4 → 4 |
| max NumberObfuscationPass | 0.161 → 0.208 | 266,402 → 181,493 | 499 → 41 |
| max StringEncodePass | 0.231 → 0.188 | 267,257 → 200,558 | 54 → 920 |
| max MemeStringsPass | 0.207 → 0.231 | 310,643 → 204,354 | 1087 → 91 |

Pure timed source generation: high 2.714 → 2.719 s; max 2.849 → 3.111 s.
The source diagnostic wall column also includes native compilation/prototype
inspection after timed generation. These two times must not be conflated.
VM input falls 227,556 → 150,780 bytes (high) and 256,377 → 169,836 bytes (max).
Source final prototype instructions fall 21,156 → 12,559 (high) and
23,297 → 12,559 (max).

## Protection scope and observed costs

String reconstruction, StringObf → FunctionObf order, source NumberObf's full
algorithm, VM handlers/dispatch/state/blob protection, and high/max output style
passes remain enabled. Generated reconstruction/CFF operands receive one bounded
generation instead of uncontrolled follow-up Number/Meme layers. Some bounded
operands use a literal rather than nested arithmetic; this intentionally changes
operand complexity. Preserved coverage does not prove equal resistance to every
analysis technique. File size and visual diversity are not security scores.

For this seed, main CFF blocks change 49 → 44, reconstruction statement counters
176 → 159, coalesced state counters 127 → 115, and dispatcher helpers remain 3.
Different upstream random draws select different existing reconstruction/CFF
styles. Reconstruction still has multiple states and compiler probes; there is
no blanket StringObf exclusion. Both profiles report `compact_retry=false` and
no protection budget adjustment. The large-function regression independently
forces 16–26 helpers on Lua 5.1/5.3, beyond the former fixed-three limit.

The source Number pass changes 499 → 41 replacements and Meme 1,045 → 91 (high;
max previously 1,087). The removed replacements are already generated operands,
not missing protection for original app numbers. In the source fixture's four
string wrappers, the former transport recorded 458 original-style reconstruction
operands; they are now identified as generated. Source pass skip counters record
9,659 protected numeric leaves at each Number/Meme stage, not 9,659 unique strings.

The first implementation serialized each numeric leaf inside a handled expression.
Whole-expression transport removed redundant markers; clipped renderer spans now
use AST validation and fall back to safe individual numeric-leaf transport.
Early Unicode memes also forced large byte/character tables. Compact offset arrays
and bulk ASCII construction reduce that overhead without changing coordinates.
Source diagnostics still pay for metadata/sampling and max escapes 920 strings
instead of 54 because memes now exist before its StringEncode stage.

Karity high's profiled output grows 2.6% and diagnostic build time increases.
Its VM-output Number stage processes 94,475 literals versus 91,401, and its new
diagnostics increase that stage from 2.541 to 7.486 s. Meme grows from 0.848 to
3.069 s under complete lexical counting. Detailed AST work is bounded to 128
samples per phase/strategy. Ordinary-build measurements above separate this
instrumentation cost from default use. Final output can grow for a particular
seed despite a smaller input; stochastic VM variants and the retained full
output Number/Meme passes still determine cost. No pass was removed to hide it.

## Visual Diversity Metrics

Source high/max generate 5,674 recorded expressions: 2,396 number literals,
2,292 bounded number expressions, 854 generated memes, 41 full original numbers
and 91 original meme replacements. Generated-origin counts are 433 StringObf
and 5,109 FunctionObf expressions. Compiler candidate work may contribute;
these are generation diagnostics, not a final-file census.

Numeric notation includes 5,974 decimal integers, 3,061 hex integers, 285 decimal
scientific forms, 646 hex floats and 14 decimal floats; secondary counts include
1,647 uppercase hex prefixes, 167 uppercase hex exponents, 140 leading decimal
dots and 155 leading hex dots. Operator families include floor division, bitwise,
arithmetic, unary, string length, modulo and shifts. Average recorded expression
has 1.33 operations and 15.84 characters. The 516 structural samples contain 62
normalized shapes, sampled mean depth 2.88 and maximum depth 12 (including full
source expressions). This is a bounded deterministic sample, not an exhaustive
maximum. No uncalibrated DiversityScore/security rating is introduced.

## Implementation and validation

The [API/design document](../literal-mosaic.md) describes exact call flow,
activation matrix, budgets, provenance and phase boundaries. Changes are grouped:

- Common service/metrics: `literal_mosaic.py`, `mosaic_metrics.py`, existing
  `number_expressions.py`, extracted `meme_expressions.py`, Number/Meme pass hooks.
- Callers/metadata: StringObf, FunctionObf, `numeric_provenance.py`, Unicode
  `ts_utils.py`, VM output/runtime emitters and packer scope boundaries.
- Activation/config: Pipeline, Profiler, Registry, typed config, SelectionPlan
  and SelectionRuntime; new marked Number/Meme regions and CLI actual lists.
- Verification/docs: `run_literal_mosaic_regression.py`, shared CI manifest,
  `compare_literal_mosaic.py`, configuration generator and pass/design docs.

Local tests passed for NumberObf (19,456 numeric cases), MemeStrings, StringObf,
54 selection cases, typing/Linux+Windows mypy, structured VM output (including
explicit duplicate Number layers), Function compiler costs, Lua 5.1/5.3 numerical
types, multiple/trailing nil returns, closure/upvalue, coroutine/error behavior,
all activation combinations in source/VM/packer, real CLI overrides, deterministic
profiling-on/off output, metadata slicing/transport/emitter round trips and marker
corruption. All 12 profiled and eight ordinary benchmark outputs execute with
original stdout. Existing MOV high release-check is in the shared full CI manifest.

The full unchanged CI matrix plus the new regression runs on Linux Python 3.12,
Linux Python 3.15 and Windows Python 3.12; verification is tracked in
[code validation run 38046952305](https://github.com/karity-0/karity-obfuscator/actions/runs/38046952305).
Local full-suite runs were deliberately stopped for isolated benchmarks after
their completed stages; they are not claimed as complete local passes. No tests
were deleted and no timeouts increased. Native Lua 5.1/5.3 are exercised through
Lupa; optional external Lua 5.1 executable checks require their existing environment
configuration. Full String/Number/Meme passes still require Lua 5.3; portable
shared generation and FunctionObf do not imply a full Lua 5.1 high/max preset.

GUI granular controls, a generic string-generating Mosaic API, VM internal hot
generator rewrites and environment interception are intentionally omitted.
Further work should measure multiple real workloads/seeds and, if needed, reduce
full lexical profiling overhead without disturbing generation or PRNG state.

## Reproduction

Archive baseline `3b8378f` into an isolated checkout under the workspace. Use the
same interpreter/dependencies and keep other builds idle:

```sh
python tools/compare_literal_mosaic.py --before temp-baseline --output measured.json
python tools/compare_literal_mosaic.py --before temp-baseline --unprofiled --runtime-repeats 1 --output ordinary.json
python test/run_ci.py
```

Seeded benchmarks cannot use `--release-check`; its independent unseeded MOV high
CLI case is covered by the existing regression. `--reuse-before-report` validates
the saved environment/seed/profiling mode and reruns every after row when iterating
on generation overhead. It is optional; a fresh full serial comparison is preferable
for publication-quality repeated measurements.
