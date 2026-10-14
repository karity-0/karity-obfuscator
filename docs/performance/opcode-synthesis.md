# Production opcode synthesis measurements

Windows, Python 3.15; seed 1400, three runs per condition. VM only: no source/output passes or packing. OS nonce/wrapper entropy is fixed only in the benchmark. Execution CPU includes loading, decryption and initialization; native process launch is excluded. Build wall and Python CPU samples are retained in the [raw report](opcode-synthesis.json).

Inputs: hello; a four-operation DAG (40 and 2,000 iterations); two repeated DAGs; two numeric functions. The full report has 170 backend/target/input/mode records and 510 timed builds. MOV has no legacy pair fusion, so its combined mode is the Balanced synthesis comparison with fusion explicitly disabled.

## Hot loop: ordinary vs Efficiency synthesis

| Backend / Lua | Build CPU, s | Execution CPU, s | Fusion CPU, s | Output bytes | Blob bytes |
|---|---|---|---|---|---|
| classic / 5.1 | 0.094 → 0.094 | 0.494 → 0.409 | 0.413 | 49,971 → 51,367 | 384 → 384 |
| karity / 5.1 | 0.469 → 0.531 | 2.866 → 2.857 | 2.834 | 150,795 → 154,073 | 434 → 434 |
| mov / 5.1 | 0.266 → 0.203 | 1.520 → 1.558 | — | 131,110 → 132,912 | 37,407 → 37,421 |
| classic / 5.3 | 0.031 → 0.047 | 0.015 → 0.015 | 0.014 | 35,371 → 36,661 | 386 → 386 |
| karity / 5.3 | 0.062 → 0.078 | 0.055 → 0.058 | 0.059 | 145,513 → 148,631 | 436 → 436 |
| mov / 5.3 | 0.062 → 0.125 | 0.397 → 0.374 | — | 114,848 → 116,795 | 37,409 → 37,423 |

Milliseconds and modest CPU differences vary with startup, scheduling, runtime selectors and opcode placement; these samples are not speed guarantees. No preset enables synthesis by default. Additional source pass costs are outside this measurement.

## Actual execution counters

Counters use separately instrumented builds, with instrumentation inserted before integrity binding. Every instrumented result is checked against native Lua. rget/rset counts include helper variants and constants. MOV bank commits count the native/encoded destination stores; its helper calls and microinstructions are distinct from Classic/Karity handler dispatch.

| Backend / Lua | Dispatches (before → after) | rget calls | rset calls | MOV bank commits |
|---|---|---|---|---|
| classic / 5.1 | 10,010 → 4,010 handler | 22,008 → 16,008 | 12,008 → 6,008 | — |
| karity / 5.1 | 10,010 → 4,010 handler | 22,008 → 22,008 | 12,015 → 12,015 | — |
| mov / 5.1 | 26,010 → 30,011 micro | 22,007 → 22,007 | 12,007 → 12,007 | 12,007 → 6,007 |
| classic / 5.3 | 10,010 → 4,010 handler | 22,009 → 16,009 | 12,008 → 6,008 | — |
| karity / 5.3 | 10,010 → 4,010 handler | 14,009 → 14,009 | 8,015 → 8,015 | — |
| mov / 5.3 | 1,826,010 → 1,830,011 micro | 6,008 → 6,008 | 4,007 → 4,007 | 12,007 → 6,007 |

Classic caches inputs and removes dead VM writes. Karity retains all encoded/pending writes and logical events, so rget/rset counts stay unchanged. MOV redirects 6,000 intermediate stores to frame-local values and adds 4,000 scope microinstructions. Its last-write version is tracked by instruction position, including register overwrites.

## Sharing on the repeated-DAG input

| Backend / Lua | Policy | Recipes | Regional | Physical handlers |
|---|---|---:|---:|---:|
| classic / 5.1 | efficiency | 1 | 0 | 2 |
| classic / 5.1 | balanced | 1 | 0 | 2 |
| classic / 5.1 | protection | 2 | 2 | 2 |
| karity / 5.1 | efficiency | 1 | 0 | 2 |
| karity / 5.1 | balanced | 1 | 0 | 2 |
| karity / 5.1 | protection | 2 | 2 | 2 |
| mov / 5.1 | efficiency | 1 | 0 | 1 |
| mov / 5.1 | balanced | 1 | 0 | 1 |
| mov / 5.1 | protection | 2 | 2 | 2 |
| classic / 5.3 | efficiency | 1 | 0 | 2 |
| classic / 5.3 | balanced | 1 | 0 | 2 |
| classic / 5.3 | protection | 2 | 2 | 2 |
| karity / 5.3 | efficiency | 1 | 0 | 2 |
| karity / 5.3 | balanced | 1 | 0 | 2 |
| karity / 5.3 | protection | 2 | 2 | 2 |
| mov / 5.3 | efficiency | 1 | 0 | 1 |
| mov / 5.3 | balanced | 1 | 0 | 1 |
| mov / 5.3 | protection | 2 | 2 | 2 |

Alias/defer event contracts can require distinct physical handlers even when semantic recipes share. All retained operand/event words are still serialized; storage compression is not an effect of this feature. Recipes add runtime source in many cases. The hello input admits no recipe, and its feature-off path retains the old output.

## Validation and limits

The complete existing CI manifest passed (58 regression suites, generated-doc check, dependency audit and 18/18 Lua fixtures). Real synthesis regressions passed on Python 3.12 and 3.15 across Classic/Karity/MOV and Lua 5.1/5.3, including protected graph/pending/block variants, multi-VM, morphing/junk, closures/varargs/coroutines/errors, numeric edge cases, malformed layout/bindings and budget fallback. MOV high release-check and real browser configuration save/restore passed. Existing tests and timeouts remain unchanged.

Large 16-step mutated bodies originally exceeded Lua’s 200-local limit. They now reuse the existing scratch compactor. A 32-recipe stress case measured over 131,000 kernel instructions; private closure banks bound each function’s dispatch jumps without dropping steps or mutation. These are compiler-budget adaptations, not fewer protected source regions.

The estimator ranks loop/repeated use and backend-specific structural work, while compiler probes bound generated handlers. It does not model nanosecond costs of every runtime graph/helper. Default user and legacy presets remain opt-in because dispatch/access reductions do not consistently improve total time or output size. See the [implementation contract](../design/adaptive-opcode-synthesis.md) for preserved events and conservative fallback.
