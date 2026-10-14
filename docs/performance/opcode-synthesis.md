# Production opcode synthesis measurements

Windows, Python 3.15; seed 1400, three runs per condition. VM only: no source/output passes or packing. OS nonce/wrapper entropy is fixed only in the benchmark. Execution CPU includes loading, decryption and initialization; native process launch is excluded. Build wall and Python CPU samples are retained in the [raw report](opcode-synthesis.json).

Inputs: hello; a four-operation DAG (40 and 2,000 iterations); two repeated DAGs; two numeric functions. The full report has 170 backend/target/input/mode records and 510 timed builds. MOV has no legacy pair fusion, so its combined mode is the Balanced synthesis comparison with fusion explicitly disabled.

## Hot loop: ordinary vs Efficiency synthesis

| Backend / Lua | Build CPU, s | Execution CPU, s | Fusion CPU, s | Output bytes | Blob bytes |
|---|---|---|---|---|---|
| classic / 5.1 | 0.125 → 0.109 | 1.347 → 1.032 | 0.947 | 49,971 → 51,369 | 384 → 384 |
| karity / 5.1 | 0.391 → 0.562 | 8.686 → 10.230 | 10.397 | 150,795 → 154,073 | 434 → 434 |
| mov / 5.1 | 0.234 → 0.891 | 3.458 → 4.190 | — | 131,110 → 132,853 | 37,407 → 37,421 |
| classic / 5.3 | 0.016 → 0.031 | 0.033 → 0.030 | 0.031 | 35,371 → 36,659 | 386 → 386 |
| karity / 5.3 | 0.031 → 0.297 | 0.220 → 0.241 | 0.248 | 145,513 → 148,627 | 436 → 436 |
| mov / 5.3 | 0.297 → 0.438 | 1.178 → 1.244 | — | 114,848 → 117,509 | 37,409 → 37,363 |

Milliseconds and modest CPU differences vary with startup, scheduling, runtime selectors and opcode placement; these samples are not speed guarantees. Built-in user presets enable policy-budgeted synthesis; legacy/custom settings retain their values. Additional source pass costs are outside this measurement.

## Actual execution counters

Counters use separately instrumented builds, with instrumentation inserted before integrity binding. Every instrumented result is checked against native Lua. rget/rset counts include helper variants and constants. MOV bank commits count the native/encoded destination stores; its helper calls and microinstructions are distinct from Classic/Karity handler dispatch.

| Backend / Lua | Dispatches (before → after) | rget calls | rset calls | MOV bank commits |
|---|---|---|---|---|
| classic / 5.1 | 10,010 → 4,010 handler | 22,008 → 16,008 | 12,008 → 6,008 | — |
| karity / 5.1 | 10,010 → 4,010 handler | 22,008 → 22,008 | 12,015 → 12,015 | — |
| mov / 5.1 | 26,010 → 30,011 micro | 22,007 → 22,007 | 12,007 → 12,007 | 12,007 → 6,007 |
| classic / 5.3 | 10,010 → 4,010 handler | 22,009 → 16,009 | 12,008 → 6,008 | — |
| karity / 5.3 | 10,010 → 4,010 handler | 14,009 → 14,009 | 8,015 → 8,015 | — |
| mov / 5.3 | 1,826,010 → 1,822,011 micro | 6,008 → 6,008 | 4,007 → 4,007 | 12,007 → 6,007 |

Classic caches inputs and removes dead VM writes. Karity retains encoded/pending writes and logical events. MOV redirects dead stores to frame-local values. Its proven integer DAGs feed encoded SSA values and cached inputs through existing LOOKUP arithmetic, eliminating two representation-boundary records per step; number-only scopes retain their guards. Actual counts above distinguish those paths.

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
| classic / 5.3 | balanced | 2 | 1 | 2 |
| classic / 5.3 | protection | 2 | 2 | 2 |
| karity / 5.3 | efficiency | 1 | 0 | 2 |
| karity / 5.3 | balanced | 2 | 1 | 2 |
| karity / 5.3 | protection | 2 | 2 | 2 |
| mov / 5.3 | efficiency | 1 | 0 | 1 |
| mov / 5.3 | balanced | 1 | 0 | 1 |
| mov / 5.3 | protection | 2 | 2 | 2 |

Alias/defer event contracts can require distinct physical handlers even when semantic recipes share. All retained operand/event words are still serialized; storage compression is not an effect of this feature. Recipes add runtime source in many cases. The hello input admits no recipe, and its feature-off path retains the old output.

## Validation and limits

The integration baseline passed the complete CI manifest (58 suites). This follow-up reruns affected existing suites and 141 real synthesis builds on each of Python 3.12/3.15 across Classic/Karity/MOV and Lua 5.1/5.3. Coverage includes protected graph/pending/block variants, multi-VM, mixed domains, morphing/junk, closures/varargs/coroutines/errors, numeric edge cases, malformed layout/bindings and budget fallback. The additional 28 builds cover hidden dispatch with six layouts and actual Strong VM settings; four more exercise actual Maximum settings and default budgets on a larger DAG. Protected Karity logical route/state traces match the baseline on both targets. MOV high release-check and configuration save/restore pass. Existing timeouts remain unchanged.

Large 16-step mutated bodies originally exceeded Lua’s 200-local limit. They now reuse the existing scratch compactor. A 32-recipe stress case measured over 131,000 kernel instructions; private closure banks bound each function’s dispatch jumps without dropping steps or mutation. These are compiler-budget adaptations, not fewer protected source regions.

Admission measures renderer/mutation compiler costs, runtime source and binding alternatives, with independent code and diversity allowances. Efficiency prefers estimated work savings; Balanced/Protection can pay bounded overhead for distinct opcode/execution forms. This is not a nanosecond model of every graph/helper. Binding probes are pure and do not consume instruction-padding RNG. The four built-in policies enable synthesis; generic/legacy configuration remains opt-in for compatibility. See the [implementation contract](../design/adaptive-opcode-synthesis.md) for preserved events and conservative fallback.
