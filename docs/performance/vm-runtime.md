# Karity VM runtime specialization

Baseline: f711103, Windows, Python 3.15, seed 9171, PYTHONHASHSEED=0.
[Lua 5.3 paired measurements](vm-runtime-lua53.json) and
[Lua 5.1 paired measurements](vm-runtime-lua51.json) contain settings,
individual samples, stage timings, graph-bank sizes and function counts.

These are VM-only builds through VMPass: no source passes, VM output passes
or packing. Bytecode format, cipher, blob encoding, NumberObf, StringObf and
CFF passes are unchanged. Default uses VM defaults. Protected requests two
VMs, maximum occurrence/cross-instruction/runtime-polymorphism/block-variation
rates, semantic state threading, argument/upvalue/table/branch virtualization,
dispatch target hiding, fake handlers, mutation, junk and integrity constants.
Actual VM counts remain bounded by the existing layout policy. The graphs_off
setting disables arithmetic occurrence graphs and runtime polymorphism;
semantic/control/loop protection is not globally disabled.

## Dependencies and graph variants

The complete handler/alias/split/fused/deferred/dispatch/clone runtime is
analyzed before keystream/tamper expansion. An allowlist of side-effect-free
local function declarations can be removed. Lexical bindings, escaping function
values, closure references and transitive dependencies determine which remain.
Fake handlers, indirect dispatch, hot-helper clones and initializers are roots.
This does not remove branches just because one execution did not take them.

Arithmetic keys come from emitted handler capabilities, not an opcode list or
guesses about operand types. Computed keys or escaping helpers retain all
operations. Forwarded slots must resolve to the audited helper's actual slot
parameter. Semantic keys come from bound _sem and clone calls; unknown keys
retain the entire semantic bank. Loop banks keep every referenced fixed key.

The old arithmetic bank always contained ten operations in two epochs:
40 native entries and 80 DAGs. Every used operation retains **all four native
entries and all eight DAGs**, both epochs, shuffled indices, masked mappings,
integer/float/metamethod fallback and occurrence-router selection. Sparse keys
preserve original indices; variant arrays stay dense so their lengths and
selection ranges remain unchanged. Semantic banks retain four functions per
used key: both epochs and their heavy/direct pair.

Value/call/control variants and all eight configured occurrence families remain.
Intentional fake handlers, route cycles, register maps/rotation, affine factors,
split/fusion/deferred handling, state/ledger coupling, virtualization and VM
counts are not reduced. The encoder still internally constructs omitted
candidates to consume the original RNG/name stream. **Emitted counts decrease;
internal candidate-generation counts do not.** This preserves retained DAG
bodies, keys, tags and subsequent seeded encodings. Regression tests compare
complete arithmetic functions and RNG state. Paired builds also assert
identical serialized blob and protection-plan hashes before runtime-dependent
integrity patching/encryption.

## Output sizes

Three alternating paired samples per case, identical input/seed/effective
settings. Full file sizes are medians; encrypted blob text can vary slightly
because existing cryptographic randomness is retained.

| Lua 5.3, default | Before bytes | After bytes | Removed bytes | Reduction |
|---|---:|---:|---:|---:|
| Hello World | 852,548 | 297,699 | 554,849 | 65.08% |
| All arithmetic, integer and float operands | 1,348,494 | 1,276,361 | 72,133 | 5.35% |
| Nested loops and generic iteration | 1,071,209 | 692,830 | 378,379 | 35.32% |
| Closures, varargs, coroutine and errors | 1,092,983 | 613,793 | 479,190 | 43.84% |
| Metamethods and multiple returns | 1,062,523 | 587,004 | 475,519 | 44.75% |

Hello World's runtime changes from 851,315 to 296,465 bytes; its serialized
blob stays 276 bytes. The arithmetic bank changes from 447,559 to 37 bytes,
the semantic bank from 95,409 to 9,676 and the loop bank from 8,944 to two.
Tiny bank skeletons remain. The reader/cipher and unchanged
value/call/control/occurrence banks account for much of the remaining output.

The all-arithmetic input retains the complete 455,804-byte arithmetic bank,
including all 80 DAGs. Its savings come from unused semantic/loop entries and
helper declarations. Its blob stays 1,447 bytes. Loop, closure and metamethod
blobs stay 928, 1,187 and 886 bytes respectively.

| Default input | Audited helpers before → after | Arithmetic DAGs emitted | Semantic functions emitted | Loop graphs emitted |
|---|---:|---:|---:|---:|
| Hello World | 41 → 15 | 80 → 0 | 72 → 8 | 3 → 0 |
| All arithmetic | 41 → 30 | 80 → 80 | 72 → 28 | 3 → 0 |
| Loops | 41 → 31 | 80 → 24 | 72 → 24 | 3 → 3 |
| Closures | 41 → 29 | 80 → 8 | 72 → 24 | 3 → 2 |
| Metamethods | 41 → 29 | 80 → 8 | 72 → 32 | 3 → 0 |

Total function counts include anonymous graphs and unchanged helpers:
Hello World changes from 345 to 129, arithmetic from 344 to 286 and closures
from 344 to 175. Protected Lua 5.3 cases reduce file size by 5.06–59.88%;
arithmetic-occurrence-disabled cases reduce it by 40.40–68.85%. These
percentages do not measure a uniform reduction in active protection.

| Lua 5.1, default | Before bytes | After bytes | Removed bytes | Reduction |
|---|---:|---:|---:|---:|
| Hello World | 668,665 | 285,124 | 383,541 | 57.36% |
| Loops | 1,000,980 | 727,508 | 273,472 | 27.32% |
| Closures | 943,739 | 615,910 | 327,829 | 34.74% |

## Time and compiler limits

Full build wall-time medians in seconds:

| Input | Lua 5.3 before → after | Lua 5.1 before → after |
|---|---:|---:|
| Hello World | 3.487 → 1.929 | 11.412 → 2.041 |
| All arithmetic | 1.374 → 2.056 | — |
| Loops | 0.650 → 0.900 | 14.949 → 6.885 |
| Closures | 0.618 → 0.894 | 15.740 → 7.871 |
| Metamethods | 0.834 → 1.018 | — |

Lua 5.3's extra parsing/binding analysis can outweigh compiler savings when
many graphs remain. This primarily reduces output size, not build time in
every case. Lua 5.1 benefits more from reducing lowering/normalization work.
The analysis reuses the lexical resolver with a relevant-identifier filter
and one query; it does not run a source RenameObf pass.

Execution CPU medians include loading, decryption, integrity, initialization
and the program. Lua 5.3 default Hello World changes from 233 to 82 ms,
arithmetic from 108 to 97, loops from 75 to 58, closures from 45 to 37 and
metamethods from 51 to 41. Lua 5.1 changes from 1.714 to 0.939 seconds for
Hello World, 4.472 to 3.245 for loops and 2.918 to 2.890 for closures. These
shared-workstation samples have noise; the last difference is too small to
infer improvement. No per-opcode throughput improvement is claimed.

Pruning exposed a Lua 5.1 capture-budget interaction: removing cold helpers
could take an executor below the old capture-bank threshold, while an inner
split-dispatch closure still captured **62 upvalues**, exceeding the native
limit of 60. The original input compiles with the historical runtime.
Compaction now also handles structurally identified dispatch groups, banking
immutable frame-local helper functions only. PC/register cells, reassigned
functions and forward routes retain their original cells. Function identity,
tail calls, multiple returns and trailing nils remain intact.

## Validation and deferred work

The new regression checks shadowing, recursive dead dependency chains, escaped
callbacks, combined computed semantic/arithmetic keys, unchanged DAG bodies/RNG
and 14 executable builds across Lua 5.1/5.3 and three option settings. Existing
generated cross-backend tests cover 24 Classic/Karity/MOV builds. Native-source
audits verify authored contracts and actual emitted inline/retained paths,
rather than requiring unused copies. Execution assertions and limits remain.

The 52-command CI manifest was checked in segments on Python 3.12, rerunning
affected checks after fixes. Classic/Karity/MOV generated cases, 31 Lua 5.1
runtime builds, 37 source/output-pass matrix builds, 30 semantic matrix builds,
MOV high release-check, user presets and all 18 dev examples passed. The
optional external Lua 5.1 toolchain check skipped because its tool paths were
not configured; bundled Lua 5.1 checks ran. One concurrent MOV run hit its
existing 120-second execution limit; the same regression passed on rerun,
without changing its limit. Python 3.15 typing and runtime-size regression
checks also passed.

Frame layouts and initialization tables are not aggressively shortened: they
cross continuation/rotation/closure boundaries and participate in state
coupling. Native duplicate entries, hot-helper clones and occurrence families
are not reduced just because one sample does not exercise them. Skipping
construction of omitted candidates is deferred until it can preserve the seeded
encoder stream. Removing unreachable bulk changes passive camouflage; matching
live variants and semantic coverage is not a proof of equal resistance to
every possible analysis.

Reproduce in PowerShell:

    $env:PYTHONHASHSEED = '0'
    python tools/profile_vm_runtime.py --baseline-ref f711103 --output temp-runtime-size/lua53.json --repeats 3
    python tools/profile_vm_runtime.py --baseline-ref f711103 --output temp-runtime-size/lua51.json --lua-version 5.1 --fixtures hello loops closures --settings default --repeats 3
