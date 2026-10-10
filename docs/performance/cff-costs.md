# CFF compiler costs and composition, 2026-10-10

The failing `future` input is `test/scripts/01_helloWorld.lua`, a 20-byte
`print("hello world")` program. The source-pass reproduction uses seed 9300,
the high/max profiles, and baseline revision `102243e`. The core implementation
is `2ceea6d`, with target fixes in `2de1a1f` and `f687f17`;
[cff-costs.json](cff-costs.json) contains pass records, individual
prototype instruction counts, jump PCs/lines, grouping measurements and runtime
samples. Measurements use Windows, Python 3.15 and native Lua 5.3. Timing samples
were collected during concurrent verification and are observations, not targets.

## Where compilation failed

FunctionObf alone compiled: its largest native jump was 21,877 instructions.
After NumberObf, it still compiled with a largest jump of 23,001. The subsequent
MemeStrings pass made compilation fail. NumberObf had expanded generated state,
transition and junk constants; MemeStrings then applied string-length arithmetic
to their operands. Unlike literal arithmetic, these expressions retain runtime
instructions instead of being folded by the compiler.

The failure was in the anonymous StringObf reconstruction functions for
`"table"` (the AntiDebug type check) and `"hello world"`. Their CFF case exits and
dispatcher backedges span the expanded case groups:

| Reconstruction | Baseline real blocks | Standalone expanded source | Isolated case instruction sum | Compiler error line |
| --- | ---: | ---: | ---: | ---: |
| `table` | 42 | 1,027,410 bytes | 135,126 | 1846, near `end` |
| `hello world` | 64 | 1,723,630 bytes | 228,409 | 3149, near `%` |

These instruction sums come from compiling the individual case groups. They
are diagnostic estimates, **not exact instruction counts or PCs of the rejected
whole prototype**: Lua does not produce bytecode for that prototype. Their
source offsets in the unminified final source were 1,437,798 and 2,457,168.
The successful pre-expansion prototypes and new outputs have exact instruction,
PC and line measurements in the JSON report.

Both [Lua 5.1's opcode layout](https://www.lua.org/source/5.1/lopcodes.h.html)
and [Lua 5.3's opcode layout](https://www.lua.org/source/5.3/lopcodes.h.html)
use 18-bit Bx and signed bias 131071.
[Lua 5.3's jump patching](https://www.lua.org/source/5.3/lcode.c.html)
rejects distances outside that range. This is a distance within one prototype,
not a whole-file size limit. The failure precedes VM input compilation; changing
VM output passes alone cannot fix it.

## Source-pass comparison

| high stage | Before bytes | After bytes | Before seconds | After seconds |
| --- | ---: | ---: | ---: | ---: |
| StringObf | 6,825 | 6,825 | 0.001 | 0.004 |
| FunctionObf | 383,775 | 196,787 | 0.271 | 2.308 |
| NumberObf | 2,192,004 | 234,480 | 0.789 | 0.238 |
| LocalizeGlobals | 2,191,995 | 234,489 | 2.197 | 0.660 |
| MemeStrings | 4,211,516 | 277,220 | 1.584 | 0.337 |
| Minified VM input | 3,713,167 | 227,905 | — | 0.176 |

FunctionObf now spends time on native compiler probes and structural scheduling.
The baseline diagnostic also measured its CFF regions during generation; this
is not a microbenchmark of the old emitter alone. The revised source pipeline
took 3.76 seconds in this sample. VM input decreased approximately 94%.
max's baseline VM input similarly failed compilation at about 3.71 MB; the
revised source-only sample produced 256,347 bytes in 5.01 seconds.

NumberObf replacements fell from 23,185 to **499**. It still processes all
eligible original literals and StringObf numeric reconstruction data. It skips
10,126 operand literals belonging to 5,029 protected FunctionObf expressions.
MemeStrings also skips these generated operands; it still applies to source
numeric expressions (1,045 replacements in this sample). Provenance belongs to
registered origin spans on source edits, not number/identifier patterns.

The high sample has 49 real reconstruction CFF blocks plus six compound CFF
blocks, compared with 178 plus 16 before. Every reconstruction operation still
executes under CFF. The current final source has 21,176 native instructions over
all prototypes; prototype and jump details are recorded individually in JSON.
The baseline FunctionObf output had 46,589 instructions before later expansion,
and its final source could not compile.

## Scheduling and budgets

Large dispatchers use measured native instruction costs, conservative reserves
for later source-literal passes, and cost-balanced helper groups. A route table
calls the selected helper once per transition. Return-containing blocks remain
in the owner, preserving result arity and trailing nils. Helper captures account
for the Lua 5.1 limit of 60 upvalues; an inline compact retry handles cases where
an additional helper would exceed the available capture slots.

The default jump budget is one quarter of 131071; the function budget is half
that domain. The pass budget reserves a jump domain plus eight times the input
instruction count, matching the eight leaves of the existing depth-three number
expression tree. The 150-instruction per-source-literal scheduling estimate
includes float-chain/tree terms, two MemeStrings arithmetic levels and load/
temporary overhead. Native probes check the emitted/pool-adjusted structure;
large regression cases verify the additional passes too. These estimates are
conservative scheduling policies, not a guarantee for arbitrary future passes.

Budget pressure selects a shared-decode dispatcher and smaller junk/dead-state
banks instead of disabling FunctionObf. All selected real blocks and edges stay.
Profiles explicitly record reduced junk density, state coalescing, automatic
splits, capture fallback and bounded-retry reasons. Impossible partitions/budgets
raise diagnostics instead of retrying random emitters indefinitely. State-ID
allocation also has a finite fallback and preserves affine encoder injectivity.

The large regression with a 2,048-instruction jump budget creates 16/24 helpers
on Lua 5.1 and 26/23 on Lua 5.3 for two seeds, retaining 181 real blocks.
The small high sample happens to use three helpers; its baseline selected no
split dispatcher. The old maximum of three is not a large-function cap anymore.

## String reconstruction granularity

Only straight-line, single-predecessor chains in registered StringObf spans
merge. Branches, joins and returns remain boundaries. StringObf → FunctionObf
ordering stays unchanged; restoration functions are not excluded from CFF.

| Maximum statements per state | Real / compound CFF blocks | VM input bytes | Source build seconds | Largest final native jump |
| --- | ---: | ---: | ---: | ---: |
| 1 | 178 / 16 | 644,783 | 10.35 | 22,361 |
| 2 | 92 / 6 | 343,671 | 5.23 | 15,266 |
| **4 (default)** | **49 / 6** | **227,840** | **4.27** | **9,004** |
| 8 | 27 / 6 | 171,284 | 2.42 | 5,239 |

Four retains 9–17 reconstruction states per string in this fixture while
avoiding most repeated state/junk scaffolding. Eight is cheaper but coarser;
one preserves the former statement granularity and still compiles after numeric
provenance is enabled. Grouping and simpler hot numeric expressions are explicit
protection tradeoffs: finer state granularity and repeated literal layers are
reduced, while reconstruction dependencies, CFF execution and source numeric
protection remain. Individual randomized builds can differ slightly in size.

## Complete profiles and VM work

high/max now default to StripInfo, RenameObf and Minify on VM/packer output.
Explicit expensive pass lists remain supported. Handler/graph protection,
instruction variants, state dependencies and dispatcher protection are unchanged.
When RenameObf is present, StripInfo does not redundantly perform its own rename.

Karity's analysis worklist now joins forward dispatcher cases before revisiting
backedges. Epoch/producer alternatives are never capped or discarded. Immutable
state projections are reused only when all physical inputs, routes, captures,
graph inventory and planned policies match; changed inputs/state invalidate the
cache and retain corruption diagnostics. Unrequested IR dumps are no longer
constructed. Numeric-origin labeling reuses the existing function AST rather
than reparsing a complete VM for each helper. Targets provide output compiler
policy through their adapter operation; the common emitter does not rediscover
the target version.

| Backend/profile | VM input bytes | Final file bytes | Build seconds | Execution seconds, median of 3 |
| --- | ---: | ---: | ---: | ---: |
| MOV high | 227,869 | 4,215,877 | 18.58 | 6.02 |
| MOV max, packed | 256,104 | 2,445,113 | 30.28 | 14.19 |
| Karity high | 228,123 | 6,129,941 | 93.70 | 3.31 |
| Karity max, packed | 255,691 | 3,134,807 | 169.82 | 13.66 |

All outputs compile and print `hello world`, matching the original. Execution
measurements include native Lua process startup, compilation, unpacking and VM
execution. The original median is 0.026 seconds. Baseline high/max have no full
build/runtime comparison because their VM input does not compile. max includes
packing, so file size is not directly comparable to unpacked high. VM/backend
randomization also affects output size independently of source-pass savings.

## Verification

The shared manifest retains the existing tests and time limits and adds compiler
cost and analysis-schedule regressions. Native Lua 5.1/5.3 tests cover large CFF,
closures/upvalues, 60 captured locals, multiple returns/trailing nil, varargs,
coroutines, errors, reconstruction CFF, original/generated numeric provenance
and bounded diagnostics. Existing NumberObf differential coverage includes
19,456 cases. Existing VM IR corruption tests check stale routes/rotation/state;
the new analysis regression checks identical fixed points under FIFO/LIFO queues.
The Lua 5.1 matrix covers the supported pass combinations; the existing 5.3-only
StringObf/NumberObf syntax has not been presented as a Lua 5.1 high profile.

The MOV high release-check passed with its existing timeout (13.37 seconds,
3,298,157 output bytes in the final Python 3.12 suite; this release build is
unseeded and differs from the benchmark). Python 3.15's complete local manifest
finished successfully; Python 3.12 completed after repairing and rerunning the
failed line-state test and the remaining manifest. Both versions also passed
the updated VM IR/target-boundary tests and all newly added regressions.
The earlier MOV failure had hidden an existing standalone line-state call with
`context=None`; target binders now supply empty prefix/pass defaults for that
call without changing normal VM binding. Optional external Lua 5.1 toolchain
checks require `KARITY_LUA51_TEST_TOOLS` and were skipped locally; native 5.1
compilation/execution is verified through Lupa. All three GitHub CI jobs passed:
Linux Python 3.12, Linux Python 3.15 and Windows Python 3.12, in
[code validation run 38032908467](https://github.com/karity-0/karity-obfuscator/actions/runs/38032908467),
revision `f687f17`.

Reproduce source costs with:

```sh
python tools/profile_cff.py test/scripts/01_helloWorld.lua --profile high --seed 9300 --output high-costs.json
python tools/profile_cff.py test/scripts/01_helloWorld.lua --profile high --seed 9300 --reconstruction-group-size 1 --output high-granular-costs.json
python main.py test/scripts/01_helloWorld.lua -c config.example.json --profile high --seed 9300 --vm-option backend=mov --profile-report mov-high.json -o mov-high.lua
python test/run_ci.py
```

`--seed` is for measurement and cannot be combined with `--release-check`.
