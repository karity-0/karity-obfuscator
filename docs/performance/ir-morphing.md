# Physical permutation and semantic IR morphing

Implemented on dev for 1.3.0. Source FunctionObf, StringObf, NumberObf and other
source passes are unchanged. This is additional structural protection, with a
bounded cost; it is not a runtime-size optimization.

## Architecture and safety

`ir/facts.py` shares conservative value/effect facts, reaching definitions,
dominance, SCCs and existing liveness/capture analysis. `ir/morphing.py` provides
budgets and diagnostics; four small modules implement independent strategies.
The snapshot is reused until a strategy changes the function. Cheap eligibility
checks avoid full analysis where no candidate can exist. No plugin framework or
second source-obfuscation engine was added.

Morphing runs after existing optimization and before the initial protection
plan. Both initial and final plans are built for the resulting IR generation.
New IDs retain source PC/line and parent/depth provenance. Normalization retains
intentional block boundaries; existing optimization cannot fold these generated
instructions back into their original form.

| Feature | Actual change | Eligibility and limits |
|---|---|---|
| TEST_SET decomposition | TEST plus an edge-local MOVE block | Conditional write and original truthiness retained |
| Tail duplication | Clone an acyclic join and redirect one predecessor | No loop, capture/close, upvalue, vararg or open-top boundary; one copy executes per path |
| Rematerialization | Recompute a pure definition at a scalar use into a fresh register | Integer proof, multiple consumers, unique reaching definition, dominance, unchanged inputs |
| Instruction MBA | Replace integer operations with multiple ordinary IR instructions | Lua 5.3 integer proof and modulo-2^64 identities; unknown/metamethod/float operands unchanged |
| Physical permutation | Move complete block bundles in serialized storage | Entry fixed; skip/extension/split/fuse/variant/integrity units kept together; displaced fallthroughs bridged |

The physical pass relinks relative jumps, absolute block targets, routes and
canonical addresses through one address map. It validates the final layout.
Bridge/address/range exhaustion retains the original layout with a reason.
This changes storage order independently of existing block variants. MBA changes
dynamic operations, while existing arithmetic graphs protect their execution.
Tail duplication and rematerialization change CFG and def-use structure rather
than just adding junk.

Scratch allocation respects open register top and reserves existing integrity
and state-dependency scratch space. Growth, added instructions/blocks,
per-strategy transformations, depth, pass-wide additions and new-operation
inventory have separate limits. The latter matters because adding an operation
can introduce a large graph/handler bank. A conservative physical-cost envelope
accounts for split widths, integrity streams, variants, junk and bridge budget;
it preserves margin within the signed jump range. This guard cannot make an
already oversized original function safe, but avoids consuming that margin.

Integration testing found two issues and fixed them in the VM/IR layer: unary
BIT_NOT requires a register, so MBA choices with unary constant operands are
filtered; synthesized linker JUMPs now have explicit ownership and do not inherit
their source arithmetic instruction's graph/split/variant descriptors. Semantic
instructions retain their existing protection selections.

## Support and configuration

| Backend | Lua 5.1 | Lua 5.3 | Physical permutation |
|---|---|---|---|
| Karity | TEST_SET and tail; integer strategies unavailable | All four | Supported |
| Classic | TEST_SET and tail; integer strategies unavailable | All four | Supported |
| MOV | TEST_SET and tail; integer strategies unavailable | All four | Unavailable, explicit capability warning/rejection when required |

All new rates default to zero in legacy JSON/CLI profiles. Existing `dev`,
`fast-vm`, `high` and `max` definitions are unchanged. User preset revision 2
adds the following policies; existing source/protection settings stay intact.

| Setting | fast | balanced | strong | maximum |
|---|---:|---:|---:|---:|
| Physical permutation rate / bridge budget | .15 / 8 | .35 / 16 | .60 / 32 | .80 / 64 |
| MBA / TEST_SET rate | .06 / .15 | .20 / .25 | .45 / .50 | .65 / .75 |
| Tail / rematerialization rate | .04 / .03 | .08 / .10 | .18 / .25 | .30 / .40 |
| Function growth / added-instruction cap | 1.12 / 16 | 1.20 / 32 | 1.30 / 64 | 1.40 / 96 |
| Added blocks / transforms per strategy | 2 / 2 | 4 / 4 | 8 / 8 | 12 / 12 |
| Depth / pass-wide added-instruction cap | 1 / 256 | 2 / 512 | 2 / 2048 | 3 / 4096 |
| New-operation inventory cap | 1 | 2 | 3 | 4 |

GUI groups remain collapsed by default. Unsupported options retain saved values
and show an explanation. Backend and preset selection remain independent.
Explicitly selecting an outdated unmodified builtin snapshot refreshes it;
custom snapshots and currently loaded saved configurations are preserved.
CLI uses the existing `--vm-option` mechanism and adds `--dump-morphed-ir PATH`.
Generated configuration/backend documentation includes all new controls.

## Measurements

Python 3.15, native Lua 5.3, Karity, seed 7361, same inputs/configurations except
new rates zero versus preset policy. One paired sample per condition: wall times
are indicative, not statistical speedups. Mixed input includes dynamic integer
operations, loops, conditional writes and functions; closure input includes
captured state and open returns. Raw reports preserve every strategy's applied,
skipped, failed and timing fields.

VM-only mixed input, excluding source/output passes and packing:

| Preset | IR instructions | Physical instructions | Applied IR transforms | Moved physical units | Final bytes |
|---|---:|---:|---:|---:|---:|
| fast | 44 → 46 | 65 → 72 | 1 | 7 | 947,303 → 937,869 |
| balanced | 44 → 50 | 80 → 93 | 3 | 8 | 954,576 → 1,080,125 |
| strong | 44 → 53 | 116 → 147 | 6 | 21 | 1,093,893 → 1,180,024 |
| maximum | 44 → 56 | 96 → 130 | 8 | 27 | 1,248,333 → 1,501,170 |

Hello has no eligible semantic transform. Closure input retains 66 IR
instructions because of proof/open-top restrictions, but moves 6/2/22/34 physical
units. Existing protections still run. Byte-size differences when no transform
applies reflect equivalent runtime/encoding choices, not stronger protection.

Full presets, including unchanged source/output/packer passes:

| Preset/input | Final bytes before → after | Build seconds before → after | Lua CPU seconds before → after |
|---|---:|---:|---:|
| fast/hello | 642,278 → 648,395 | 4.416 → 4.156 | .049 → .046 |
| fast/mixed | 820,606 → 827,611 | 5.184 → 4.853 | .061 → .053 |
| balanced/hello | 663,588 → 623,123 | 4.242 → 3.688 | .043 → .044 |
| balanced/mixed | 887,687 → 1,110,741 | 5.372 → 6.574 | .061 → .078 |
| strong/hello | 3,141,905 → 3,137,804 | 20.089 → 19.994 | .440 → .382 |
| strong/mixed | 3,757,873 → 4,032,000 | 25.677 → 31.264 | .533 → .501 |
| maximum/hello | 2,067,913 → 1,860,864 | 33.142 → 35.796 | 3.086 → 2.796 |
| maximum/mixed | 2,375,111 → 2,307,916 | 40.490 → 41.376 | 3.859 → 4.270 |

Balanced/strong mixed output grows 25.1%/7.3%; their build time grows 22.4%/21.8%
in this sample. Maximum's packed size falls despite more physical instructions;
this is not a compression claim. Different IR alters protection planning and
equivalent randomized runtime/encoding choices, so final bytes are not a direct
measure of transformation strength. Native execution matched in every pair.

Strategy isolation, strong/mixed, each rate 1, other new rates 0:

| Feature | Applied | IR instructions/blocks after (base 44/18) | Physical after (base 116) | Build seconds before → after |
|---|---:|---:|---:|---:|
| TEST_SET | 1 | 45 / 19 | 119 | 1.769 → 1.364 |
| Tail duplication | 2 | 47 / 20 | 123 | 1.955 → 2.330 |
| Rematerialization | 3 | 47 / 18 | 124 | 1.740 → 1.827 |
| MBA | 3 | 52 / 18 | 130 | 1.755 → 1.963 |
| Physical permutation | 0 IR transforms | 44 / 18 | 140 | 1.684 → 1.579 |

Preflight eligibility and shared SCC analysis reduced the morphing phase on the
large full-preset hello input from 1.267 to .219 seconds (strong) and 3.793 to .941
seconds (maximum), without changing eligible protection scope. Total build times
still include expensive pre-existing passes. Full mixed morphing takes 1.893/
2.225 seconds for strong/maximum; this remains a cost worth monitoring.

Reports: VM-only (generated locally), full presets (generated locally),
strategy isolation (generated locally). Reproduce using
`tools/profile_ir_morphing.py --output REPORT.json`, with `--full` or
`--ablation --presets strong --inputs mixed` as appropriate.

## Validation and remaining limits

New tests verify actual physical reordering, atomic bundles, valid routes/jumps,
range fallback, all-off identity, all four real structural changes, bounded
growth, unique IDs/provenance, optimizer preservation and scratch reservation.
MBA identities cover signed integer boundaries and wraparound, including binary
RK constants. Native differential builds cover three backends, both Lua versions,
multiple seeds, closures, errors, coroutines, open returns/trailing nil,
metamethods, floats and signed zero. Python 3.12/3.15 run the new fact/morph/option
regressions. A real browser with temporary settings verifies Korean labels,
target/backend gating and independent preset selection.

Existing VM IR, generated cross-backend, serialization, state coupling, runtime
polymorphism, native integer lowering, line-state, GUI and preset regressions
also pass. The existing Lua 5.1 semantic matrix passes 30 builds, MOV regression
passes its protected/multi-VM cases and high release-check, and the legacy dev
corpus passes 18/18 inputs. CI's manifest includes the four new regressions;
hosted CI is separate from local verification.

No speculative integer proof, interprocedural type inference, open-top scratch
reuse, cyclic tail cloning or MOV physical reorder is attempted. These skips are
reported. No claim is made that extra instructions alone prove lifting resistance;
tests demonstrate changed operation sequences, CFG, def-use and physical order.
