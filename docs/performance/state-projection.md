# Stable state detail projection

Baseline: `8fad8cf`, branch `future`, CPython 3.15 on Windows.
[Raw samples, complete state digests and normalized code hashes](state-projection.json).

## Implementation and protection

Karity's cyclic fixed-point analysis now propagates register and open-box
states without constructing native-input snapshots, capture snapshots, graph
dependency records or replacement transition objects at every visit. Once
the fixed point is stable, each reachable instruction receives its complete
detail record from its final incoming state. Acyclic functions retain eager
recording to avoid a second transfer through ordinary straight-line code.

The worklist, joins, epoch sets, pending materialization, closure boundaries,
reachability and state validation are unchanged. No state/epoch caps, handler
exclusions or protection options are added. The final transition contains all
the same fields. Number expressions and RNG consumption, StringObf/CFF,
presets, VM handlers, graph protection and compiler checks remain unchanged.

## Isolated state measurements

Seven serial repetitions per revision; medians exclude digest and JSON
serialization. Four workloads cover straight-line code, loops, closures and
StringObf followed by FunctionObf. All complete state digests match baseline.

| Workload | State analysis seconds, before → after |
|---|---:|
| Straight-line | 0.0534 → 0.0490 |
| Loop | 0.0291 → 0.0306 |
| Closures | 0.0041 → 0.0048 |
| StringObf + CFF | 4.3039 → 3.0833 |

The large CFF workload improves about 28.4%. Its propagation visits remain
83,038; full detail records fall from 83,038 to 10,127. This reduces temporary
analysis work, not protected instructions or runtime dependencies. Small
function timing differences and Windows CPU timer quantization limit claims
about those rows; tiny cyclic functions can incur projection overhead.

Reproduce against an archived baseline checkout:

```powershell
python tools/benchmark_state_number.py --checkout temp-state-number-baseline --output before.json --repeats 7
python tools/benchmark_state_number.py --output after.json --repeats 7
```

## Complete ordinary builds

Diagnostics disabled, `PYTHONHASHSEED=0`, serial builds without other local
builds. Karity backend; seed 9300 for hello, 9301 for numbers. All ten retained
outputs execute with original stdout. Runtime is sampled once per output.

| Fixture / preset | Build seconds, before → after | Difference |
|---|---:|---:|
| 20-byte hello / high | 43.698 → 42.366 | 3.1% faster |
| 20-byte hello / max | 64.162 → 55.627 | 13.3% faster |
| 188-byte numbers / high | 25.702 → 22.803 | 11.3% faster |
| 188-byte numbers / max | 43.854 → 44.115 | 0.6% slower |

Numbers max aggregates two before/after pairs. The first was 43.883 → 45.589;
the repeat was 43.825 → 42.641. Both are retained: this workload has no stable
overall speedup in these samples. Other rows each have one pair, so they are
not universal estimates. Peak complete-build memory changes only slightly.
Output size changes are negligible; encrypted packer randomness is retained.

An exploratory hello-high pair used a subsequently rejected number candidate
and is excluded. The hello-high row was rerun with final production code.
Current absolute times differ substantially from the preceding report;
compare paired revisions here rather than mixing separate measurement runs.
The max twenty-second target has not been met or guaranteed.

The ordinary benchmark now supports `--backends`, `--profiles` and `--fixture`
to isolate these comparisons; default behavior remains unchanged.

## Number candidate decision

Combining hexadecimal case checks and bypassing exponent-case traversal for
non-exponential numbers preserved 1,536 tested expressions and RNG states.
However, nine alternating pairs against the actual old engine gave medians
0.4480 → 0.4497 seconds (native), 0.4860 → 0.4888 (portable). No stable benefit
was demonstrated; the candidate was removed. No numeric cache or expression
reuse was added. Earlier regex/list candidates were also rejected. The final
numeric engine and preset hashes equal baseline after LF normalization.

## Regression verification

- Python 3.12/3.15: 28 functions compare final records with the old per-visit
  recording behavior, and compare forward/reverse worklist schedules.
- Coverage includes graph and ungraphed pending values, loops, closures and
  upvalue closes, varargs, trailing nil, coroutine calls and error paths.
- VM IR, Lua 5.1/5.3 closure GC across all backends, twelve dispatcher/state
  coupling builds and runtime polymorphism checks pass.
- Type checks and Python 3.12 syntax checks pass on both Python versions.
- Existing CI manifest and timeout limits are retained; full CI runs separately.
