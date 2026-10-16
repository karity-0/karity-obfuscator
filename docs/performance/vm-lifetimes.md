# VM lifetime and preset measurements, 2026-10-16

Baseline `ec07e7f` versus the lifetime, chunk-interface and table-key corrections in this change. Windows, Python 3.15.0, seed 124. Lua 5.1 uses Lupa 2.8; Lua 5.3 uses the matching bundled executable/compiler. Raw reports and exact generated outputs remain under ignored `local/`.

## Correctness coverage

The differential corpus compares native Lua with Classic, Karity and MOV on Lua 5.1/5.3, including protected variants. Recorded cases cover overwritten and captured objects, coroutine disposal, callable tables, weak references, deleted object keys, nil/NaN key errors, open results through 1,100 values, module arguments/results, custom environments and `require`. Both standalone source packing and VM plus packing are exercised. CFF also has a compact-function delimiter regression.

The shared 66-command CI manifest completed through staged runs and targeted reruns after fixes. Optional external toolchain checks whose environment paths are unset are skipped, not verified. Python 3.12 syntax is checked; this host executes Python 3.15. Passing the finite corpus does not prove arbitrary equivalence, identical automatic GC timing, finalizer order or debug stack layout.

## VM-only before/after costs

Each pair uses identical options and input hashes. Source/output transformations and packing are excluded. Each condition has one build and five fresh runtime executions, alternating before/after order. CPU time includes loading and initialization but excludes process/Python startup. Lua 5.1 uses 200 arithmetic iterations / 100 callback iterations; Lua 5.3 uses 4,000 / 500. Values across Lua versions are not directly comparable. Builder timings and memory are single samples; child peak working set excludes compiler grandchildren.

All 48 generated outputs matched native stdout in all 240 measured executions. The table shows execution CPU medians, not isolated getter/GC costs. Runtime integrity keys and routing can change when the runtime changes, so small differences and percentage changes on very short runs are not universal speedup claims.

| Lua | Backend | Input | Mode | Before CPU s | After CPU s | Change |
|---|---|---|---|---:|---:|---:|
| 5.1 | classic | arithmetic | minimal | 0.269 | 0.262 | -2.6% |
| 5.1 | classic | arithmetic | protected | 0.281 | 0.267 | -5.0% |
| 5.1 | classic | calls | minimal | 0.289 | 0.295 | +2.1% |
| 5.1 | classic | calls | protected | 0.374 | 0.358 | -4.3% |
| 5.1 | karity | arithmetic | minimal | 0.955 | 0.975 | +2.1% |
| 5.1 | karity | arithmetic | protected | 1.715 | 1.784 | +4.0% |
| 5.1 | karity | calls | minimal | 1.434 | 1.541 | +7.5% |
| 5.1 | karity | calls | protected | 2.650 | 2.648 | -0.1% |
| 5.1 | mov | arithmetic | minimal | 1.252 | 1.183 | -5.5% |
| 5.1 | mov | arithmetic | protected | 1.177 | 1.220 | +3.7% |
| 5.1 | mov | calls | minimal | 1.180 | 1.182 | +0.2% |
| 5.1 | mov | calls | protected | 1.717 | 1.698 | -1.1% |
| 5.3 | classic | arithmetic | minimal | 0.048 | 0.054 | +12.5% |
| 5.3 | classic | arithmetic | protected | 0.036 | 0.037 | +2.8% |
| 5.3 | classic | calls | minimal | 0.042 | 0.034 | -19.0% |
| 5.3 | classic | calls | protected | 0.054 | 0.051 | -5.6% |
| 5.3 | karity | arithmetic | minimal | 0.204 | 0.200 | -2.0% |
| 5.3 | karity | arithmetic | protected | 0.320 | 0.335 | +4.7% |
| 5.3 | karity | calls | minimal | 0.223 | 0.205 | -8.1% |
| 5.3 | karity | calls | protected | 0.368 | 0.333 | -9.5% |
| 5.3 | mov | arithmetic | minimal | 4.963 | 4.796 | -3.4% |
| 5.3 | mov | arithmetic | protected | 4.095 | 4.078 | -0.4% |
| 5.3 | mov | calls | minimal | 0.356 | 0.349 | -2.0% |
| 5.3 | mov | calls | protected | 0.420 | 0.389 | -7.4% |

Protected Karity callback CPU was 2.650 → 2.648 s on Lua 5.1 and 0.368 → 0.333 s on Lua 5.3. Protected arithmetic was 1.715 → 1.784 s and 0.320 → 0.335 s respectively. Across this matrix the observed changes span −19.0% to +12.5%; the latter is 0.048 → 0.054 s. These observations support correctness with measurable, workload-dependent cost rather than zero-overhead claims.

## Current GUI preset costs

The current built-in GUI presets were measured serially on Lua 5.3, using three inputs: record parsing/grouping/sorting (120 records), stateful callbacks/varargs/coroutines (96 callbacks), and the existing integration fixture (`backend_escape_boundaries.lua`, named `release` in the tool). These are representative repository fixtures; production scripts were not provided.

Each backend/preset/input combination has three independent builds with seeds 9300–9302 and one fresh execution per output. All 108 outputs matched native stdout. Ordinary preset settings were used with no ablation or diagnostic profiling; the non-executable signature banner was disabled. Output sizes are UTF-8 bytes. Source and output hashes, resolved configurations and exact LF-encoded artifacts are retained in the local report and verified against the saved files.

The following ranges span the **three input medians**, not confidence intervals. Build times cover pipeline work inside a fresh worker. Runtime wall times include process startup, loading and initialization; they are not comparable to the CPU times above. Memory is the child peak working set, excluding compiler grandchildren. Repeats vary generated code, so these measurements combine variant and run-to-run variation.

| Backend | Preset | Build s | Output MiB | Runtime wall s | Builder peak MiB | Runtime peak MiB |
|---|---|---:|---:|---:|---:|---:|
| classic | fast | 3.33–4.22 | 0.56–0.69 | 0.11–0.16 | 165.58–197.45 | 7.73–9.67 |
| classic | balanced | 3.06–5.36 | 0.51–0.79 | 0.11–0.16 | 157.21–222.48 | 7.60–10.14 |
| classic | strong | 33.27–67.78 | 4.52–5.69 | 1.97–2.73 | 1098.95–1641.93 | 56.80–105.59 |
| classic | maximum | 48.10–121.45 | 2.76–5.79 | 5.66–9.65 | 1506.09–2644.11 | 85.37–177.65 |
| karity | fast | 4.97–6.53 | 0.74–0.92 | 0.11–0.36 | 219.96–262.33 | 8.54–16.65 |
| karity | balanced | 5.18–7.67 | 0.71–1.01 | 0.16–0.36 | 218.46–285.29 | 8.21–18.02 |
| karity | strong | 37.82–93.38 | 5.12–6.54 | 2.93–8.64 | 1263.39–1869.56 | 84.89–198.94 |
| karity | maximum | 59.46–214.57 | 3.22–7.44 | 10.00–19.79 | 1702.50–3058.24 | 137.64–380.43 |
| mov | fast | 0.69–0.72 | 0.30–0.33 | 0.16–0.31 | 44.24–44.53 | 12.86–23.19 |
| mov | balanced | 0.79–0.82 | 0.16–0.25 | 0.16–0.31 | 45.04–49.28 | 12.05–19.55 |
| mov | strong | 10.11–45.45 | 0.91–3.15 | 7.93–28.50 | 210.39–843.64 | 47.84–166.19 |
| mov | maximum | 14.12–93.21 | 1.33–7.27 | 14.44–66.81 | 276.33–1727.17 | 94.00–326.30 |

The protection settings have substantial cost on these inputs. For example, MOV `records` takes 0.311 s with `fast` and 66.815 s with `maximum`; Karity `release` with `maximum` takes 214.570 s to build with a 3,058 MiB median builder peak working set. These figures describe full preset pipelines, not the cost of the lifetime correction alone. No protection features were disabled to improve the reported figures. This report establishes a current baseline; it does not compare the full presets against the old commit.

## Reproduction

```powershell
python tools/benchmark_vm_lifetimes.py --before PATH_TO_BASELINE_CHECKOUT --samples 5 --output local/performance/vm-lifetimes.json
python tools/benchmark_user_presets.py --fixtures records callbacks release --repeats 3 --output local/performance/presets.json
python tools/explore_vm_semantics.py --seeds 124 7719 20261016 --generated 8 --output local/vm-audit/run
```
