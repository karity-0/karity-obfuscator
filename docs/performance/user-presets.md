# User preset measurements, 2026-10-11

Catalog revision 1 on `future`, based on `8d1d74e`. Windows, Python 3.15, Lua 5.3, seed 9300.
[Raw ordinary samples, complete policies and output hashes](user-presets.json).

Three inputs cover UTF-8 strings, nested loops, and closures/varargs/trailing nil/coroutines/error handling. All 36 backend/preset/input outputs match original stdout. Each input has **one sample**; ranges below span different inputs, not confidence intervals or paired speedups. Builds were serial with diagnostic profiling disabled; process peak working set excludes compiler grandchildren. Lua runtime wall time includes startup and is sampled at 50 ms.

| Backend | Preset | Build seconds | Output MiB | Lua seconds | Peak builder MiB |
|---|---|---:|---:|---:|---:|
| karity | fast | 5.63–7.32 | 0.89–1.00 | 0.16–0.16 | 269 |
| karity | balanced | 6.07–6.98 | 0.94–1.04 | 0.16–0.16 | 277 |
| karity | strong | 23.70–63.87 | 4.06–7.53 | 0.72–2.38 | 1251 |
| karity | maximum | 36.08–67.19 | 2.42–3.63 | 4.04–6.97 | 1581 |
| classic | fast | 3.03–3.42 | 0.43–0.52 | 0.11–0.11 | 150 |
| classic | balanced | 3.14–3.70 | 0.48–0.56 | 0.11–0.11 | 156 |
| classic | strong | 21.23–29.26 | 3.48–6.33 | 0.51–1.22 | 1059 |
| classic | maximum | 30.94–43.64 | 1.98–2.87 | 4.00–5.50 | 1318 |
| mov | fast | 0.61–0.66 | 0.15–0.31 | 0.16–0.21 | 40 |
| mov | balanced | 0.61–0.70 | 0.15–0.23 | 0.21–0.21 | 41 |
| mov | strong | 2.97–10.08 | 0.74–5.15 | 0.62–3.99 | 345 |
| mov | maximum | 5.18–15.08 | 1.03–1.97 | 2.18–7.93 | 411 |

Maximum includes packing. Smaller packed files do not mean less VM protection; decoding/decompression/loader integrity contributes to its runtime cost. A single seed can select different blob formats/handler variants, so balanced may be smaller or slightly faster on a particular input despite larger budgets. More seeds/repetitions are needed for stable performance estimates.

## Protection and cost policy

- Fast/balanced keep the common VM protection intents; StringObf/CFF/source NumberObf/MemeStrings are selective by default (BooleanObf/global localization are enabled for balanced). Unmarked source has less default protection after lifting than strong/maximum. This is an explicit coverage difference.
- Strong/maximum cover eligible source functions at all nesting depths and retain StringObf → CFF → source NumberObf/MemeStrings. Compiler-budget fallback uses existing compact CFF, retaining source/reconstruction blocks with lower junk/dead-state density. The adjustment is recorded, not described as equal protection.
- Every tier has visible NumberObf/MemeStrings on VM output; maximum has them on its packer loader too. Number/Meme are generated together once per eligible runtime literal with provenance protection. Hot operation caps are 2/2/3/3; cold caps are 3/6/12/20. Notation diversity is independent of these caps. Original source NumberObf keeps its engine.
- VM output general StringObf/CFF are off. Backend-owned handlers/state/dispatch protection remains enabled as supported. State dependency arity caps are 1/2/2/3, with increasing graph/variant rates, spans and helper counts. Classic/MOV do not support Karity state machinery; the GUI/CLI explicitly report unsupported intent.
- StringEncode is absent from new defaults; legacy JSON profiles and optional passes remain supported.

The twenty-second maximum goal is **not met generally**. On these inputs maximum took 36–67 seconds with Karity, 31–44 with Classic, and 5–15 with MOV. Karity maximum reached about 1.54 GiB of builder memory; source protection still has substantial cost. There is no universal “maximum is fast” claim.

## Correctness issues exposed by the new coverage

Large captures in compact source CFF exposed a Karity state-analysis operand error: GET_UPVALUE_TABLE B and SET_UPVALUE_TABLE A are upvalue indices, not frame registers. Treating them as registers could index beyond maxstack or corrupt dependency tracking. The corrected typed register accesses retain capture/table protection.

Classic dispatcher hiding was using Lua 5.1 numeric bit helpers on Lua 5.3, where those helpers were absent, causing a nil-field call even without output passes. Lowering now carries the actual target bit-helper choice; 5.3 uses native integer operators and 5.1 keeps its portable helpers. Dispatcher hiding remains enabled.

## Reproduction

```powershell
python tools/benchmark_user_presets.py --fixtures strings loops closures --repeats 3 --output temp-user-preset-benchmark/ordinary.json
python tools/benchmark_user_presets.py --fixtures small --backends karity --diagnostic --repeats 1 --output temp-user-preset-benchmark/diagnostic.json
```

Diagnostics are separate from ordinary timing. Mosaic counts describe generation attempts, including discarded compiler retries, rather than a count of visible literals in a packed final file. CFF compiler/protection records describe the retained transform. `--ablation notation|no-unroll|no-pack|full-output|no-cff-budget` labels explicit experiments and never changes production policies.

## Paired cost experiments

Small input (29 bytes), Karity, two paired seeds (9300/9301), serial ordinary builds. These exploratory medians do not establish a general speedup; only the named cost policy changes. All outputs match original stdout.

| Policy | Preset | Build seconds | Output MiB | Lua seconds |
|---|---|---:|---:|---:|
| Default | strong | 29.62 | 4.74 | 1.02 |
| Default | maximum | 39.96 | 2.58 | 4.32 |
| CFF pass budget off | strong | 33.13 | 5.71 | 1.29 |
| CFF pass budget off | maximum | 45.70 | 2.97 | 5.22 |
| Output notation only (no arithmetic/memes) | strong | 30.47 | 3.60 | 0.74 |
| Output notation only (no arithmetic/memes) | maximum | 38.97 | 1.73 | 2.88 |
| Packing off | maximum | 39.15 | 5.84 | 1.12 |

Notation-only and no-pack are deliberately reduced experiments, not production defaults. The bounded output Number/Meme layer has a visible size/runtime cost but little build-time difference here; parsing/binding/rendering the large runtime remains dominant. Packing retains its storage benefit and adds decoding/runtime cost.

## Diagnostic structure and per-pass costs

Separate one-seed profiled runs, not the ordinary timing samples above. CFF blocks include mini-CFF blocks; helper counts describe split dispatcher closures, not total Lua functions.

| CFF budget | Preset | String output bytes | CFF output bytes | Native CFF instructions | Largest jump | CFF blocks | Split helpers |
|---|---|---:|---:|---:|---:|---:|---:|
| Off | strong | 16119 | 227777 | 17386 | 5560 | 59 | 0 |
| Off | maximum | 17811 | 279636 | 19022 | 8707 | 85 | 3 |
| Default | strong | 16119 | 66067 | 3655 | 616 | 59 | 9 |
| Default | maximum | 17811 | 76251 | 3822 | 789 | 85 | 6 |

The default 12x/16x pass budgets selected compact retry in these strong/maximum samples. That deliberately reduces junk/dead-state density; all eligible source/reconstruction functions remain transformed. It is not a claim of identical analysis resistance. The fast macro regression also verifies reconstruction/CFF under its 8x selective budget. The tier ratios are measured initial policy defaults, not a universal optimum.

| Preset | String seconds | CFF seconds | Source Number seconds | VM total seconds | VM output seconds | Pack seconds | VM lowered instructions | Handler graph sites |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| fast | 0.000 | 0.000 | 0.000 | 5.656 | 5.066 | 0.000 | 174 | 29 |
| balanced | 0.000 | 0.000 | 0.000 | 5.642 | 5.033 | 0.000 | 232 | 35 |
| strong | 0.043 | 2.376 | 0.046 | 26.442 | 22.615 | 0.000 | 9554 | 3527 |
| maximum | 0.046 | 2.595 | 0.050 | 36.277 | 30.898 | 2.365 | 13085 | 4452 |

VM output timing is included in VM total, not additive. More graph sites/instructions demonstrate different applied structure and cost, not a numeric security rating. Maximum also permits three-way state dependencies, three VMs and wider/more variants; strong permits two-way dependencies and two VMs.

All four diagnostics record hexadecimal integer/prefix case, decimal scientific/exponent case, leading decimal dot, hexadecimal float/leading hexadecimal dot and meme strategies. Their full notation, phase, origin and duplicate-prevention counters are in the raw report. The Number stage reports zero second-stage replacements because the preceding combined emitter already generated both Number and Meme styles. Maximum additionally records 444 packer-output literals protected from rewrapping.

## Verification

All runnable commands in the Python 3.15 CI manifest completed, including legacy MOV high release-check and 18/18 dev fixtures. A new integration test initially used mismatched compiler/Lupa dump fingerprints; it was corrected to use the compiler-matched Lua executable, then rerun along with remaining manifest commands. Existing tests and timeouts were retained.

Python 3.12 passed typing/import, GUI, new user presets, backend options, nested/large CFF, Karity analysis and Literal Mosaic regressions. Native-library tests exercise Lua 5.1/5.3 compilation, closures, upvalues, trailing nil, varargs, coroutines and errors. The optional external Lua 5.1 toolchain matrix and six explicitly configured Lua-library tests were skipped because their environment paths were unset. Complete new user policies explicitly reject unsupported Lua 5.1 layers.

A read-only browser preview verified both button groups, preset/backend independence and Korean labels after an advanced checkbox edit.
