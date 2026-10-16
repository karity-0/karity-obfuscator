# Ordered DAG and guarded-local measurements

Python 3.15.0, Lua 5.3, karity; seed 1400, 3 alternating samples. Historical synthesis: `2815766`. All other runtime code/options are identical. VM only; generous Protection budgets expose the feature, so these are not full GUI preset timings. Build wall includes synthesis; execution uses Lua os.clock() inside the chunk, including runtime loading/initialization but excluding parsing/process startup. Counter builds are separate and all results match native Lua. Concurrent local CI was running; timings are indicative, not regression thresholds.

| Input / protection | Build wall s | Lua os.clock s | Output bytes | Regions | Reads, median | Writes, median |
|---|---|---|---|---|---|---|
| scalar / False | 0.526 → 0.471 | 0.141 → 0.113 | 149,418 → 149,416 | 1 → 1 | 22,009 → 22,009 | 12,015 → 12,015 |
| scalar / True | 1.218 → 1.471 | 0.200 → 0.223 | 516,361 → 518,980 | 1 → 1 | 22,025 → 18,025 | 12,031 → 12,031 |
| capture / False | 0.384 → 0.436 | 0.021 → 0.015 | 157,925 → 158,050 | 0 → 1 | 1,414 → 1,414 | 825 → 825 |
| capture / True | 1.115 → 1.142 | 0.047 → 0.033 | 587,744 → 539,731 | 0 → 1 | 2,215 → 2,215 | 1,226 → 1,226 |
| table / False | 0.432 → 0.461 | 0.023 → 0.008 | 155,933 → 156,022 | 0 → 1 | 1,413 → 1,413 | 820 → 820 |
| table / True | 1.367 → 2.048 | 0.112 → 0.080 | 592,235 → 557,264 | 0 → 1 | 2,257 → 2,258 | 1,264 → 1,265 |
| vararg / False | 0.522 → 0.785 | 0.024 → 0.030 | 156,978 → 158,081 | 0 → 1 | 1,422 → 1,422 | 830 → 830 |
| vararg / True | 1.374 → 1.675 | 0.094 → 0.075 | 634,487 → 593,877 | 0 → 1 | 2,222 → 2,222 | 1,230 → 1,230 |

Mandatory Karity encoded writes and graph/pending/route/state events are retained. Raw local values bypass reads only when epoch, map generation and pending-state checks succeed. The cost selector can retain the materialized kernel instead; lower dispatch counts do not guarantee lower runtime. Additional ordered recipes expand protection coverage and can increase source size. Counter totals include state-dependent graph/junk activity. Per-operation graph/native variant counts and occurrence families are checked unchanged and retained in the raw samples. Short-input timings are noisy. Raw samples include blob/runtime sizes, forms and rejection reasons.
