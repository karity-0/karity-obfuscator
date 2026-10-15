# Synthesis selection through full user presets

Python 3.15 / native Lua 5.3, seed 1400. Three alternating historical/current pairs, with identical nonce entropy. Both sides use the corrected epoch/generation-validating register cache; the baseline isolates the historical selector and vocabulary. Source passes, VM output passes and Maximum packing remain enabled. Execution includes loading and initialization. Every timed output matches native Lua. Diagnostics are separate from ordinary timed builds. Native Lua wall time also includes source parsing/process startup; runtime peak memory is sampled separately. Peak builder working set excludes compiler grandchildren. [Raw samples](synthesis-pipeline.json).

| Backend / preset / input | Build wall s | Execution CPU s | Output bytes | Builder MiB | Lua wall s | Lua MiB | Regions / handlers |
|---|---|---|---|---|---|---|---|
| karity / fast / hello | 3.702 → 3.763 | 0.053 → 0.035 | 588,146 → 588,146 | 181.6 → 182.9 | 0.114 → 0.109 | 6.9 → 6.9 | 0 / 0 → 0 / 0 |
| karity / fast / functions | 4.194 → 4.156 | 0.049 → 0.053 | 638,756 → 638,756 | 192.9 → 193.7 | 0.110 → 0.110 | 7.3 → 7.3 | 1 / 1 → 1 / 1 |
| karity / fast / strings | 4.946 → 4.957 | 0.063 → 0.053 | 778,731 → 778,731 | 224.9 → 225.0 | 0.110 → 0.109 | 8.1 → 8.1 | 0 / 0 → 0 / 0 |
| karity / balanced / hello | 3.884 → 3.698 | 0.038 → 0.040 | 586,075 → 586,075 | 179.2 → 179.3 | 0.109 → 0.109 | 7.0 → 7.0 | 0 / 0 → 0 / 0 |
| karity / balanced / functions | 4.431 → 4.283 | 0.061 → 0.064 | 676,965 → 676,965 | 203.3 → 204.2 | 0.108 → 0.109 | 7.6 → 7.6 | 2 / 1 → 2 / 1 |
| karity / balanced / strings | 4.754 → 4.658 | 0.047 → 0.049 | 722,625 → 722,625 | 213.7 → 214.0 | 0.109 → 0.109 | 8.0 → 8.0 | 0 / 0 → 0 / 0 |
| karity / strong / hello | 23.222 → 23.029 | 0.344 → 0.349 | 3,714,239 → 3,714,239 | 878.1 → 877.5 | 0.461 → 0.515 | 25.0 → 25.0 | 0 / 0 → 0 / 0 |
| karity / strong / functions | 24.056 → 24.110 | 0.411 → 0.454 | 3,643,427 → 3,650,527 | 861.8 → 862.4 | 0.563 → 0.563 | 27.8 → 27.9 | 1 / 1 → 6 / 5 |
| karity / strong / strings | 32.721 → 35.479 | 0.539 → 0.529 | 4,220,167 → 4,231,573 | 1012.7 → 1016.2 | 0.714 → 0.715 | 39.8 → 39.9 | 3 / 2 → 4 / 3 |
| karity / maximum / hello | 36.958 → 38.360 | 3.107 → 3.051 | 2,169,810 → 2,173,751 | 1245.9 → 1244.2 | 3.190 → 3.087 | 45.4 → 45.3 | 1 / 1 → 8 / 6 |
| karity / maximum / functions | 37.122 → 39.324 | 3.286 → 3.345 | 2,111,393 → 2,170,607 | 1200.8 → 1228.6 | 3.387 → 3.291 | 51.8 → 52.5 | 13 / 10 → 28 / 19 |
| karity / maximum / strings | 48.825 → 50.074 | 4.189 → 4.034 | 2,578,484 → 2,586,658 | 1425.3 → 1429.2 | 4.345 → 4.145 | 65.0 → 65.1 | 4 / 3 → 4 / 3 |
| karity / maximum / long | 49.587 → 49.218 | 4.436 → 4.373 | 2,743,791 → 2,743,816 | 1289.9 → 1292.1 | 4.452 → 4.450 | 77.5 → 77.5 | 0 / 0 → 0 / 0 |

## Separate diagnostic stage costs

These are separately profiled after builds, not the ordinary timing samples above. VM generation, output processing and synthesis are distinct boundaries; nested parent times are not added together.

| Preset / input | Source CFF s | VM code generation s | VM output transforms s | Synthesis discovery + selection s |
|---|---|---|---|---|
| fast / hello | 0.000 | 0.642 | 3.027 | 0.008 |
| fast / functions | 0.000 | 0.713 | 3.321 | 0.041 |
| fast / strings | 0.000 | 0.920 | 3.859 | 0.009 |
| balanced / hello | 0.000 | 0.666 | 2.997 | 0.009 |
| balanced / functions | 0.000 | 0.835 | 4.371 | 0.047 |
| balanced / strings | 0.000 | 0.739 | 3.763 | 0.010 |
| strong / hello | 0.949 | 5.367 | 19.416 | 0.291 |
| strong / functions | 2.142 | 4.387 | 15.286 | 1.306 |
| strong / strings | 7.119 | 4.397 | 18.807 | 1.001 |
| maximum / hello | 1.581 | 5.729 | 26.004 | 0.859 |
| maximum / functions | 2.514 | 5.886 | 23.906 | 2.144 |
| maximum / strings | 9.526 | 6.769 | 26.862 | 1.395 |
| maximum / long | 0.948 | 5.091 | 23.160 | 4.529 |

No source pass, VM protection option, VM output signature pass or packing stage was removed. More accepted bit DAGs can increase generation cost and output size under Protection. Unchanged output/region counts do not establish a causal speedup from timing noise. Compiler costs and SCC frequencies remain estimates; all runtime branches are not calibrated to nanoseconds.

## Findings and limits

Measured implementation: `d249c45`, with register-cache fix `02f7757` shared by
both sides. The baseline uses the selector and numeric vocabulary from
`d7ec9ca`; this is not a checkout-wide historical comparison. There are 78
ordinary timed builds and 13 separate diagnostic builds in this report.

Fast/Balanced preserve the same output bytes on all six inputs; these samples
do not establish a broad generation or execution speedup. Strong functions
increase from 1 region / 1 handler to 6 / 5 for 7,100 additional bytes, and
Maximum functions increase from 13 / 10 to 28 / 19 for 59,214 additional bytes.
Those are broader integer-bit synthesis coverage and different ISA forms, with
measured costs, rather than a universal size reduction or a security proof.
Source arithmetic protection, graph/pending writes, VM output signatures and
packing remain configured throughout.

For Maximum hello, separate profiling attributes 26.004 s to VM output
transforms, 5.729 s to VM code generation, and 0.859 s to synthesis discovery
plus selection. These nested measurements are not summed. This change alone
does not make Maximum a sub-20-second preset.

Maximum long has no admitted regions on either side: the after build reports
1,348 `active_capture` rejections and two `open_register_top` rejections after
source transforms. Existing CFF and VM protection remain active. The current
safe synthesis vocabulary covers numeric DAGs and proven Lua 5.3 integer-bit
DAGs; general call/table effects and active-capture synthesis are further work.

Full `test/run_ci.py` passes on Python 3.12 and 3.15 with this runtime code,
including 198 real synthesis VM builds per interpreter, unchanged disabled
paths, 144 FunctionObf Lua 5.1 differential builds, MOV high release-check,
GUI/configuration persistence, the register-cache regression and the 18-input
CLI corpus. [Cache-specific timings](register-cache.md) separately compare old,
validating and disabled caches; all paired synthesis samples here use the fix.
