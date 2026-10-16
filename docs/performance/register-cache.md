# Register cache validation costs

Python 3.15.0, seed 124; 9 rotated-order executions of each generated file. VM-only Karity, synthesis disabled; graph/state/dispatch protection remains enabled in protected cases. CPU includes blob loading and runtime initialization, excluding source parsing/process startup; builder timings are single samples. Lua 5.1 uses 200 arithmetic/comparison / 150 table/closure iterations; Lua 5.3 uses 4000 / 2500. Old cache is correct on these workloads, which never overwrite captured owner slots. Raw samples (generated locally).

| Lua / options / input | Old s | Full-position guard s | Cached-address guard s | Disabled s | Change vs old |
|---|---:|---:|---:|---:|---:|
| 5.1 / bare / arithmetic | 0.6260 | 0.6190 | 0.6200 | 0.6140 | -1.0% |
| 5.1 / bare / table_reads | 0.6500 | 0.6480 | 0.6460 | 0.6360 | -0.6% |
| 5.1 / protected / arithmetic | 2.1080 | 2.1190 | 2.1250 | 2.1740 | +0.8% |
| 5.1 / protected / table_reads | 2.1310 | 2.1280 | 2.0980 | 2.1100 | -1.5% |
| 5.3 / bare / arithmetic | 0.1310 | 0.1250 | 0.1300 | 0.1080 | -0.8% |
| 5.3 / bare / table_reads | 0.0900 | 0.0910 | 0.0870 | 0.0770 | -3.3% |
| 5.3 / protected / arithmetic | 0.3130 | 0.3230 | 0.3210 | 0.2970 | +2.6% |
| 5.3 / protected / table_reads | 0.1970 | 0.2010 | 0.1980 | 0.1770 | +0.5% |
| 5.1 / bare / repeated_operand | 0.5350 | 0.5480 | 0.5370 | 0.5320 | +0.4% |
| 5.1 / protected / repeated_operand | 2.2490 | 2.2650 | 2.2490 | 2.2200 | +0.0% |
| 5.3 / bare / repeated_operand | 0.0650 | 0.0690 | 0.0670 | 0.0630 | +3.1% |
| 5.3 / protected / repeated_operand | 0.1900 | 0.1930 | 0.1870 | 0.1720 | -1.6% |
| 5.1 / bare / captured_reads | 1.1210 | 1.1050 | 1.1060 | 1.1070 | -1.3% |
| 5.1 / protected / captured_reads | 4.9710 | 4.9640 | 4.9590 | 4.9830 | -0.2% |
| 5.3 / bare / captured_reads | 0.5970 | 0.5900 | 0.5940 | 0.5780 | -0.5% |
| 5.3 / protected / captured_reads | 1.0520 | 1.0300 | 1.0260 | 0.9880 | -2.5% |
| 5.1 / bare / cross_instruction | 0.6620 | 0.7080 | 0.6740 | 0.7080 | +1.8% |
| 5.1 / protected / cross_instruction | 2.2780 | 2.2700 | 2.2990 | 2.2900 | +0.9% |
| 5.3 / bare / cross_instruction | 0.0750 | 0.0810 | 0.0760 | 0.0770 | +1.3% |
| 5.3 / protected / cross_instruction | 0.2920 | 0.2960 | 0.2950 | 0.2730 | +1.0% |

The validating cache stores `{value, epoch, generation, epoch_bank_address}`. Generation is checked before dereferencing the cached bank address, so remapping cannot read an old slot. Valid hits avoid recomputing all four mapped addresses and avoid representation decoding. Pending producers finish before validation. Both Lua templates and their generated getter variants use the same rule. No protection option is removed. These timings are workload dependent and include coarse native clock resolution.

Across this matrix the checked cache changes CPU by -3.3% to +3.1% versus the old cache. That range includes measurement noise and runtime path changes caused by integrity rebinding; it is not an isolated getter-cost estimate. On the proven cross-instruction-reuse Lua 5.1 bare fixture, checked execution takes 0.674 s versus 0.708 s disabled (-4.8%). Several other fixtures run faster disabled, so caching is not a universal speedup. Version checks preserve correctness without eliminating valid cross-instruction hits. The existing VM regression independently instruments real hits across instruction PCs. Representation/escape invalidation and generation rotations limit useful reuse on protected paths.
