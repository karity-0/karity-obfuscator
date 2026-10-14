# Numeric DAG runtime and storage follow-up

Baseline `a1ab669` and current code: same process, Python 3.15, hash seed 0, random seed 1400. Three alternating pairs per case, VM only. Source/output passes and packing are excluded. Execution includes loading/initialization. All results match native Lua. Options, samples, pruning/storage/reuse profiles and decision totals/examples: [report](synthesis-storage.json).

| Backend / Lua / input | Build wall s | Execution CPU s | Output bytes | Change | Blob bytes |
|---|---|---|---|---|---|
| classic / 5.1 / dag | 0.538 → 0.519 | 0.415 → 0.374 | 51,369 → 49,255 | -2,114 (-4.12%) | 384 → 384 |
| classic / 5.1 / large | 1.473 → 1.724 | 1.311 → 1.393 | 103,780 → 100,146 | -3,634 (-3.50%) | 19,812 → 17,786 |
| classic / 5.3 / dag | 0.361 → 0.297 | 0.012 → 0.014 | 36,661 → 34,686 | -1,975 (-5.39%) | 386 → 386 |
| classic / 5.3 / large | 1.416 → 1.504 | 0.078 → 0.070 | 88,166 → 84,629 | -3,537 (-4.01%) | 19,814 → 17,788 |
| karity / 5.1 / dag | 1.764 → 1.661 | 1.003 → 0.944 | 155,265 → 153,031 | -2,234 (-1.44%) | 434 → 434 |
| karity / 5.1 / large | 3.560 → 3.118 | 3.337 → 3.650 | 223,703 → 219,930 | -3,773 (-1.69%) | 19,812 → 17,786 |
| karity / 5.3 / dag | 0.792 → 0.748 | 0.025 → 0.033 | 148,992 → 146,909 | -2,083 (-1.40%) | 436 → 436 |
| karity / 5.3 / large | 1.993 → 2.005 | 0.145 → 0.094 | 207,390 → 203,709 | -3,681 (-1.77%) | 19,814 → 17,788 |
| mov / 5.1 / dag | 0.803 → 0.872 | 1.757 → 1.890 | 132,853 → 132,853 | +0 (+0.00%) | 37,421 → 37,421 |
| mov / 5.1 / large | 7.824 → 7.751 | 4.313 → 3.787 | 220,418 → 218,638 | -1,780 (-0.81%) | 87,407 → 85,381 |
| mov / 5.3 / dag | 0.571 → 0.549 | 0.175 → 0.153 | 117,507 → 117,507 | +0 (+0.00%) | 37,363 → 37,363 |
| mov / 5.3 / large | 8.698 → 9.882 | 0.430 → 0.462 | 176,826 → 175,039 | -1,787 (-1.01%) | 71,146 → 69,120 |
| karity / 5.3 / maximum | 7.990 → 8.587 | 0.166 → 0.137 | 1,172,501 → 1,118,150 | -54,351 (-4.64%) | 3,925 → 3,925 |

The large fixture contains 256 repeated four-step numeric DAGs; it exercises operand dictionary storage. The maximum case uses the actual built-in VM settings. Smaller inputs retain KVM2 whenever dictionary and reader overhead cannot be recovered. MOV number-only HOST fallback bodies remain required. Logical PCs, all 48 word bits, accumulator updates, graph/state records and planned protection variants are retained. Timing differences include startup and scheduling noise; these are not full GUI preset times.

Full per-region decisions are available through the synthesis debug dump. Lua 5.1 verifies native rename/minify/StripInfo and emoji decoding; NumberObf/MemeStrings remain unsupported under its existing capability policy. Lua 5.3 also verifies NumberObf/MemeStrings after compressed loading.

Validation: Python 3.12 and 3.15 each pass 155 real VM builds (141 existing plus 14 compressed-storage/protected-trace/outside-handler builds), the ten-test serialization suite with 100 randomized layouts, and unchanged-RNG/disabled-byte-identity checks. Existing backend, state-coupling and typing checks also pass.
