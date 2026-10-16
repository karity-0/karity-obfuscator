# Terminal opcode synthesis measurements

Baseline `9af561d`; Python 3.15.0, Karity / Lua 5.3, seed 1400, 3 alternating samples. VM only, ample Protection budgets. Block clones and physical permutation are disabled to isolate these recipes; other protected settings retain graphs, alias/state, integrity, mutation and pending work. These are not full GUI preset timings. Concurrent local regressions make timings indicative. Lua os.clock includes initialization, excluding parsing and process launch. All outputs match native Lua.

| Input / protection | Build s | Execute s | Output bytes | Terminal regions |
|---|---|---|---|---|
| call / False | 1.590 → 1.642 | 0.134 → 0.154 | 151,121 → 153,790 | 0 → 1 |
| call / True | 3.015 → 4.744 | 0.252 → 0.331 | 611,296 → 616,132 | 0 → 1 |
| branch / False | 0.605 → 1.020 | 0.093 → 0.125 | 163,636 → 165,395 | 0 → 3 |
| branch / True | 1.706 → 1.713 | 0.201 → 0.183 | 557,963 → 480,718 | 0 → 3 |

Terminal synthesis expands the opcode vocabulary; it does not guarantee a smaller or faster build. Original encoded stores and logical events remain. Terminal mixed recipes retain materialization and do not borrow the scalar strategy's raw temporaries, which can add work relative to a scalar-only region. Per-kind arithmetic DAG, native variant and occurrence-family counts are asserted equal for protected pairs. Raw records include runtime/blob sizes. If grouping a terminal would remove existing selected block clones, the generator recovers eligible prefix DAGs using shared discovery and records `terminal_block_variants`; recovered candidates still pass the ordinary budgets.
