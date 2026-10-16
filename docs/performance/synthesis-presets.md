# Synthesis under built-in VM protection settings

Karity / Lua 5.3 / Python 3.15, seed 1400, three timed runs per condition. VM only: source/output passes and packing are excluded. All other preset VM options remain enabled. Execution includes loading and initialization; every result matches native Lua. Raw samples and options: report (generated locally).

| Preset / input | Build wall s, off → on | Execution CPU s, off → on | Output bytes, off → on | Change | Regions / handlers |
|---|---|---|---|---|---|
| fast / hello | 1.507 → 1.620 | 0.053 → 0.045 | 336,613 → 340,316 | +3,703 (+1.10%) | 0 / 0 |
| fast / dag | 2.381 → 2.403 | 0.096 → 0.092 | 560,825 → 568,093 | +7,268 (+1.30%) | 1 / 1 |
| fast / functions | 1.455 → 2.255 | 0.059 → 0.065 | 532,445 → 542,268 | +9,823 (+1.84%) | 1 / 1 |
| balanced / hello | 1.163 → 1.077 | 0.031 → 0.036 | 328,114 → 326,190 | -1,924 (-0.59%) | 0 / 0 |
| balanced / dag | 1.743 → 3.030 | 0.067 → 0.108 | 536,217 → 549,555 | +13,338 (+2.49%) | 1 / 1 |
| balanced / functions | 1.862 → 2.331 | 0.076 → 0.074 | 580,113 → 602,413 | +22,300 (+3.84%) | 2 / 2 |
| strong / hello | 1.137 → 1.491 | 0.036 → 0.050 | 348,368 → 347,868 | -500 (-0.14%) | 0 / 0 |
| strong / dag | 2.443 → 2.413 | 0.087 → 0.104 | 600,615 → 624,296 | +23,681 (+3.94%) | 1 / 2 |
| strong / functions | 2.823 → 3.886 | 0.120 → 0.140 | 1,069,293 → 1,085,846 | +16,553 (+1.55%) | 2 / 2 |
| maximum / hello | 1.168 → 1.440 | 0.045 → 0.047 | 321,107 → 318,592 | -2,515 (-0.78%) | 0 / 0 |
| maximum / dag | 2.632 → 2.196 | 0.149 → 0.071 | 739,340 → 736,772 | -2,568 (-0.35%) | 0 / 0 |
| maximum / functions | 4.137 → 3.775 | 0.141 → 0.138 | 1,370,394 → 1,377,671 | +7,277 (+0.53%) | 0 / 0 |
| maximum / long_dag | 2.921 → 7.836 | 0.133 → 0.116 | 1,019,246 → 1,172,501 | +153,255 (+15.04%) | 5 / 14 |

An enabled feature may admit no numeric DAG. Existing junk/morphing and type/effect boundaries can interrupt eligible regions, especially in small inputs. No preceding protection was disabled to increase these counts. Feature-request entropy can alter frame keys and runtime layout even when no recipe is admitted; source-size differences alone are not recipe cost. The raw profile separates discovery, cost admission and physical emission. CPU resolution and scheduling make small timing differences noisy. These VM-only numbers are not full GUI preset build times.
