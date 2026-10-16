# Current synthesis cost selection

Python 3.15; seed 1400; 3 repeats per condition. VM only, source/output passes and packing excluded. Execution CPU includes loading and initialization. All outputs match native Lua. Raw samples (generated locally).

| Backend / Lua / input / mode | Build wall s | Execution CPU s | Output bytes | Regions | Dispatches |
|---|---|---|---|---|---|
| classic / 5.3 / dag / ordinary | 0.127 | 0.002 | 35,371 | 0 | 210 |
| classic / 5.3 / dag / fusion | 0.112 | 0.002 | 35,142 | 0 | 169 |
| classic / 5.3 / dag / synthesis | 0.163 | 0.004 | 34,686 | 1 | 90 |
| classic / 5.3 / dag / efficiency_fusion | 0.149 | 0.003 | 35,142 | 0 | 169 |
| classic / 5.3 / dag / balanced | 0.158 | 0.006 | 34,684 | 1 | 90 |
| classic / 5.3 / hot / ordinary | 0.135 | 0.012 | 35,371 | 0 | 10,010 |
| classic / 5.3 / hot / fusion | 0.119 | 0.014 | 35,142 | 0 | 8,009 |
| classic / 5.3 / hot / synthesis | 0.136 | 0.012 | 34,684 | 1 | 4,010 |
| classic / 5.3 / hot / efficiency_fusion | 0.142 | 0.012 | 35,142 | 0 | 8,009 |
| classic / 5.3 / hot / balanced | 0.129 | 0.014 | 34,686 | 1 | 4,010 |
| karity / 5.3 / dag / ordinary | 0.280 | 0.015 | 149,468 | 0 | 210 |
| karity / 5.3 / dag / fusion | 0.246 | 0.012 | 147,964 | 0 | 169 |
| karity / 5.3 / dag / synthesis | 0.284 | 0.011 | 143,165 | 1 | 90 |
| karity / 5.3 / dag / efficiency_fusion | 0.263 | 0.013 | 144,401 | 0 | 169 |
| karity / 5.3 / dag / balanced | 0.256 | 0.012 | 143,241 | 1 | 90 |
| karity / 5.3 / hot / ordinary | 0.255 | 0.062 | 146,403 | 0 | 10,010 |
| karity / 5.3 / hot / fusion | 0.232 | 0.061 | 151,362 | 0 | 8,009 |
| karity / 5.3 / hot / synthesis | 0.249 | 0.069 | 147,434 | 1 | 4,010 |
| karity / 5.3 / hot / efficiency_fusion | 0.282 | 0.083 | 150,303 | 0 | 8,009 |
| karity / 5.3 / hot / balanced | 0.265 | 0.064 | 143,824 | 1 | 4,010 |
| mov / 5.3 / dag / ordinary | 0.226 | 0.073 | 114,848 | 0 | 36,530 |
| mov / 5.3 / dag / synthesis | 0.264 | 0.078 | 114,848 | 0 | 36,530 |
| mov / 5.3 / dag / balanced | 0.230 | 0.072 | 117,564 | 1 | 36,451 |
| mov / 5.3 / hot / ordinary | 0.220 | 0.375 | 114,848 | 0 | 1,826,010 |
| mov / 5.3 / hot / synthesis | 0.272 | 0.349 | 114,848 | 0 | 1,826,010 |
| mov / 5.3 / hot / balanced | 0.242 | 0.351 | 117,564 | 1 | 1,822,011 |

Ordinary, selected pair Fusion and synthesis are distinct modes. MOV has no pair Fusion. Efficiency can reject synthesis when existing Fusion or mandatory MOV host scope work is cheaper; Balanced/Protection retain bounded diversity. Compiler work remains a proxy, not a runtime speed guarantee. Timing differences at millisecond resolution and short-input load costs are noisy. Full preset costs are measured separately in [pipeline measurements](synthesis-pipeline.md).
