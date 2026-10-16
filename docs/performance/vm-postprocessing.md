# VM postprocessing, 2026-10-13

The later [DAG generation optimization](vm-generation.md) implements the unused
candidate work that was still pending in this measurement.

Baseline `ddcfdd2`; Windows, Python 3.15, native Lua 5.3,
`PYTHONHASHSEED=0`, seed 8471. The actual GUI API uses built-in presets and
its ordinary profiler. No source, output or protection settings were reduced.
Raw samples and complete configurations (generated locally).

## Changes

- Measure each generated number expression once. Budget-only calls count
  operators without constructing diversity counters; enabled diagnostics reuse
  the measured summary. Expression generation and PRNG consumption are unchanged.
- Capture literals, identifiers, labels and comments together for scalar output
  finalization. The original tree and binding graph remain authoritative;
  generated non-scalar syntax still requires complete final analysis.
- Read numeric spellings without copying their provenance onto temporary tokens.
  Protected spans and origins are read from the original source and retained.
- Reuse short local names across independent functions during shared VM output
  finalization. Names remain distinct within each function. Captured names are
  reserved through every intermediate function, including grandchild captures.
  General source naming and readable hints retain their existing policy.

Frequency-ranked naming already existed. Unused graph candidates are still
constructed to retain the existing generator stream. Graph variants, helpers,
source protection, NumberObf/MemeStrings styles and arithmetic budgets are intact.

## Full output sizes

| Preset / input | Before bytes | After bytes | Removed | Reduction |
|---|---:|---:|---:|---:|
| Fast / `print("hi")` | 752,918 | 731,149 | 21,769 | 2.89% |
| Fast / nested loops | 723,762 | 672,416 | 51,346 | 7.09% |
| Fast / closures, varargs, coroutine, errors | 823,697 | 800,042 | 23,655 | 2.87% |
| Fast / UTF-8 STRING_OBF macro | 1,341,467 | 1,295,488 | 45,979 | 3.43% |
| Strong / `print("hi")` | 4,621,421 | 4,386,010 | 235,411 | 5.09% |
| Maximum / `print("hi")`, packed | 2,572,290 | 2,327,418 | 244,872 | 9.52% |

The four Fast cases have two samples per checkout. Strong/Maximum have one
size/correctness sample and ran alongside regression checks: their times are
diagnostic, not an isolated performance comparison. Maximum benefits from
shorter identifiers and more repetitive identifiers in its compressed payload.

## Time and preservation

Two ordinary Fast samples suggested lower build wall/CPU time, but workstation
variation was substantial. A separate reverse-order check gave:

| Input | Before wall | After wall | Before CPU | After CPU |
|---|---:|---:|---:|---:|
| `print("hi")` | 6.877 s | 6.844 s | 3.094 s | 2.813 s |
| Nested loops | 6.145 s | 5.561 s | 2.625 s | 2.500 s |

These are single check samples, not confidence intervals. Hello World wall time
is effectively unchanged; the loop check improved about 9.5%. No general
execution-speed improvement is claimed. Ordinary Fast execution CPU samples
overlap (0.055–0.191 s before, 0.058–0.144 s after).

All samples match runtime stdout and serialized protected-IR hashes. Fast and
Strong also match generated numeric-expression sequences and expression counts.
Maximum retains the expression count; its final expression hash changes because
packing a different Lua payload changes loader length/checksum constants.
Active arithmetic/semantic/loop variants, occurrence families and audited helper
counts match. All identifier occurrences still receive a replacement.

Relevant regressions cover exact shared/sequential naming output, sparse/full
capture coverage, protected numeric origins, field escape analysis, closure
captures, varargs/trailing nils, coroutine/errors, late generated helpers and
repeated passes. Classic/Karity/MOV generated-program tests exercise Lua 5.1/5.3.

Reproduce with `tools/profile_vm_postprocessing.py --tree <baseline-checkout>
--output <baseline.json>`, then run without `--tree` for the current checkout.
