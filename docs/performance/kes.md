# KES cost measurements

The KES frontend preserves ordinary source text. It adds a candidate scan; text containing feature-like strings/comments also takes a token gate that skips opaque text. Actual extensions use a scoped parser, source splices and a statement-anchored position map. Lazy expressions use lexical functions, so additional allocations, calls and stack frames are observable. They do not have a zero-overhead guarantee.

## Measurement method

`tools/benchmark_kes.py` compares two equivalent accumulator programs (ordinary Lua control flow vs `??`/`+=`) and a constant increment vs the actual VM-count getter. The getter comparison is a complete-program comparison, not an isolated opcode timing. Every emitted VM program must print its expected result before its sample is admitted.

The tool builds and executes each condition serially on Lua 5.3 and Classic/Karity/MOV. It uses minimal VM settings with no source/output transforms or packing. These settings isolate the language/API comparison; they are **not** GUI preset measurements. Two builds use seeds 9300–9301, and each output runs in three fresh Lua processes. Each accumulator loop has 500 iterations. Output size is UTF-8 bytes. Build wall time includes pipeline work; Lua CPU time includes loading and initialization but excludes process launch. Short-program timings and generated-code variation limit ratio interpretation.

Frontend timings use five batches of ten calls on three inputs: ordinary statements, ordinary statements with feature-like opaque literals, and equivalent KES statements. Unchanged inputs must retain their source object identity.

Raw configuration, input/output hashes, samples and executable artifacts are written beneath `local/performance/` and excluded from version control. Reproduce with:

```powershell
python tools/benchmark_kes.py --output local/performance/kes.json
```

## Recorded comparison (2026-10-17)

Host: Windows-11-10.0.22631-SP0; Python 3.15.0; bundled Lua 5.3. Medians below use the method above. Builds and executions ran serially without other regression jobs. The first build can include cold initialization; two seeds are not sufficient to establish a build-speed improvement.

| Frontend input | Source bytes | Lowered bytes | Median ms/call |
|---|---:|---:|---:|
| standard | 3,090 | 3,090 | 0.338 |
| opaque | 7,954 | 7,954 | 0.602 |
| kes | 3,858 | 19,587 | 6.619 |

The following pairs show **standard → KES/intrinsic**. Each CPU median contains six executions of two independently built outputs.

| Backend | Pair | Build seconds | Output KiB | Lua CPU ms |
|---|---|---:|---:|---:|
| classic | syntax | 0.200 → 0.119 | 35.76 → 36.61 | 8.5 → 19.5 |
| classic | getter | 0.115 → 0.113 | 34.93 → 35.57 | 12.5 → 8.0 |
| karity | syntax | 0.198 → 0.209 | 142.12 → 151.66 | 33.5 → 103.5 |
| karity | getter | 0.206 → 0.210 | 133.72 → 136.74 | 17.0 → 22.0 |
| mov | syntax | 0.227 → 0.198 | 105.87 → 105.83 | 76.0 → 127.0 |
| mov | getter | 0.161 → 0.168 | 85.84 → 86.08 | 56.5 → 48.0 |

In this 500-iteration syntax example, lazy-expression function calls increased Lua CPU time from 8.5 to 19.5 ms (Classic), 33.5 to 103.5 ms (Karity), and 76.0 to 127.0 ms (MOV). The convenience syntax therefore has a measurable runtime cost. These include VM initialization and are not steady-state per-operator costs. Getter differences are small and noisy, with some measured medians below the constant-control program; they do not establish that an intrinsic is faster than a constant. Output size and cost depend on the program and protection configuration.

## Full protection compatibility and cost

Correctness is checked separately on Lua 5.1/5.3 × three backends, minimal/protected intrinsic configurations, all 12 built-in backend/preset combinations, selection exclusions, and source/output transforms. The integration test also explicitly applies FunctionObf/Rename/Minify to **both** the VM and Packer outputs.

That last explicit configuration can be much more expensive than the built-in presets. One saved Karity protected output completed with the expected result in **147.5 seconds**, after the initial 60-second execution budget expired. A diagnostic hook showed its startup hash loop progressing through a roughly 2.30-million-byte transformed function dump. This is a wall-time observation including process startup, with other regressions running; it is not comparable to the minimal Lua CPU measurements. The expensive integration case has a 300-second execution bound. Its production protection settings were retained.

The implementation also corrected existing integration costs exposed by these inputs: selective minify now supplies exact lexical edits rather than diffing repetitive CFF source, and generic packing scans the original buffer and indexes scope depth once. Generic Packer field substitutions and payload line/upvalue ordering were corrected so finalized selective VM integrity remains valid. No native fallback or protection ablation was introduced to pass these checks.
