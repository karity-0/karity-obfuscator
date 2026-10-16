# Compact prototype storage

Baseline: `c4f02f8` (1.2.0), Windows / Python 3.12, seed 9450.
Raw paired storage measurements (generated locally) and
whole-pipeline smoke measurements (generated locally).

## Storage and protection

The shared handler blob uses format `KVM\x02` before encryption. Instructions
occupy six little-endian bytes. All 41 operand/opcode/variant bits, the seven
remaining low-word padding bits, randomized field positions and rolling opcode
accumulator are retained. The unused upper 16 padding bits are omitted. Padding
entropy therefore decreases from 23 to seven bits per instruction; this is not
a claim that every aspect of the physical representation is unchanged.

Physical slots, split/fused/operand instructions, PC numbering, block routes,
graph descriptors, scratch slots and integrity programs are unchanged. Runtime
execution still fetches from the same instruction-indexed arrays. Lengths and
counts do not affect accumulator steps or integrity's instruction-count input.

Each avalanche/graph metadata section has an absent/dense/sparse mode byte.
Sparse sections store a ULEB128 entry count and positive deltas between physical
instruction indices. Record payloads retain their original count byte and
fields. Actual index/count storage sizes select the smaller representation;
ties use dense storage. Empty records alone are omitted: a graph family or
policy of zero and a scratch slot of zero remain valid, preserved data.

Instruction/constant/upvalue/child/route counts, string byte lengths, and route
targets use canonical uint32 ULEB128. Integers and floats remain 64-bit; hashes,
random selector seeds and graph IDs remain fixed-width. Readers reject uint32
overflow, overlong values, invalid modes and invalid sparse indices. Python's
integrity patcher skips the compact instruction region and walks both metadata
forms; appended MOV data remains untouched.

New artifacts include their matching decoder. Previously generated standalone
Lua artifacts retain their embedded old decoder and require no migration. Raw
legacy handler blobs are not accepted by the new decoder/patcher; version
mismatches fail explicitly. The MOV v11 extension is unchanged.

## Paired storage measurements

Three inputs (small, UTF-8 strings, closures/varargs/coroutines/error handling),
four user presets and three backends produce 36 comparisons. Each comparison
uses the exact same source-protected physical program and serializer RNG state,
not separately randomized protection plans. Both Lua storage readers reproduce
identical low 48-bit words, metadata, constants and nested prototypes. Serializer
RNG consumption is identical. Five alternating batched samples measure each
implementation; the batch avoids short probes rounding to zero on Windows.

The following reductions include the unchanged MOV extension, but exclude the
encryption nonce, textual blob encoding, VM source and outer packing.

| Backend | Fast | Balanced | Strong | Maximum |
|---|---:|---:|---:|---:|
| Classic | 23.9–26.0% | 24.4–26.7% | 18.3–22.4% | 19.1–19.4% |
| Karity | 24.2–25.9% | 24.5–26.8% | 19.1–22.9% | 19.8–20.8% |
| MOV | 0.9–1.5% | 1.1–1.6% | 6.1–8.5% | 4.4–6.0% |

Across these snapshots, instruction storage is 25% smaller. Avalanche section
storage changes from 275,278 to 7,609 bytes while preserving every scratch slot;
the previous empty count bytes dominate that difference. Graph section storage
changes from 1,431,360 to 1,348,135 bytes. Its descriptor payloads are preserved,
and dense metadata deliberately avoids unnecessary index overhead.

Median per-case after/before wall-time ratios are approximately 0.92 for
serialization, 1.00 for the Lua 5.1 storage reader and 0.94 for Lua 5.3. Padding
masks are now computed once per writer. Reader probes include operand rekeying
and metadata/constant parsing, but omit encryption, keystream generation,
string masking and execution setup. These ratios are not whole-build/startup
speedups or statistical confidence intervals.

Reproduce with a baseline sharing the current physical handler IR:

```sh
python tools/profile_serialization.py --baseline-ref c4f02f8 --output storage.json
```

## Final artifacts and validation

One full Karity build per preset/format on the small fixture retained every
source/output pass and Maximum's packing. Three native Lua 5.3 executions of
each artifact matched original stdout. These builds ran concurrently with CI;
the recorded build/runtime times are descriptive and do not establish speedups.

| Preset | Final Lua bytes before → after | Size change |
|---|---:|---:|
| Fast | 870,483 → 873,268 | 0.32% larger |
| Balanced | 893,627 → 893,436 | 0.02% smaller |
| Strong | 4,584,275 → 4,462,076 | 2.67% smaller |
| Maximum | 2,190,448 → 2,132,890 | 2.63% smaller |

The added decoder has a fixed cost, and runtime Lua code dominates these files.
A smaller raw blob does not imply the same reduction in final Lua size or a
large total build-speed improvement. VM protection options and preset budgets
are unchanged.

The serialization regression covers both Lua readers, 100 random field layouts,
all metadata modes, uint32 boundaries and malformed data, binary/UTF-8/empty
strings, nested prototypes, integrity rebinding with a trailing MOV extension,
and protected execution on every backend/target pair. Existing Lua word,
host-materialization, state-coupling, MOV high release-check, Unicode blob and
packer regressions provide integration coverage.
