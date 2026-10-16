# DAG generation and shared executor leaves

Baseline `bd28f7b`; VM-only output, seed 9171, three alternating-order samples
per case on Windows. No source/output passes or packing. Serialization, blob
encoding and protection settings are unchanged. Raw results:
Python 3.15 / Lua 5.3 (generated locally),
Python 3.12 / Lua 5.1 (generated locally).

## Generate live candidates

The previous dependency optimization already omitted unused graph entries from
the output, but still compiled their bodies. Candidate positions now reserve
one seed each. Only live candidates construct their bodies, using their own
PRNG. Skipping one cannot alter later candidates or the protection-plan RNG.
Fixed name allocation and sparse bank indices remain intact. Old graph text
is not byte-identical: candidate seed isolation changes equivalent encodings.

Dependencies still include fake handlers, aliases, indirect calls, execution-kit
clones and cold protection routes. Unknown/computed keys retain the complete
bank. Every retained arithmetic kind keeps eight DAGs and four native variants;
every semantic kind keeps its four heavy/direct variants. Occurrence, call,
control and value graph families retain their existing policy.

| Lua 5.3 input | Arithmetic DAGs constructed | Semantic variants constructed | Loop graphs constructed |
|---|---:|---:|---:|
| Hello World | 80 → 0 | 72 → 8 | 3 → 0 |
| All arithmetic operations | 80 → 80 | 72 → 28 | 3 → 0 |
| Nested loops | 80 → 24 | 72 → 24 | 3 → 3 |
| Closures / varargs / coroutine / errors | 80 → 8 | 72 → 24 | 3 → 0 |
| Loops, occurrence graphs off | 80 → 0 | 72 → 24 | 3 → 3 |

**Emitted variant counts are identical to the baseline in every paired case.**
These reductions concern internal construction, not removing previously emitted
protection. The existing `*_before` fields describe potential candidate counts;
`*_generated` now reports bodies actually constructed.

## Share identical executor leaves

ULEB128 readers, prototype readers, blob decoders and basic conversions already
live outside the executor template. `vm_count` does not duplicate them. Large
new savings from sharing those functions are therefore unavailable.

The new sharing pass has a closed allowlist and exact AST signatures, retaining
parentheses because they can affect return arity. Binding analysis verifies
direct calls and rejects escaping function identities or executor layouts
crossing lexical blocks. Karity also reuses the
existing helper dependency AST/bindings rather than parsing again.

- Karity: fixed slot masking (`_rslot`) and the wrapper calling the existing
  outer mixer (`_rmix`). The latter is shared only when all calls resolve to
  the same immutable outer binding. Lua 5.1 conservatively retains the wrapper
  when its mixer references do not pass this audit.
- Classic: packet count/read and identity leaves (`_acount`, `_aget`, `_carry`).
- MOV: no eligible executor duplicates; its packet utilities are already outer.

Sharing preserves VM count, maps, assignments, keys, frames, register rotation,
handler variants, graph-bank variants, dispatch and protection state. Graph banks
were already program-wide; this change does not merge new protection banks.
Single-VM runtime source is byte-identical with sharing on/off.

| Lua 5.3 input / effective VM count | Duplicate declarations removed | Runtime bytes saved by sharing | Runtime reduction |
|---|---:|---:|---:|
| Arithmetic / 2 | 2 | 503 | 0.034% |
| Arithmetic / 3 | 4 | 876 | 0.053% |
| Closures / 2 | 2 | 497 | 0.071% |
| Closures / 3 | 4 | 870 | 0.093% |

Lua 5.1 retains `_rmix` and shares only `_rslot`: two-VM arithmetic/closure
cases save 208/200 runtime bytes, and three-VM cases save 363/350 bytes
(0.020–0.034%). These counts include target lowering and final naming.

`dag_only` and `after` use identical new DAG encodings and isolate sharing.
Whole before/after output differences also include equivalent graph encoding
variation and must not be presented as compression savings. Blob sizes are
unchanged. Output literals can have a few bytes of encoding variation even
when single-VM runtime text is unchanged.

Sharing provides a small common call site for these mechanical leaves. It does
not add a common opcode decoder, key schedule or graph dispatcher. Broader
sharing of frame-dependent state and protected execution paths was deliberately
deferred: their independence matters more than these modest size savings.

## Time and validation

Generation cost depends on which candidates remain; inputs requiring all
arithmetic operations have few candidates to skip. Full build time includes
runtime analysis, target lowering, integrity work and final emission. The raw
samples contain build wall/CPU, graph-emission CPU, execution CPU, sizes, function
counts and retained variants. These process CPU samples are quantized in about
16 ms steps; very short graph samples can read zero. Workstation timing varies substantially,
so these results do not establish a universal build or execution speedup.

Selected medians (seconds; execution includes loading and initialization):

| Target / input | Build wall before → after | Graph emission CPU before → after | Execution CPU before → after |
|---|---:|---:|---:|
| Lua 5.3 / Hello World | 1.000 → 0.934 | 0.047 → 0.016 | 0.035 → 0.037 |
| Lua 5.3 / all arithmetic | 2.774 → 4.446 | 0.094 → 0.312 | 0.123 → 0.236 |
| Lua 5.3 / loops | 2.743 → 2.567 | 0.109 → 0.031 | 0.221 → 0.206 |
| Lua 5.3 / closures, 2 VMs | 1.090 → 1.109 | 0.031 → 0.016 | 0.047 → 0.042 |
| Lua 5.1 / loops | 7.348 → 6.907 | 0.047 → 0.031 | 3.305 → 3.183 |
| Lua 5.1 / arithmetic, 3 VMs | 14.032 → 15.456 | 0.172 → 0.125 | 4.552 → 4.537 |

Some samples regress, particularly the Lua 5.3 all-arithmetic case; all its
arithmetic candidates still need construction. These are three samples at one
seed, not confidence intervals. Equivalent randomized encodings differ and
can affect runtime work as well as code size. This change establishes reduced
unused construction and removal of verified duplicates, rather than a general
performance claim. No limits or test timeouts were raised.

Every paired build asserts equal serialized protected-IR and protection-plan
hashes before runtime-dependent integrity patching/encryption, equal retained
graph counts, and matching original/generated execution output. Coverage includes
loops, floats, bit operations (Lua 5.3), closures/upvalues, multiple results,
trailing nil, coroutine yields/resumes and error handling. Dedicated regressions
also cover graph-off generation, candidate RNG restoration after exceptions,
shadowed/mutable mixers, escaping functions, separate scopes and changed
audited bodies.

Final checks passed: shared-skeleton regressions on Python 3.12 and 3.15;
VM runtime size/dependency regression (14 builds); generated cross-backend
matrix (24 builds on Classic/Karity/MOV); finalizer (114 cases); VM output
emitter integration; runtime polymorphism (five distinct traces); state coupling
(12 builds, six dispatcher styles); standalone/packed line-state integrity;
Linux/Windows mypy contracts and Python 3.12 syntax; generated-doc/CI manifest
checks. Existing tests and limits are unchanged, and the new skeleton regression
is included in the shared CI manifest. A full hosted CI run is separate.

Reproduce with `tools/profile_vm_generation.py --output <report.json>`;
use `--lua-version 5.1` for the compatible arithmetic fixture. `vm_count` remains
clamped by prototype count; the report records the effective value.
