# Adaptive semantic opcode synthesis: initial design

Baseline: dev `d690710` (1.3.0). First milestone is Phase A/B: shared semantic
planning plus an executable dispatch/register-local prototype. This is not yet
enabled in the production VM pipeline or user presets. Source passes, VM blob
ABI and release version remain unchanged during this milestone.

## Existing pipeline and reuse

`VMBuildPipeline` compiles Lua, normalizes/optimizes SemanticIR, runs independent
morphing strategies, builds/applies the initial ProtectionPlan, builds the final
plan, and then lowers/optimizes/emits through a backend. Candidate synthesis
belongs after the final semantic protection plan, before backend lowering.
It should retain an immutable SynthesisPlan alongside SemanticIR rather than
add arbitrary operations to the fixed semantic operation contract.

Reuse `ir/facts.py` (value/effect/definitions/CFG/dominance), `ir/liveness.py`
(liveness/captures/open top), source IDs and `ProtectionPlan.generation`.
Physical lowering already owns split/fuse/defer/variant bundles and canonical
address relocation. The writer already uses 6-byte instruction words, bounded
ULEB128 counts, sparse auxiliary tables and per-VM disjoint 15-bit vop allocation.
MOV appends separate microcode tapes to that shared blob.

Existing fusion consumes an adjacent pair and retains a second operand slot.
Its body decodes that slot and sequentially executes both ordinary operations.
It does not discover a larger def-use DAG or eliminate an intermediate rset/rget.
The prototype must demonstrate at least three operations in one semantic recipe,
one dispatch record, and local temporary values with dead VM writes removed.

## Shared recipe contract

A recipe contains ordered scalar steps over input/temporary references, inputs,
outputs, dependency edges, a semantic signature and estimated execution/storage
costs. An occurrence binds input registers/constants and output registers and
retains the exact ordered source instruction IDs and original fallback sequence.
Structural signatures abstract register numbers and constant-pool indices, but
retain input kind, input aliasing, operation ordering and output topology.
Shared definitions never erase occurrence-specific provenance or protection.

Safety precedes cost. The first prototype restricts local execution to proven
numeric scalar operations within one basic block. It does not reassociate Lua
arithmetic. Lua 5.3 integer and Lua 5.1 number semantics remain distinct.
Unknown operands, potential metamethods, capture/close/top/vararg/call boundaries
and protection-origin instructions are barriers. Only values dead at region exit
may omit VM writes; live outputs are committed in original definition order.

Recipe ownership, generation, source order, value-reference topology, operand
binding ranges, writes and fallback IDs are validated before use. Bad recipes
must not be silently accepted. Backend lowering may reject individual valid
recipes with an explicit fallback reason. It may not silently reject a whole
backend or weaken enabled protections.

## Protection preservation is a gate

Karity rset does more than store a number: it changes encoded epochs/representations
and `_ss_value` state. `_route_step`/`_ss_step` run at dispatch boundaries and
depend on PC, vop, operands and representation/state banks. Graph occurrences
have concrete identities, selector/state keys and avalanche scratch dependencies.
Even family-zero descriptors are not a license to omit those events. Deferred
reads can materialize pending values. Classic also has per-dispatch routing/state
updates. MOV HOST PREPARE/COMMIT boundaries are part of its operand/representation
contract, not just slow Lua calls.

Consequently a plain local-arithmetic handler cannot safely replace arbitrary
protected production sequences. The prototype records/rejects pending protection
obligations instead of disabling their settings to obtain a better benchmark.
Full integration needs backend event lowering that consumes all original logical
events, with trace assertions and explicit register-local/materialized modes.
Mutation, decoys and aliases must cover newly generated handlers too. Unknown
protection fields are rejected until their preservation contract is implemented.

## Physical lowering proposal for Phase C/D

Prefer one normal 48-bit slot with Bx indexing a sparse per-prototype occurrence
operand table. Inputs/outputs are ULEB descriptors; normal instructions pay no
per-slot field. Extension slots are the fallback when descriptor-table storage
loses against an inline bounded binding. Per-VM registries allocate collision-free
vops alongside current aliases/split/fuse/defer vops. Definitions may be reused
across prototypes, while bindings and original logical event sequences stay local.
Consumed semantic regions become atomic layout units: interior entries are
forbidden, existing fusion is excluded inside, canonical/branch/route addresses
are relinked once. Unselected sequences keep the existing layout.

Classic generates direct bodies from recipes, rather than concatenating existing
handlers. Karity emits graph/representation/state events around the same ordered
steps and commits. MOV lowers that same DAG to its MOVE/LOOKUP/SELECT/HOST model;
unprofitable or unsupported individual steps/recipes retain the exact original
lowering. This requires extending MOV slot/entry validation and HOST binding,
not routing all arithmetic through a generic Lua handler under another name.

## Cost and sharing

Measure dispatch, register accesses, binding bytes and handler bytes separately.
Include selected existing fusion, state replay, graph/pending overhead and
backend emission cost. Static hotness/repetition are estimates, not profiling.
Efficiency shares equivalent recipes; Balanced permits bounded regional forms;
Protection specializes regions within handler/storage/build budgets. All policies
share the same proof/protection gates. Prototype cost weights are explicitly
uncalibrated and cannot justify production preset defaults.

Phase B benchmarks compare ordinary scalar dispatch, two-slot fusion-shaped
execution and generated recipe execution with actual read/write counters.
These are mechanism measurements, not full Karity/Classic/MOV performance claims.
Phase D/F must repeat measurements in all three real runtimes, Lua 5.1/5.3,
with the five requested execution modes and all protection options held fixed.

## Milestones after the prototype

- C: occurrence registry, strict plan validation, backend preservation contracts,
  original-sequence fallback and generation-aware diagnostics.
- D: actual physical lowering/codec/dispatch/relocation for all three backends;
  retain full register writes where state preservation requires them.
- E: calibrate backend costs, implement the three sharing policies and explicitly
  compare existing fusion against synthesis.
- F: native differential tests, bad-binding/layout cases, full protection traces,
  coroutine/error/capture/top/multi-VM tests and per-backend benchmarks.
- G: opt-in CLI/JSON/GUI controls, dumps and docs, then measured preset integration
  and the 1.4.0 version bump. Off-path bytecode/runtime equivalence is mandatory.
