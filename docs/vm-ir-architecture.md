# VM IR architecture

The VM build has an explicit backend-neutral pipeline:

```text
Lua source
  -> selected Lua 5.1/5.3 compiler and frontend
  -> normalized typed SemanticIR
  -> semantic optimization / ProtectionPlanner / capability resolution
  -> backend-independent semantic protection / final ProtectionPlan
  -> backend lowering / optimization / validation
  -> backend serialization and runtime emission
  -> target finalization / output passes / dump integrity / wrapper
```

`SemanticIR` models functions, basic blocks, typed instructions and values with
stable IDs. Its validator checks references, CFG targets and terminators.
Frontends decode parser prototypes into this model; backend inputs do not retain
the source Proto or raw Lua instruction-word bridges.

`ProtectionPlan` records semantic targets and policy, not backend opcode numbers
or microcode tables. Capability resolution activates a native implementation or
declared fallback, disables an unsupported optional request with a warning, or
rejects an unsupported required request. See [backend options](backends.md) and
[Lua 5.1 pass boundaries](lua51-pass-matrix.md).

## Ownership and contracts

| Component | Responsibility |
|---|---|
| `vm/frontends/` | Version-specific decoding into normalized common IR |
| `vm/ir/` | Common model, validation, liveness and semantic optimization/protection |
| `vm/protection.py` | Concrete protection targets, policy and capability resolution |
| `VMBuildPipeline` | Orchestrates frontend, planner and backend lifecycle |
| `ClassicBackend` | Typed handlers, immutable dispatcher/placement state and conservative layout optimization |
| `KarityBackend` | Pending/epoch/representation state, continuation routing, graph emission and materialization optimization |
| `MovBackend`, `vm/mov/` | Semantic/control adapters, MOV Micro IR, optimization, serialization and HOST boundaries |
| `vm/targets/`, versioned runtime assets | Compilation, native APIs/storage, finalization, dumps and wrappers |

Classic and Karity share a typed handler ABI and physical codec. MOV binds its
semantic/control inputs to the serialized HOST layout, while its micro-operations
remain MOV-local. Backend choice and target version are independent axes.

Backend `lower`, `optimize`, `validate_lowered`, serialization and `emit` hooks
own their representations. Physical validation rejects mismatched operations,
split/fuse interiors and invalid routes. Karity validates pending producer and
epoch alternatives across CFG joins, capture/close boundaries and graph inputs.
MOV validates linked tapes, continuations, scratch/codebook references and HOST
guard/fallback/commit boundaries.

Protection targets and policy are selected before emission. Backend-local random
names, scheduling and equivalent encodings do not reselect protected sites.
Runtime-dependent materialization and rotation use planned guards and triggers.
Karity graph compilers and their isolated RNG live in `backends/karity_graphs.py`;
the shared runtime emitter does not define or re-export them.

## Target-native runtime generation

Target contracts select runtime templates, entry symbols, blob decoding and graph
operations without shared emitters rediscovering a Lua version string. Lua 5.1
uses `runtimes/lua51/`; Lua 5.3 retains its own assets. User values stay native,
while exact private 48/64-bit storage belongs to the target runtime.

Lua 5.1 finalization resolves explicit private operations and API syntax nodes,
not arbitrary source expressions. Unsupported late APIs are rejected. Private
word recognition uses `rawget` to avoid invoking user-table metamethods, and late
capture compaction banks immutable generated helper bindings without banking
mutable cells or user values. See [Lua targets](lua-targets.md).

## Debug dumps

The CLI exposes deterministic snapshots:

```text
--dump-ir semantic.ir
--dump-protected-ir protected.ir
--dump-protection-plan protection.plan
--dump-backend-ir backend.ir
```

Lifecycle stages retain their own generation and stable IDs. Backend dumps include
selected policy, backend state and optimization details; MOV dumps include its
`MOVE`, `LOOKUP`, `SELECT` and `HOST` tape. Stale-generation input is rejected.

## Invariants and limits

- Common IR contains no backend-specific state or MOV microcode.
- Both frontends use the same normalization and semantic types.
- Capability declarations drive CLI/GUI option metadata and validation.
- Protected targets are not chosen again during serialization or emission.
- Backend optimizers preserve calls, errors, metamethods, captures and yield boundaries.

Karity's static comparison specialization is a conservative within-instruction
optimization. Cross-instruction decoded-value reuse is runtime memoization, not a
general static region optimizer. MOV retains hybrid HOST operations; it is not
complete MOV-only execution. The separate [native execution domain](native-lowering.md)
supports a bounded integer leaf subset, not a general native compiler.
