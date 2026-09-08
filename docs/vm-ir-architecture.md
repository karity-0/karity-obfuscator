# VM IR architecture

The VM build now has an explicit backend-neutral seam:

```text
Lua source
  -> Lua 5.3 compiler/parser (`Proto`)
  -> SemanticIR (`semantic_ir.py`)
  -> ProtectionPlanner (`protection.py`)
  -> capability resolution
  -> backend adapter lowering (`vm/backends/`)
  -> backend optimization boundary
  -> compatibility serializer/runtime emission
```

`SemanticIR` models functions, basic blocks, semantic instructions and values.
Instruction inputs, outputs, constants and control-flow targets use stable IDs.
The original Lua instruction word is retained only as frontend provenance for
the compatibility lowerers; it is not a backend field. `validate_semantic_ir`
checks unique IDs, value references, block targets and terminator placement.

`ProtectionPlan` is separate metadata keyed by those stable IDs. It records the
desired protection state (for example delayed materialization or state
threading), never a Classic handler number or a MOV lookup table. A backend
declares `BackendCapabilities`; resolution either activates a request, disables
an optional request, or raises for an unsupported required request.

## Current production map

| Existing component | Stage | Migration status |
|---|---|---|
| `Lua53Parser`, `Proto` | frontend artifact | retained as the lossless compatibility source |
| `build_semantic_ir` | semantic IR construction | production path |
| `inject_junk` | backend-independent protection transform | planned before application; still mutates `Proto`, then IR is rebuilt |
| serializer split/fuse/defer and graph-site selection | protection lowering | compatibility path behind backend adapters |
| `KarityBackend` | backend lowering | production adapter; exposes graph/state policies |
| `ClassicBackend` | backend lowering | production adapter to direct handlers |
| `MovBackend` and `vm/mov/ir.py` | backend lowering and MOV Micro IR | production adapter; micro-ops remain outside common IR |
| serializer, runtime templates, output emitter | backend optimization/emission | retained implementation |

The adapter layer is intentionally incremental: it preserves byte-for-byte
input semantics and the existing runtime emitters while moving policy ownership
out of the shared build method. Future migrations can replace one compatibility
lowerer at a time without changing the frontend or protection planner.

## Option ownership

Configuration is translated to requests by `ProtectionPlanner`. Backends decide
how supported requests affect their lowering policy. Unsupported options retain
the established CLI/GUI behavior: values stay in configuration, a warning is
reported at the boundary, and the optional request is disabled. This keeps a
stored profile portable across backends without silently pretending support.

## Debug dumps

The CLI can write deterministic, line-oriented snapshots suitable for fixtures:

```text
--dump-ir semantic.ir
--dump-protection-plan protection.plan
--dump-backend-ir backend.ir
```

The Semantic IR dump is taken before protection transforms. The protection plan
and backend dump describe the protected IR. MOV backend dumps additionally list
its `MOVE`, `LOOKUP`, `SELECT`, and `HOST` micro-instruction tape.

## Invariants

- Common IR contains no `mov_*`, `classic_*`, or `karity_*` fields.
- Backend capability declarations are the source used to derive unsupported
  option metadata.
- MOV micro-operations are attached only after MOV lowering.
- All three adapters consume the same `SemanticIR` and `ProtectionPlan` types.
- The legacy source artifact is private to the compatibility bridge and omitted
  from deterministic dumps.
