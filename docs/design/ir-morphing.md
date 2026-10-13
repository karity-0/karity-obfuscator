# Physical permutation and semantic morphing

Baseline: `6c2b7a6` on dev. Source passes remain unchanged.

## Placement

Compilation → semantic frontend/normalization → existing optimization → morphing
→ validation → initial protection plan → semantic protection → final plan
→ handler lowering/layout → physical permutation → serialization/runtime.
Plans are generated from the new IR generation, never patched across generations.
Post-morph normalization preserves intentional morph block boundaries using real
transform provenance; it does not introduce fake edges.

## Physical layout

Reuse existing layout chunks and retain each selected block's route and variants
as one unit. Bind skip instructions to their following slot; retain extension,
split/fuse and integrity stream adjacency. Keep the entry unit first. Shuffle
selected units using a private seeded stream, reconnect displaced fallthroughs
with budgeted absolute BLOCK_GOTO slots, and relink relative jumps, existing
absolute jumps, canonical indices and 1-based route addresses in one mapping.
Validate the complete candidate before replacing the original layout. Encoding
or bridge budget exhaustion retains the original layout and reports the reason.
Karity/Classic share this representation; MOV permutation is initially unsupported
and reported by the existing capability/required-protection system.

## Small semantic strategies

One function analysis supplies CFG/predecessors, dominance, conservative value
facts, reaching definitions, effects, existing liveness/captures and open-top
constraints. Strategies are independent functions with separate rates, explicit
eligibility checks and diagnostics. Reuse the snapshot until a strategy changes
the function; refresh before the next strategy. No generic plugin framework.

- TEST_SET: TEST plus an edge-local MOVE block. Only the matching edge writes;
  truthiness and operand evaluation are unchanged.
- Tail duplication: redirect one incoming edge of a safe acyclic join to a fresh
  block clone. Calls can remain only where cloning cannot cross capture, top,
  close or loop boundaries; exactly one copy executes per path.
- Rematerialization: clone a proven pure dynamic calculation at a later use into
  a fresh register. Require a unique reaching definition, dominance and unchanged
  operand definitions. Rewrite scalar uses only, retaining other consumers.
- MBA/substitution: lower proven Lua 5.3 integer operations to multiple ordinary
  IR instructions, using several 64-bit identities. Preserve modulo-2^64 behavior;
  uncertain operands, floats, implicit conversions and possible metamethods stay
  unchanged. Lua 5.1 uses TEST_SET/tail strategies and reports integer MBA and
  integer rematerialization unavailable.

Fresh instruction/block IDs retain source line/PC and explicit parent provenance.
Generated instructions carry protection provenance so the existing optimizer
cannot fold them back. No strategy recursively processes its own output.
Scratch registers are appended within the 255-register ABI only when open-top
constraints permit. Function/strategy/pass growth and transformation budgets
bound expansion; recorded skips are distinct from invariant failures.

## Controls and validation

All new rates default to zero for existing CLI/JSON profiles. User presets receive
measured ascending densities/budgets; backend choices and saved overrides retain
their existing ownership. Add option validation, capabilities, GUI metadata,
generated docs and a morphed-IR debug dump.

Tests prove physical storage actually changes, jump/route validity, structural
IR substitution/def-use/CFG changes, disabled-path identity, multiple seeds,
Lua 5.1/5.3 and supported backends. Differential inputs cover overflow, floats,
metamethods, captures/close, top/varargs/trailing nil, calls/errors/coroutines and
existing graph/split/fuse/variant/integrity protection. Measure strategies alone
and combined before selecting preset defaults; report unavailable/unsafe cases.
