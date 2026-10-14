# Adaptive semantic opcode synthesis

Implemented for 1.4.0 on dev. The Phase A/B decoded prototype remains documented
in [prototype measurements](../performance/opcode-synthesis-prototype.md).
Production measurements are in [VM measurements](../performance/opcode-synthesis.md).

## Common contract

Synthesis runs after semantic morphing and the final ProtectionPlan, before
physical lowering. It leaves SemanticIR and its source IDs intact and attaches
an immutable SynthesisPlan to LoweredIR. All backends use the same discovery,
value/effect facts, liveness, DAG registry and safety validator.

A recipe contains at least three ordered ADD/SUB/MUL/NEGATE steps. Inputs refer
to registers/constants or prior temporary values; edges can cross intervening
independent calculations. Signatures retain operation order, input aliasing and
output topology while abstracting concrete register/constant indices. Occurrences
retain their exact source instruction sequence, operand bindings, live outputs,
sharing scope and protection-plan signature. Register overwrites create new value
versions. Arithmetic is never reassociated.

Candidates stay within one basic block. Unknown types, metamethods, calls,
yield/close/capture boundaries and open stack tops cause explicit source fallback.
Lua 5.1 floating-number facts and Lua 5.3 integer/float facts remain distinct.
Provenance-marked calculations are eligible only with all original writes kept.
Calls, table access, comparisons and control operations retain ordinary lowering;
this is deliberately a bounded numeric recipe vocabulary, not a new Lua compiler.

## Actual physical representation

Each admitted region gets a program-specific, collision-free 15-bit vop. Original
48-bit instruction words remain as operand and logical-event records. Only the
head vop changes; interior words are consumed inside the recipe, not independently
dispatched. Existing rolling word encoding and sparse graph/avalanche metadata
remain in use. There is no new serializer ABI and no claim of blob compression.

Bindings are encoded in those existing operand words; the emitted sparse head
lookup and recipe bodies define their interpretation. Keeping the words preserves
original PC-based decoder, integrity, state and graph contracts. The standalone
prototype's compact binding encoding is not the production storage format.

Regions are atomic physical layout units. Existing pair fusion and splitting
remain available outside them; the region replaces those competing forms inside.
Karity deferred forms remain deferred inside a region. Clone routing/permutation
moves the complete region. No jump, skip or route may enter its interior.
Budget rejection happens before effective forms change, so a rejected occurrence
retains its original lowering. An admitted region lost during layout is a hard,
source-ID-bearing diagnostic rather than a silently weakened fallback.

## Backend lowering and protection

- **Classic:** generated DAG bodies cache numeric external inputs, use local
  intermediate values and commit only live outputs. Each original logical fetch,
  arithmetic primitive, avalanche record and alias-state transition still runs.
  Provenance-marked regions instead materialize every original register write.
- **Karity:** generated bodies retain encoded-register commits, graph occurrences,
  epochs and pending producers via the existing arithmetic/defer helpers. The head
  is restored to its original vop for routing/state events before recipe dispatch.
  Every interior instruction runs its own original fetch and state event. Register
  writes are retained even when liveness alone would permit their removal.
- **MOV:** the same region is lowered to scoped microcode. BEGIN/END boundaries
  bind the dynamic head to its program-specific recipe. Dead intermediate native
  values or encoded digit vectors live in frame-local temporary banks; live outputs
  use the original register representation. PREPARE/COMMIT guards, LOOKUP/SELECT
  arithmetic recipes and their original native fallback remain. There is no
  replacement of MOV arithmetic with a generic Lua calculation kernel.

New handler bodies receive the existing planned mutation machinery. Original alias
transitions remain specialized; semantically different alias-event contracts cannot
share a physical body merely because their numeric DAGs match. Fake handlers,
graph families, helper variants, state coupling, integrity and multi-VM options are
not disabled by synthesis. MOV's pre-existing unsupported options are still
reported by the capability system. MOV has no legacy physical pair-fusion/splitting
backend; those controls are explicitly marked unsupported there.

## Cost and sharing policies

All policies use identical semantic/protection gates. They differ in sharing and
admission, not correctness.

| Policy | Selection and sharing |
|---|---|
| Efficiency | Share equivalent DAGs/event contracts; require a loop region or repeated structural use to amortize generated code. |
| Balanced | Shared by default; deterministic bounded regional specialization, at most a quarter of the recipe budget (minimum one). |
| Protection | Region-specific definitions within the same explicit budgets. |

Default limits are 6 steps per region, 32 recipe/physical-handler groups and 512
source occurrences. Efficiency ranks loop/repeated candidates by retained-event
and bank-access savings; MOV includes its two extra scope microinstructions,
while Karity includes no speculative register-access saving. Nonpositive
structural work falls back under Efficiency. This is an explicit work estimate,
not a calibrated prediction of nanoseconds or a guarantee of faster execution.

Maximum settings are 16/256/4096. Admission includes physical
alias/defer specializations, not just semantic recipe count. These limits bound
handler generation; they are not a prediction that every admitted region is faster.

Costs separately report ordinary dispatches, a pair-fusion dispatch estimate,
recipe dispatches, register reads/writes, retained logical events, loop membership
and operand bytes. Actual emitted handler/head-table bytes are profiled separately.
The existing compiler cost probe measures each generated body. Large aggregate
handler sets use private per-frame closure banks once they exceed a quarter of
Lua's 131071-instruction signed jump range. Large mutated bodies reuse the existing
scratch compactor to reserve three quarters of Lua's 200-local limit for the
enclosing executor. Neither adjustment disables mutation or arithmetic events.
Karity materialized mode reports no register-access saving. MOV reports microcode
cost separately: its scope instructions can increase microdispatch count.

Measurements show that loading/initialization can dominate small programs and
that preserving encoded/pending state limits execution savings. Default user and
legacy presets therefore remain opt-in. Higher diversity is not proof of greater
security, and lower dispatch counts are not proof of lower total runtime.

## Controls and diagnostics

Use GUI advanced settings **Opcode synthesis** or JSON `vm_options`:

```json
{
  "opcode_synthesis": true,
  "synthesis_policy": "balanced",
  "synthesis_max_steps": 6,
  "synthesis_max_recipes": 32,
  "synthesis_max_occurrences": 512
}
```

CLI supports `--opcode-synthesis`, `--synthesis-policy efficiency|balanced|protection`
and the existing `--vm-option KEY=VALUE`. Policy alone does not enable the feature.
`--dump-synthesis-plan PATH` emits recipes, bindings, source IDs and structural
costs; `--dump-backend-ir PATH` adds actual dynamic opcodes and physical spans.
The profile includes discovery rejection counts, physical fallback diagnostics,
clone/handler counts and emitted handler size. GUI result inspection shows the
summary and the existing expandable profile. Backend/Lua choices and saved custom
settings remain independent of synthesis controls.

Disabled builds bypass discovery and emission, consume no synthesis RNG and retain
old VM output. Benchmark tests freeze OS nonce/wrapper entropy only to verify
byte identity; production retains the existing independent security entropy.

## Verification

The shared CI manifest runs prototype proof tests and real backend regressions.
Coverage includes all three backends and both Lua targets, differential execution,
register overwrite, floating arithmetic, pending heads, graph/block variants,
IR morphing/junk, physical permutation, multi-VM, closures/upvalues, varargs,
trailing nil, coroutines/errors/metamethod fallback, malformed bindings/scopes and
budget fallback. Existing frontend, protected backend, release-check, GUI, source
pass and runtime regression suites remain in place with unchanged timeouts.
