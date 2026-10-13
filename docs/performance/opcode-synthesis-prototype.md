# Adaptive opcode synthesis: Phase A/B results

This is a mechanism prototype on dev `d690710`, not completed 1.4.0 backend
integration. Production Karity/Classic/MOV emitters, serialization, source passes,
GUI presets and version remain unchanged. The common prototype is opt-in through
its Python API and is not wired into VMPass.

## What is implemented

`vm/synthesis/model.py` holds backend-independent recipes, ordered value-reference
steps, dependency edges, occurrence bindings, source IDs and structural costs.
`planner.py` reuses the existing value/effect/liveness/capture analyses. Within a
basic block it identifies connected numeric DAGs of 3–16 operations. Register
overwrites become new temporary versions, not ambiguous register-name references.
Live outputs are committed in original definition order; dead intermediate writes
remain local. Original instruction IDs and the unchanged SemanticIR provide the
exact fallback sequence. No algebraic reassociation is performed.

The initial operations are ADD, SUB, MUL and NEGATE with proven numeric operands.
Unknown/metamethod operands, active captures, open top, effect/lifetime boundaries
and protection-origin instructions are barriers. Numeric-for value facts now
retain Lua 5.1's float domain when the initial state is proven numeric. This does
not introduce Lua 5.3 integer/bitwise semantics into Lua 5.1.

Registry signatures retain operation order, input aliasing/kinds, dataflow and
output topology while abstracting register/constant indices. Efficiency shares
definitions. Balanced/Protection prototype policies can create regional identities
within budgets; this only verifies ownership/sharing machinery, not improved
protection diversity. Runtime variants and calibrated cost decisions remain for
later phases.

Generation, contiguous ownership, DAG semantics, operand/output bindings, source
fallback order, IDs and overlaps are revalidated. Corrupt plans fail explicitly.
The prototype allocates deterministic disjoint 15-bit vops and writes a real
6-byte instruction record with a ULEB operand-binding table. It does not change
the existing KVM format or claim its test packet is a complete VM blob.

## A real discovered recipe

Lua input:

```lua
local sum = 0
for i = 1, 100000 do
    local a = i * 3
    local b = a + 7
    local c = b * 5
    sum = sum + c
end
print(sum)
```

The optimized SemanticIR contains `MUL → ADD → MUL → ADD`. Discovery produces
four ordered steps, edges `0→1→2→3`, two register inputs, three constant bindings
and one live output. Dynamic vop 4494 is assigned for benchmark seed 14000.
The generated body is equivalent to:

```lua
local i = rget(binding.iterator)
local previous = rget(binding.accumulator)
local t0 = i * constant(binding.k0)
local t1 = t0 + constant(binding.k1)
local t2 = t1 * constant(binding.k2)
local t3 = previous + t2
rset(binding.output, t3)
```

This body is synthesized from value references, not existing handler-body
concatenation. It has one semantic dispatch record rather than two pair handlers
and four operand records, and actually omits three temporary VM writes/reads.
Tests also exercise a DAG whose first definition is used across another numeric
calculation, so discovery is not restricted to adjacent producer/consumer pairs.

## Measured mechanism costs

100,000 region executions, seven samples per mode, rotated measurement order.
CPU clocks measure Lua execution; process startup is excluded. Instrumented runs
count accesses separately from timing runs. Lua 5.3 uses the native executable;
Lua 5.1 uses the existing Lupa runtime. All results match the original Lua result
`75004250000`.

“Pair execution” is a fusion-shaped prototype baseline that retains materialized
intermediates. It is not the production fusion emitter, whose decoding and private
state costs are absent from this isolated harness.

| Metric | Ordinary | Pair execution | Synthesis |
|---|---:|---:|---:|
| Dispatches | 400,000 | 200,000 | 100,000 |
| VM register reads, excluding constants | 500,000 | 500,000 | 200,000 |
| VM register writes | 400,000 | 400,000 | 100,000 |
| Lua 5.1 median CPU seconds | .055 | .045 | .029 |
| Lua 5.3 median CPU seconds | .047 | .039 | .026 |
| Lua 5.1 generated harness bytes | 555 | 513 | 697 |
| Lua 5.3 generated harness bytes | 543 | 501 | 685 |

Synthesis reduces dispatches 75%, register reads 60% and writes 75% versus
ordinary execution. Isolated CPU time falls 47%/45% on Lua 5.1/5.3, and 36%/33%
versus pair execution. This is evidence for the local-execution mechanism, not
an equivalent speedup for the full obfuscator or protected VM runtimes.

The one-off harness grows 26% versus ordinary and 36–37% versus pair execution.
Operand binding introduces overhead: synthesized code must not be selected just
because it dispatches fewer times. Planning takes about 1.1/1.0 ms on this tiny
input; larger-input scalability and protection event replay remain unmeasured.

Region records occupy 24 bytes in ordinary/pair form. The prototype synthesized
packet has a 6-byte record plus 13 binding bytes = 19 bytes, before registry/
handler/section framing overhead. This does not establish complete VM-blob size
reduction. Shared definitions can amortize handler cost; the prototype validates
sharing and distinct occurrence binding, but has not measured full VM amortization.

Raw samples, actual recipe/kernel and packet data:
[opcode-synthesis-prototype.json](opcode-synthesis-prototype.json).
Reproduce with `tools/profile_opcode_synthesis_prototype.py --output REPORT.json`.

## Protection gate and the next integration work

Real protection plans are currently rejected with
`production_event_lowering_not_implemented`. This intentionally includes even
unselected/family-zero arithmetic descriptors until event semantics are explicit.
The benchmark does not claim to preserve private states by simply removing them.
No production protection setting is changed to obtain these figures.

Karity encoded writes update epochs and `_ss_value`; dispatch updates `_route_step`
and `_ss_step`; pending reads can materialize producers. Classic dispatch also
updates private routing state. MOV has HOST PREPARE/COMMIT and linked microcode
entry invariants. Full integration needs backend lowering of the *same recipe*,
including those original events. Some regions should keep intermediate
materialization; others must fall back. Mutation/decoys/aliases, multi-VM allocation,
physical relocation and sparse-table decoding must cover synthesized handlers.

Phase C/D are therefore not complete. The design in
[adaptive-opcode-synthesis.md](../design/adaptive-opcode-synthesis.md) specifies
those contracts. Phase E must compare actual normal/fusion/synthesis costs in
each backend; Phase F/G then add complete protection traces and opt-in CLI/GUI
controls. No 1.4.0 release claim or preset default is made at this milestone.

## Verification

New prototype tests cover Lua 5.1/5.3 native-result parity, counters, register
overwrites, negative/floating/signed-zero calculations, non-adjacent dataflow,
sharing/regional identities, collision/exhaustion, 48-bit packet fields, malformed
recipes/bindings, overlap/stale generation and capture/top/metamethod/provenance
rejection. Production plans are explicitly refused.

Python 3.12/3.15 pass the new prototype and value-facts tests. Existing IR morphing
passes 27 differential VM builds on each Python version. The existing Lua 5.1
semantic matrix passes 30 builds across Classic/Karity/MOV. These existing-backend
results verify regression absence, not synthesis integration. CI's manifest lists
the new prototype regression; hosted CI is separate from these local results.
