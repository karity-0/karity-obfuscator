# Adaptive semantic opcode synthesis

Implemented for 1.4.0 on dev. The Phase A/B decoded prototype remains documented
in [prototype measurements](../performance/opcode-synthesis-prototype.md).
Production measurements are in [VM measurements](../performance/opcode-synthesis.md).
Actual built-in protection settings are measured separately in
[preset measurements](../performance/synthesis-presets.md).
The runtime/storage follow-up is measured against `a1ab669` in
[numeric DAG measurements](../performance/synthesis-storage.md). This first
implementation began with a conservative numeric DAG vocabulary. The ordered
DAG follow-up adds table/upvalue reads, moves and further scalar operations;
direct VM calls and control operations are still region boundaries.
The expanded integer-bit vocabulary and revised admission model are compared in
[cost selection measurements](../performance/synthesis-cost-selection.md) and
[full user-preset pipeline measurements](../performance/synthesis-pipeline.md).
The ordered-DAG follow-up is measured separately in
[ordered DAG measurements](../performance/synthesis-dag.md).

## Common contract

Synthesis runs after semantic morphing and the final ProtectionPlan, before
physical lowering. It leaves SemanticIR and its source IDs intact and attaches
an immutable SynthesisPlan to LoweredIR. All backends use the same discovery,
value/effect facts, liveness, DAG registry and safety validator.

A recipe contains at least three connected, ordered steps. Proven numeric steps are ADD/SUB/MUL/NEGATE,
plus Lua 5.3 BIT_AND/BIT_OR/BIT_XOR/BIT_NOT/SHIFT_LEFT/SHIFT_RIGHT when every
operand is proven integer. Integral floats, coercions and bit metamethods do not
qualify for the proven-integer strategy. Shift direction, negative/large counts and overflow keep the original
Lua operation order; no algebraic reassociation or masking is introduced. Inputs refer
to registers/constants or prior temporary values; edges can cross intervening
independent calculations. Signatures retain operation order, input aliasing and
output topology while abstracting concrete register/constant indices. Occurrences
retain their exact source instruction sequence, operand bindings, live outputs,
sharing scope and protection-plan signature. Register overwrites create new value
versions. Arithmetic is never reassociated.

The additional ordered strategy supports GET_TABLE, GET_UPVALUE_TABLE,
GET_UPVALUE, GLOBAL_GET, MOVE, MOD, POW, DIV, FLOOR_DIV, LENGTH and LOGICAL_NOT,
as well as scalar arithmetic with unknown/metamethod-capable operands. These
regions replay the actual planned alias bodies and semantic routes, with every
original write retained. They do not cache operands across a possible user call.
May-call steps invalidate captured value versions and upvalue input observations
in the DAG itself, so later reads are not represented as stale dependency edges.

Candidates stay within one basic block and retain their exact contiguous source
order. Bounded subwindows can find a useful DAG beside an unrelated read/move;
no instruction is moved across an effect. VM CALL/TAIL_CALL/RETURN, closure
creation, vararg/top instructions and close/control boundaries still fall back.
Active captures no longer reject an entire numeric run: captured destination
writes are materialized, while unrelated captures do not prevent local execution.
Functions with open top ranges retain every candidate write; the top-changing
instructions themselves cannot enter a region.
Lua 5.1 floating-number facts and Lua 5.3 integer/float facts remain distinct.
Provenance-marked calculations are eligible only with all original writes kept.
Comparisons and control operations retain ordinary lowering. Strategy selection
uses the same facts/def-use/liveness analysis, not independent backend analyzers.

## Actual physical representation

Each admitted region gets a program-specific, collision-free 15-bit vop. Original
48-bit instruction words remain as operand and logical-event records. Only the
head vop changes; interior words are consumed inside the recipe, not independently
dispatched. Existing rolling word encoding and sparse graph/avalanche metadata
remain in use at execution time. Storage may use KVM3 below; runtime instruction
count and logical PCs remain unchanged.

Bindings are encoded in those existing operand words; the emitted sparse head
lookup and recipe bodies define their interpretation. Keeping the words preserves
original PC-based decoder, integrity, state and graph contracts. The standalone
prototype's compact binding encoding is not the production storage format.

KVM3 stores repeated A/B/C operand triples in a per-prototype dictionary.
Synthesized spans carry ULEB dictionary indices plus three bytes containing all
15 rolling opcode bits and seven randomized padding bits. Ordinary slots remain
six-byte words. A span directory and dictionary are sized from the actual legacy
serialized bytes; adjacent synthesized spans may share one storage block. The
reader restores every original bit before accumulator decoding and memory-key
masking. Graph/avalanche metadata, routes, constants, PC counts and MOV extension
data retain their original meaning. Integrity patching understands both versions.

Serialization first follows the legacy RNG/order and then rewrites storage without
consuming RNG. KVM3 is selected only when net blob savings exceed the complete added
reader source cost, including call sites. Small or poorly repeated inputs retain
the byte-identical KVM2 storage path. This is a storage optimization, not deletion
of logical protection events. Subsequent output-pass costs are outside that source
budget; final VM-only output sizes are measured separately.

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
  Proven pure scalar producers can additionally forward raw intermediate values
  through local variables or indexed local cells. Before each reuse, the consumer
  checks the shared mapping generation, register epoch and absence of a pending
  producer; a miss uses the original register helper. Generation is checked before
  dereferencing the cached epoch address. The value-returning helpers are derived
  from the existing arithmetic helpers and retain their encoded-linear fast path,
  graph routing, seals, writes and epoch updates. Deferred producers are not
  eagerly forced to obtain a raw value. Helpers with no usable local edge are not
  emitted. This bypasses some reads; it does **not** remove encoded materialization.
  Each four-field cache initializes separately: a 16-step region can forward 15 values,
  and banking one wide parallel nil assignment exceeds Lua 5.1's expression
  register limit. Proven scalar kernels also reuse the existing scratch-local
  reservation when mutation is disabled; ordered/userdata locals keep their
  lexical lifetimes. Mutation settings are not changed to obtain that fallback.
- **MOV:** the same region is lowered to scoped microcode. BEGIN/END boundaries
  bind the dynamic head to its program-specific recipe. Dead intermediate native
  values or encoded digit vectors live in frame-local temporary banks; live outputs
  use the original register representation. PREPARE/COMMIT guards, LOOKUP/SELECT
  arithmetic recipes and their original native fallback remain for unknown or
  floating numeric representations. Proven Lua 5.3 integer DAGs use a specialized
  PREPARE continuation: the two unreachable representation-guard/fallback records
  per step are removed while the encoded LOOKUP arithmetic remains. A runtime
  assertion and semantic/physical proof binding guard this direct path. The common
  recipe's explicit input/temporary references feed private SSA digit-value banks,
  caching external inputs and retaining distinct value versions across register
  overwrites. These kernels execute the discovered DAG through existing lookup
  primitives. VM/number domains own separate heads and each VM emits only its
  used synthesis bank; number-only scopes omit the integer-DAG helper. There is no
  replacement of MOV arithmetic with a generic Lua calculation kernel. Ordered
  mixed regions retain every store and every original HOST/lookup boundary;
  unknown results never gain a false integer proof.

New handler bodies receive the existing planned mutation machinery. Original alias
transitions remain specialized; semantically different alias-event contracts cannot
share a physical body merely because their numeric DAGs match. Fake handlers,
graph families, helper variants, state coupling, integrity and multi-VM options are
not disabled by synthesis. MOV's pre-existing unsupported options are still
reported by the capability system. MOV has no legacy physical pair-fusion/splitting
backend; those controls are explicitly marked unsupported there.

Handler-based emission distinguishes logical event aliases from executable
dispatch targets. Numeric operations wholly consumed by synthesis no longer need
their ordinary alias bodies or unused competing split/fuse/defer bodies. All
logical maps and transitions remain available to recipes. An operation still
executed elsewhere retains its planned aliases; split parts remain executable.
Planned fake handlers remain generated, with real/composite/synthesis IDs reserved
against collisions. MOV's number-only HOST fallbacks retain their ordinary bodies.

## Cost and sharing policies

All policies use identical semantic/protection gates. They differ in sharing and
admission, not correctness.

| Policy | Selection and sharing |
|---|---|
| Efficiency | Share equivalent DAGs/event contracts; require a loop region or repeated structural use to amortize generated code. |
| Balanced | Shared by default; additional execution forms and regional kernels consume measured remaining code capacity. |
| Protection | Region-specific definitions and independently seeded execution forms, even without speed/size savings, within explicit budgets. |

Default explicit-config limits are 6 steps, 32 recipe/physical-handler groups and
512 occurrences. Admission compiles the same renderer and planned mutation stream
used by final emission, comparing local-value and indexed-cell forms. Karity
also compares the original fully materialized kernel against guarded raw-value
forms; paying for guards is optional, rather than rejecting useful dispatch
synthesis when forwarding is too expensive. Complete helper-source costs are
conservatively reserved per physical kernel and shared in final emission. Compiler
instructions, source bytes, actual register-helper bodies, loop/repeated use,
head/binding overhead and retained graph/pending events are recorded separately.
MOV probes the actual target runtime additions and ULEB microcode cost; direct
integer continuations save two boundary records per step. Karity encoded writes
remain mandatory because their epochs/seals and lazy producers are protection
effects, not ordinary dead stores. Removing them is an invalid optimization under
the current contract. No policy assumes those effects disappear.

`synthesis_max_code_growth` is an additional kernel-source allowance relative to
the target loader, per VM (default 0.1, range 0–64). Efficiency uses half,
Balanced the full allowance and Protection twice it. This is not a promised final
file-size percentage. Zero rejects before physical forms are changed. Failed
physical admission cannot be reinstalled later, even on MOV's unsplit stream.
Hard per-handler compiler bounds remain independent of this configurable allowance.
Large handler banks retain their existing closure/scratch fallback.
Admission reserves the measured representative body for each planned alias/defer
specialization. Variant-specific transitions and final renaming can change actual
bytes; the emission profile records all actual bodies and applies the hard compiler
check to their combined instruction count. The admission allowance is an estimate,
not a hard final-output byte cap.

Balanced specialization no longer uses a fixed 25% RNG chance or quarter-recipe
cap. Different intermediate storage forms are selected reproducibly using private
plan entropy, and each regional mutation is measured and charged. Measurement
elapsed times never seed the dynamic ISA. Analysis/liveness is shared through
discovery and validation of the same immutable IR, including cached SCC sizes.
Admission compares the actual planned alias/split/fuse/defer bodies, including
their emitter-owned mutation seeds, with synthesized kernels. Only existing
planned Fusion pairs are alternatives; no fusion is invented or enabled by the
cost model. All selectable block variants remain intact on fallback. Efficiency
must beat the cheapest planned variant; Balanced/Protection can pay their explicit
diversity allowance. The old materialized-synthesis reference kernel is no longer
generated just to estimate ordinary execution. MOV separately charges the emitted
scope initialization/cleanup and mandatory integer proof, rather than equating
two deleted records with two free runtime operations. These compiler counts are
conservative proxies, not actual executed instruction counts through every branch.
Saved Classic helper work uses shortest compiler-CFG completion paths, so unused
captured-box branches cannot inflate the claimed saving. Head remapping work on
remaining ordinary instructions in the same loop SCC (or cold function) is also
charged and shared among admitted regions in that group. Budget/compiler
fallbacks remain ordinary sites: a bounded removal-only fixed point reprices the
remaining regions without regenerating kernels. SCC site counts approximate frequency; dynamic invocation counts remain
unknown. These adjustments are driven by actual paired VM comparisons rather
than an arbitrary fixed nanosecond multiplier.

Cost discovery also bounds distinct probed physical event signatures by the
existing recipe/handler-group limit, before expensive mutation/compilation. Failed
probes consume this deterministic budget; repeated signatures can reuse results.
`cost_probe_handler_budget` records source fallback explicitly. This avoids
unbounded exploration of combinations later rejected by physical admission;
it is not a wall-time deadline and does not alter any preceding protection pass.

The model accounts for code/compiled work and reports probe build time; it is not
a prediction of nanoseconds spent in every runtime branch. Runtime benchmarks
remain necessary to evaluate that tradeoff.

Admission and emission reuse exact rendered kernels, planned mutation and compiler
reports within one build. The generator's explicit injective key-renaming map
allows reuse across its later identifier spelling change; arbitrary source-pattern
equivalence is never assumed. Different recipes, forms, alias transitions, seeds
and target dialects keep distinct entries. Cached bodies are released after
emission, leaving reuse statistics in the profile. Fewer probes do not guarantee
lower total build time when storage/other stages add work.

Maximum settings are 16/256/4096. Admission includes physical
alias/defer specializations, not just semantic recipe count. These limits bound
handler generation; they are not a prediction that every admitted region is faster.

Costs separately report ordinary dispatches, the selected pair-fusion bodies,
recipe dispatches, register reads/writes, retained logical events, loop membership
and operand bytes. Actual emitted handler/head-table bytes are profiled separately.
The existing compiler cost probe measures each generated body. Large aggregate
handler sets use private per-frame closure banks once they exceed a quarter of
Lua's 131071-instruction signed jump range. Large mutated bodies reuse the existing
scratch compactor to reserve three quarters of Lua's 200-local limit for the
enclosing executor. Neither adjustment disables mutation or arithmetic events.
Karity materialized mode reports no register-access saving. MOV reports microcode
cost separately: its scope instructions can increase microdispatch count.

The four built-in user presets enable synthesis independently of the backend:

| Preset | Policy | Steps | Recipe groups | Occurrences | Code allowance |
|---|---|---:|---:|---:|---:|
| Fast | Efficiency | 4 | 8 | 128 | 0.4 × 0.5 |
| Balanced | Balanced | 6 | 16 | 256 | 0.6 |
| Strong | Protection | 8 | 24 | 512 | 0.8 × 2 |
| Maximum | Protection | 10 | 32 | 512 | 1.0 × 2 |

VM-only trials with the actual protected presets showed that allowances below
0.2 often rejected the first mutated kernel. These larger allowances admit the
numeric loop and multi-function fixtures while retaining mutation and encoded
events; measured final output overhead is recorded in the preset report. An
enabled feature still requires a safe numeric region: earlier IR morphing can
replace a candidate with operations outside the current recipe scope.

Legacy/project profiles and saved custom configurations retain their explicit
settings. Generic configuration remains opt-in for compatibility. Built-in preset
revision 3 carries the new defaults; backend selection is still independent.
Loading/initialization and encoded/pending state can limit execution savings.
Higher diversity is not proof of greater security, and lower dispatch counts are
not proof of lower total runtime. Protection admission intentionally permits a
bounded size/time cost for a less uniform ISA.

## Controls and diagnostics

Use GUI advanced settings **Opcode synthesis** or JSON `vm_options`:

```json
{
  "opcode_synthesis": true,
  "synthesis_policy": "balanced",
  "synthesis_max_steps": 6,
  "synthesis_max_recipes": 32,
  "synthesis_max_occurrences": 512,
  "synthesis_max_code_growth": 0.1
}
```

CLI supports `--opcode-synthesis`, `--synthesis-policy efficiency|balanced|protection`
and the existing `--vm-option KEY=VALUE`. Policy alone does not enable the feature.
`--dump-synthesis-plan PATH` emits recipes, bindings, source IDs and structural
costs; `--dump-backend-ir PATH` adds actual dynamic opcodes and physical spans.
The profile includes discovery rejection counts, physical fallback diagnostics,
clone/handler counts and emitted handler size. GUI result inspection shows the
selected summary and the existing expandable profile, including policy reason,
execution form, compiler/code budgets, exact binding alternatives and fallback.
Backend/Lua choices and saved custom
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
Real protected Karity route/state event traces are compared before/after synthesis
on both Lua targets. MOV integer continuation/proof corruption and zero-budget
unchanged operand/physical forms are also covered.
KVM3 regression coverage includes 100 randomized layouts, exact padding/word
restoration, both native readers, malformed dictionaries/spans/indices, nested
prototypes, unchanged RNG consumption, format-aware integrity patching and actual
compressed VM outputs on all three backends. Additional tests cover mixed numeric/
bit DAGs, negative and at-least-64 shift counts, overflow, integral-float and
metamethod fallback, and actual Fusion-versus-synthesis cost decisions. They retain ordinary
numeric handlers outside synthesized spans and verify real kernel cache hits.

`run_synthesis_dag_regression.py` exercises actual ordered mixed regions on all
three backends and both Lua targets, with bare and protected/multi-VM settings.
It covers captured owner writes, unrelated captures, callback clobbers, open
multiple-return tails, false/nil indexing, further arithmetic, table/upvalue
reads, metamethod ordering/errors and Lua 5.3 metamethod yield/resume. Both raw
temporary forms receive independent execution tests, stale epoch/mapping/pending
guards are exercised, and actual Karity reads decrease while write counts and
logical route/state traces are preserved. Direct VM calls, top/control changes,
cross-block candidates and arbitrary instruction motion remain outside the
supported recipe vocabulary. The original broad roadmap is not claimed complete.
