# Function obfuscation

`function_obf` transforms source function boundaries and eligible nested bodies.
It can introduce vararg wrappers, helper closures, safe helper inlining,
state-machine control flow and junk blocks. Compound-loop transforms can split,
unroll or lower eligible loops within configured growth limits. These are source
rewrites, separate from VM opcode/handler mutation.

Generated protection uses Lua 5.1/5.3-common arithmetic: affine encoded states,
signed relative transitions, and bounded parity predicates. CFF, helper splits,
nested processing, loop transforms and live/dead junk remain enabled under the
same eligibility and growth rules. No `math.type`, bit library, or int64 shim is
injected. Only generated bounded integers receive arithmetic predicates; arbitrary
source parameters (including NaN, infinities and objects) do not. Source expressions
are preserved, so input syntax must already match the target. Luau is not a
validated target. VM output protection is supported on Lua 5.1 too; the VM's dump
integrity still requires runtime-specific compatibility.

## Configuration and order

Add `function_obf` to `passes`, `vm_output_passes` or `packer_output_passes`.
Use the [configuration reference](../configuration.md#function_obf) for
`function_obf_options` and compound-loop budgets. The output contexts deliberately
have stricter growth behavior than source transforms. Prefer existing profiles
before increasing rates on already expanded runtime code.

## Scope and fallback behavior

Compiler costs govern large dispatchers independently of the requested style.
Lua 5.1 and 5.3 both encode signed jump distances with a maximum magnitude of
131071 ([5.1 opcode layout](https://www.lua.org/source/5.1/lopcodes.h.html),
[5.3 jump validation](https://www.lua.org/source/5.3/lcode.c.html)). The default
jump budget reserves three quarters of that range for local pooling and later
literal passes. Source literals additionally reserve 150 instructions each:
NumberObf's eight float-chain terms/seven binary-tree nodes, MemeStrings' two
arithmetic levels, and load/temporary overhead. Actual prototypes are compiled
again after pooling. Diagnostics report the prototype, largest jump PC and line.

An unsafe flat/nested dispatcher becomes a cost-balanced helper bank, without
the old three-helper ceiling. A state-to-helper route table calls one helper per
iteration. Return-containing blocks stay in the owner function, preserving nils
and multiple results; helpers share the existing lexical cells. Table pooling
also accounts for Lua 5.1's 60-upvalue limit. A singleton helper omits its case
guard because the route table already establishes its state.

Function and pass budgets can select shared-decode CFF and smaller live-junk and
dead-state banks. This adjustment retains every selected real block and edge;
profiling reports reduced junk density. An impossible budget fails explicitly
after one compact retry. Compound-loop byte/block budgets still apply and record
their existing fallback counters. Source varargs/goto eligibility is unchanged.

CFF numeric expressions now use the extracted NumberExpressionEngine with a
bounded, exact arithmetic policy for hot transitions. Registered origin spans
survive source edits and structured VM literal emission; subsequent NumberObf
and MemeStrings skip these expressions. Private transport comments are removed
before output and do not form a public annotation or numeric pattern matcher.
Original literals retain the full NumberObf engine.
The jump/function and generated-number budgets may be overridden by function
directives; `max_pass_instructions` belongs only in global `function_obf_options`.
StringObf reconstruction statements remain eligible CFF source, in the same
StringObf → FunctionObf order.
Registered StringObf spans allow grouping up to four consecutive reconstruction
statements by default. Only single-predecessor straight-line CFG chains merge;
branches, joins and returns remain boundaries. Every operation still executes in
CFF and in dependency order, with many reconstruction states per string.
`reconstruction_group_size=1` restores the previous one-statement granularity;
values up to eight are supported. Profiles record both original blocks and
coalesced states so reduced state granularity is explicit.

The high/max defaults use StripInfo, RenameObf and Minify for VM/packer output.
Explicit heavy output pass lists still work. VM handler, state and dispatcher
protection settings are independent and remain enabled.

Eligibility checks protect lexical scope, captured locals, loop control and
return behavior. A transformation may be skipped when goto/labels, varargs,
unsafe boundaries or growth budgets prevent a safe rewrite. Skipping one rewrite
does not mean the whole function is unprotected. Generated helper bodies are not
recursively expanded without bound. No configuration promises that every source
function or loop will be rewritten.

Closures/upvalues, early returns, tail calls, multiple returns, breaks and nested
loops are semantic constraints, not interchangeable syntax. Validate application
behavior when changing transformation rates. Added helpers and state machines
can increase output size and runtime overhead; `max` has no size/time target.
VM output protection is optional and can expand already-generated helpers
substantially. Enabling source `function_obf` does not require enabling it a
second time in `vm_output_passes`; benchmark that extra layer on your workload.

## Verification and implementation

`test/run_function_boundary_regression.py`, `test/run_function_loop_regression.py`
and `test/run_function_nested_regression.py` exercise boundary, control-flow and
recursive processing cases and are included in `python test/run_ci.py`.
`test/run_function_lua51_regression.py` additionally executes native Lua 5.1/5.3
differential cases, and the Lua 5.1 pass matrix checks generated VM output.
`test/run_function_cost_regression.py` exercises large dispatcher splits,
numeric origins, coroutine/error behavior and CFF-protected string macros.
`tools/profile_cff.py INPUT --profile high --output REPORT.json` records per-pass
sizes/times and native prototype costs. Full VM timing uses `main.py --profile-report`.
Implementation: [function_obfuscation.py](../../obfuscator/passes/function_obfuscation.py).
