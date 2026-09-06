# Function obfuscation

`function_obf` transforms source function boundaries and eligible nested bodies.
It can introduce vararg wrappers, helper closures, safe helper inlining,
state-machine control flow and junk blocks. Compound-loop transforms can split,
unroll or lower eligible loops within configured growth limits. These are source
rewrites, separate from VM opcode/handler mutation.

## Configuration and order

Add `function_obf` to `passes`, `vm_output_passes` or `packer_output_passes`.
Use the [configuration reference](../configuration.md#function_obf) for
`function_obf_options` and compound-loop budgets. The output contexts deliberately
have stricter growth behavior than source transforms. Prefer existing profiles
before increasing rates on already expanded runtime code.

## Scope and fallback behavior

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

## Verification and implementation

`test/run_function_boundary_regression.py`, `test/run_function_loop_regression.py`
and `test/run_function_nested_regression.py` exercise boundary, control-flow and
recursive processing cases and are included in `python test/run_ci.py`.
Implementation: [function_obfuscation.py](../../obfuscator/passes/function_obfuscation.py).
