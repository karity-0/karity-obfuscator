# Function merging

The source `function_obf` pass can put multiple original function bodies in one
shared control-flow dispatcher. This is separate from inlining, splitting one
function into helpers, and VM instruction fusion.

`merge` defaults to `true` while source CFF is enabled. `merge_max_functions`
defaults to `4` (range `2..8`), and `merge_max_groups` to `64` (range `0..256`).
Explicit `merge=false` or a zero group budget preserves individual processing.
The existing safe chunk inliner runs first. VM-output dispatcher protection does
not merge generated runtime functions.

## Execution

Eligible adjacent sibling `local function` declarations retain small, distinct
callable wrappers at their declaration sites. A wrapper tail-enters the common
worker with a generated entry tag and its fixed parameters. The actual original
bodies share one shuffled CFF block bank; there is no bank of old body closures
called by a multiplexer. Each worker invocation has its own parameters and local
cells, including recursion, callbacks and interleaved coroutines.

Fixed argument binding, ignored extra arguments, missing arguments, bare returns,
multiple return values and trailing nils use ordinary Lua call/return semantics.
No argument/result packing dependency is introduced. Escaped wrappers remain
distinct function objects on Lua 5.3, and returned nested closures retain their
own invocation's cells. Source descendants are processed once; generated workers
and CFF helpers do not become new recursive source candidates.

## Eligibility and lifetime

All members need the same external lexical capture set. A persistent worker must
not make one escaped wrapper retain another member's guest objects or function
references. This also means that unrelated self-recursive functions generally
stay separate; recursive groups whose actual capture sets match can merge.
Invocation-local table pooling is prohibited for merged workers. The common
dispatcher uses compact affine CFF with independent local cells, and measured
compiler limits bound group admission.

Functions must be adjacent declarations in the same lexical block. Moving their
bodies after the declarations must preserve binding visibility: an earlier
global/outer reference cannot become a later sibling's local binding. Different
selection policies and nested protection boundaries prevent grouping. `_ENV`
rebinding, vararg owners, goto/labels and empty bodies are excluded. Anonymous
assignments, global declarations and methods retain their existing processing.
Nested vararg closures inside an eligible fixed-argument owner remain supported.

Lua 5.1 groups additionally require direct-call-only references and exclude
environment/reflection-sensitive bodies. Functions exposed to `setfenv`, passed as
values or otherwise requiring independent function environments stay unmerged.
As with CFF generally, reflective debug frames/prototypes/upvalue numbering are
not a stable source interface.

Excluded groups and compiler/capture-layout fallbacks retain the existing
individual function protection. `function_merge` profiling reports selected
members, entry tags, actual CFF block counts, compiler costs and exclusion or
fallback reasons. `last_merge_group_count` and `last_merged_function_count` count
successfully emitted groups and original functions, respectively.

## Verification

`test/run_function_merge_regression.py` compares real Lua 5.1/5.3 executions and
checks common worker structure, distinct wrappers, lexical visibility, mutable
captures, recursive/reentrant invocations, coroutine suspension, error behavior,
nil tails, closure/function collection, selection, bounds and disabled paths.
Native source, VM and packer compositions are covered separately. Existing
function boundary, loop, nested, compiler-cost and Lua-version regressions remain
part of the function protection checks.
