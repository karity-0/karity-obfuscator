# Selective obfuscation

Source macros and directives select protection at build time. They do not call
runtime functions. Unannotated input and existing flat/profile configurations
retain their existing behavior.

## Configuration and precedence

`selection_modes` selects `all` or `marked` independently for `string_obf`,
`number_obf`, `boolean_obf`, `table_obf`, `function_obf`, and `vm`.

```json
{
  "passes": ["string_obf", "number_obf", "boolean_obf", "table_obf", "function_obf", "vm"],
  "selection_modes": {
    "string_obf": "marked",
    "number_obf": "marked",
    "boolean_obf": "marked",
    "table_obf": "marked",
    "function_obf": "marked",
    "vm": "marked"
  },
  "vm_options": {"backend": "karity"},
  "vm_output_passes": ["rename_obf", "minify"]
}
```

A listed pass defaults to `all`. In `marked` mode only selected locations run
through that pass. A macro/directive can also enable an absent pass; that pass
defaults to `marked` unless `selection_modes` explicitly says otherwise.
File-level `@VM` overrides `marked` and selects the whole chunk.

Configuration supplies default options. Enclosing selections supply overrides;
inner selections override individual supplied keys. Exclusions take precedence:
`NO_VM` excludes VM execution while allowing source passes, and `NO_OBF` excludes
source transformations and VM execution. Packaging still transports the final
script, including excluded code.
Direct `Pipeline` users inherit function selection defaults from their configured
`FunctionObfuscationPass` instance, including disabled features and nesting limits.

## Literal macros

```lua
local message = STRING_OBF("secret")
local limit = NUMBER_OBF(-123)
local enabled = BOOLEAN_OBF(true)
local data = TABLE_OBF({1, 2, 3, name="literal"})
```

Each macro takes exactly one parenthesized argument. Strings include Lua long
strings. Numbers support literals and unary-negative literals; booleans require
`true` or `false`; tables require a constructor. Runtime expressions such as
`NUMBER_OBF(getValue())` are rejected. The macro names are reserved global names;
declaring an identity function with one of these names is rejected.

`TABLE_OBF` selects the table constructor transformation. It does not implicitly
enable string, number or boolean protection. Select those values separately:

```lua
local data = TABLE_OBF({name=STRING_OBF("secret"), count=NUMBER_OBF(12)})
```

Literal macros run before enclosing function transformations. When a table has
selected inner literal macros, those run first. Existing table eligibility
checks remain in force: generated calls such as `string.char(...)`, source
calls, index operations, or multiple-result fields can prevent the table rewrite.
In that case inner literal protection still applies and the table is reported as
skipped. Field ranges inside a constructor are not a supported table syntax.

## Function protection

Put an annotation immediately before a function declaration or a single local
assignment to an anonymous function:

```lua
-- @FUNCTION_OBF(cff, wrapper, junk=false, nested=false)
local function check(value)
    local result = value + 1
    if result > 10 then result = result * 2 end
    return result
end
```

Both `-- @DIRECTIVE` and bare `@DIRECTIVE` are accepted. Comment directives keep
the source valid for Lua editors. Bare directives are removed before parsing.
Directives occupy their own physical lines. Marker text inside strings, ordinary
comments and long comments has no effect. Trailing Lua comments are accepted.

Supported feature flags are `cff`, `junk`, `inline`, `wrapper`, `split`,
`loop_split` and `loop_unroll`. A positional feature list explicitly selects
those features and disables the other features in that list. `split` enables CFF
with `boundary_mode="split"`. Keyword-only options inherit configuration defaults.
Every existing `function_obf_options` key is also accepted, including nesting and
loop growth budgets. `inline` and loop transforms are components of the CFF
rewrite; they do not run independently when `cff=false`. `junk` and `wrapper`
can be used without CFF. All four new configuration switches (`cff`, `junk`,
`inline`, `wrapper`) default to `true`, preserving existing behavior.

The paired form can select the complete containing function body:

```lua
local function check(value)
    @FUNCTION_OBF_START(cff, junk)
    local result = value + 1
    if result > 10 then result = result * 2 end
    return result
    @FUNCTION_OBF_END
end
```

It can also select part of a function body, including statements inside a loop:

```lua
local function check(value, ...)
    local fast = value + 1
    -- @FUNCTION_OBF_START(cff, junk=false)
    local result = fast * 3
    if result > 10 then return result, ... end
    -- @FUNCTION_OBF_END
    return result
end
```

Partial regions run through a local helper; unselected statements and the
original parameter list remain in place. Locals declared in the region remain
available afterward with their original shadowing and shared closure behavior.
Partial regions inherit enclosing function options before applying their own
overrides. A region with every executable feature disabled emits no helper and
remains a boundary for an enclosing `all` rewrite.
Escaping `return`, multiple results (including trailing nil), varargs, and a
`break` targeting an enclosing loop are transported back to the caller.
Partial source regions support Lua 5.1 and 5.3. Whole-function varargs,
goto/labels, empty bodies and existing eligibility/growth checks can still cause
a requested rewrite to be skipped. An explicit nested target is processed while its enclosing function's
structural rewrite is skipped to preserve that target's provenance. Nested
functions otherwise follow `nested` and `nested_max_depth`.

## VM boundaries

```lua
local counter = 0

-- @VM_START(profile="fast-vm", junk_rate=0.05)
local function protected(amount)
    counter = counter + amount
    return counter
end
-- @VM_END

local function hot_path()
    counter = counter + 1
end
```

VM regions can contain complete function declarations, assignments to anonymous
functions, or arbitrary complete sibling statements in one Lua block:

```lua
local total = 0
for i = 1, 100 do
    -- @VM_START(profile="fast-vm")
    local increment = i * 2
    total = total + increment
    if total > 500 then break end
    -- @VM_END
end
print(total)
```

Regions may appear at chunk scope or inside functions, branches and loops. A
region cannot cut through an expression, declaration, branch or loop boundary.
Outer locals are shared through live getter/setter cells, preserving reads,
writes, recursion and shared closure state across native/VM calls. Locals
declared by selected statements keep their initializer visibility and remain
available to later statements. Escaping return/break, methods, varargs, multiple
results and environment reassignment are covered by regression tests. Selective
VM boundaries require Lua 5.3 and support Karity, classic and MOV.
In `marked` mode, fully excluded VM selections emit no runtime and do not require
VM boundary support from the target. Exclusion-only selections are also reported
when a VM pass is configured in `marked` mode.
Embedded runtimes qualify global accesses before integrity binding, so source
locals named `string`, `type`, or other standard APIs cannot capture VM internals.
Bridge support APIs are captured at initialization, so selected code can run
inside a minimal custom lexical `_ENV` without supplying those APIs itself.

VM options accept the existing `vm_options` keys. `profile` takes a named profile
from the input configuration; flat configurations can declare
`selection_profiles: {"fast-vm": {"vm_options": {...}}}`. A selection profile
supplies VM options only, not source passes, output passes or a different target.
Inner selections inherit supplied parent options. Identical effective options
share the enclosing domain. Independent selected regions with the same effective
options are compiled together and share one runtime initialization; each region
still has its own live capture bridge. Explicit default values and backend aliases
are normalized before grouping. Different effective options/backends use separate
runtimes. This also preserves mutual recursion, shared locals and interleaved
coroutines across selected regions. `vm_count` still controls the backend's own
internal VM distribution within each shared runtime.

File-level whole VM execution and native exclusions:

```lua
-- @VM
local counter = 0

-- @NO_VM
local function hot_path()
    counter = counter + 1
end

local function protected()
    hot_path()
    return counter
end
print(protected())
```

`@VM` must precede Lua code; leading comments and blank lines are allowed. It
can accept VM options, for example `@VM(profile="fast-vm")`. `@NO_VM` selects
the immediately following function. `@NO_VM_START` / `@NO_VM_END` select complete
sibling statements, including part of a selected VM function:

```lua
-- @VM
local total = 0
-- @NO_VM_START
for i = 1, 10000 do total = total + i end
-- @NO_VM_END
print(total)
```

A host factory bank holds native exclusions and independently configured VM
domains. Nested native exclusions work both in whole-chunk mode and inside
independently selected VM regions/functions. Exclusions remain stronger than
inner VM selections. Whole VM execution without selective boundaries continues
to support existing targets.

Generated VM output is emitted at its final line position and is not rewritten
after integrity binding. Use `vm_output_passes` for output minification. In a
configuration that already enables `vm`, choose `selection_modes.vm="marked"`
to make `VM_START` / `VM_END` selective; otherwise the surrounding chunk retains
the configured whole-script VM behavior.

## Exclusions and reports

```lua
-- @NO_OBF_START
local readable = "leave this alone"
-- @NO_OBF_END
```

Source-only `NO_OBF` regions can contain complete statements in one Lua block.
When the chunk is virtualized, excluded statements execute through native
factories with live access to the VM's lexical state.
Renaming preserves every binding referenced by excluded code, including its
references elsewhere. `strip_info` and the whole-script `anti_debug` pre-pass are
conservatively skipped if any `NO_OBF` region exists, with a report entry.
Comment removal and source minification preserve excluded text. An enclosing
function rewrite is skipped when it would cross an exclusion or explicit nested
selection; eligible sibling/nested functions can still be transformed.

```bash
python main.py examples/selective.lua -o examples/selective.protected.lua -c config.selective.example.json --seed 1234 --selection-report selections.json
```

The checked-in [source](../examples/selective.lua) and
[protected output](../examples/selective.protected.lua) show the selected regions
and the preserved `NO_OBF` block side by side.

`--selection-report -` prints JSON; `pipeline.last_selection_report` provides the
same entries to API/GUI callers. Entries include the original source line,
feature, status (`applied`, `partial`, `excluded`, `skipped`) and a reason where
appropriate. Reports describe transformations rather than promising every
eligible literal will change: empty strings, numeric fallbacks and safety checks
can retain the original expression. Unknown options, mismatched markers,
cross-block regions, invalid macro arguments and unsupported VM boundaries fail
before writing the output file.

`goto` may stay entirely inside a VM region, but jumps into or out of a
protection region are rejected with the directive's original source line.
Source CFF retains its existing goto/label eligibility restriction. Regions
must contain at least one statement. A partial source region that contains an
explicit nested protection target is skipped to preserve that target; its
report explains the boundary constraint. It also skips a rewrite that would
rename an exported binding referenced by `NO_OBF` code.

Existing IR dump flags write the last emitted VM unit when a build contains
multiple VM runtime groups. Pass profiling aggregates their stages.

Verification: `python test/run_selection_regression.py`, also registered in
`test/run_ci.py`. Runtime comparisons use the original Lua after marker/macro
lowering, not an emulated identity implementation.
