# Karity Extended Syntax (KES)

For a concise introduction with examples, see the [KES syntax quick guide](kes-guide.md) ([한국어](kes-guide.ko.md)).

KES is enabled automatically in `Pipeline`, the CLI, GUI builds, and GUI source execution. It runs before protection markers, macros and source passes. It also works without a VM pass. Direct VM builds accept KES too. String literals, long strings and comments are lexed as opaque text. Inputs without extensions retain their original source text at this stage.

## Assignment and evaluation order

```lua
total += amount
total -= discount
total *= rate
total /= count
total %= modulus
total ^= exponent -- Lua exponentiation
text ..= suffix
total //= divisor -- Lua 5.3 only
config.timeout ??= 30
```

For a table target, evaluation order is **receiver, key, old value, right operand, write**. Each is evaluated once. `__index`, arithmetic metamethods and `__newindex` follow that order. For `??=`, the right operand and write occur only when the old value is nil. A false old value is retained.

Lua 5.1 rejects `//=` at build time. It is not approximated using floating-point division and `math.floor`.

## Lazy, single-result expressions

```lua
local name = input ?? "Guest"
local profile = user?.profile?.name
local result = score >= 50 ? "PASS" : "FAIL"
```

`??` evaluates its left side once and evaluates its right side only for nil. False, zero and NaN are retained. `?.field` checks only for nil: indexing false, numbers and other unsupported receivers still raises the usual Lua error. Each optional field access evaluates its receiver once. Optional calls, method calls and bracket indexing are not introduced by this release; ordinary calls/indexing after an optional expression retain ordinary Lua errors.

Ternary evaluates only the selected arm and preserves false/nil. All three new expression forms produce exactly **one** result, even in the last argument of a call or a return list. Ordinary Lua calls/varargs outside these forms retain their usual multiple-result behavior. Free varargs are forwarded into the generated lexical function; no global helper or fallback API is installed. Additional Lua frames/allocation are observable through debug/GC APIs; stack identity, allocation counts and exact collection timing are not compatibility promises.

New precedence, weakest first:

| Operator | Association |
|---|---|
| `condition ? yes : no` | Right |
| `??` | Right |
| `or` | Left |
| `and` | Left |
| Existing Lua comparisons, bitwise, concat, arithmetic, unary and power | Existing Lua precedence |
| Field/index/call and `?.field` | Postfix |

Thus `a or b ?? c` means `(a or b) ?? c`; `a ?? b or c` means `a ?? (b or c)`. `a ? b : c ? d : e` means `a ? b : (c ? d : e)`.

Lua method calls also use a colon. In a ternary true arm a colon adjacent to whitespace is the ternary separator; parenthesize a spaced method call, for example `ok ? (obj : method()) : fallback()`. Write `ok ? obj:method() : other:method()` with spacing around the separator. In an entirely unspaced ambiguous method chain the final top-level colon separates the arms. Parentheses make the intended grouping explicit.

## Continue

Numeric/generic `for`, `while`, `repeat` and nested loops support `continue`. It targets the nearest loop in the current function. Break exits the source loop; return exits the source function. No goto is introduced, including on Lua 5.1.

Existing variables/functions named `continue` remain valid, including Lua's parenthesized, string and table call syntax. A bare `continue` statement performs loop control.

```lua
for i = 1, 10 do
    if i % 2 == 0 then continue end
    print(i)
end
```

In `repeat`, continue still evaluates the until condition. Body locals visible to that condition have fresh bindings each iteration. If continue skips such a declaration, its value in the condition is nil. Initializers use their original lexical bindings; closures keep the corresponding iteration's upvalues.

```lua
repeat
    step += 1
    if step < 3 then continue end
    local finished = true
until finished -- nil on skipped iterations, true on the third
```

## Numeric literals

```lua
local binary = 0b1010_1010
local large = 1_000_000
local hex = 0xFF_FF
```

Separators must sit between digits of the relevant base (or decimal exponent digits). Leading, trailing, doubled and exponent-adjacent separators are rejected. Binary literals are unsigned bit patterns up to 64 bits and lower to hexadecimal Lua literals. Lua 5.3 interprets them using its native signed 64-bit integer rules; Lua 5.1 uses its native floating-point rules and may round large values. Decimal/hexadecimal normalization also retains the target Lua parser's numeric model. NumberObf receives ordinary Lua numeric literals.

## VM intrinsic APIs

These reserved identifiers permit direct calls only. Storing, aliasing, shadowing, assigning, declaring parameters with these names, or using them as named fields is rejected. A string/table key with the same spelling is ordinary data. The compiler marks parsed bare calls privately before bytecode compilation; it never recognizes a coincidentally named table lookup as an intrinsic.

| API | Result and physical operation |
|---|---|
| `KARITY_GET_SCRIPT_HASH()` | Unsigned 32-bit runtime integrity value, `GET_SCRIPT_HASH` |
| `KARITY_GET_VM_COUNT()` | Configured/effective runtime VM count, `GET_VM_COUNT` |
| `KARITY_GET_VM_ID()` | Zero-based physical VM ID of the current function, `GET_VM_ID` |
| `KARITY_GET_LAYOUT_HASH()` | Unsigned 32-bit instruction encoding layout hash, `GET_LAYOUT` |
| `KARITY_GET_CODE_LENGTH()` | Current function's physical handler instruction count modulo 2^32, `GET_CODE_LENGTH` |

All getters take zero arguments and return one value through a real VM instruction. They are not substituted with numeric literals. VM count/ID refer to the enclosing emitted runtime; separately emitted selective runtimes have their own counts/IDs. Layout hash describes instruction field layout, not the source AST or full control-flow graph. Code length includes physical protection/layout expansion; on MOV it counts the serialized host instruction slots, **not** MOV microinstructions.

Script hash is the existing integrity CRC derived from the finalized runtime function dump and line state. It is not a source-file checksum, stable build identifier, cryptographic digest or secret. All these values can change with target, seed, protection options, output transforms or runtime generation. `GET_SEED`, routing and internal state mutation operations are not public APIs.

| API | Contract |
|---|---|
| `KARITY_ABORT()` | Raise a generic error for this execution |
| `KARITY_ASSERT(condition)` | Evaluate one adjusted condition once; abort for nil/false, otherwise return zero values |
| `KARITY_UNREACHABLE()` | Same failure behavior as Abort |
| `KARITY_PANIC()` | Poison this runtime instance and raise a generic error |

Abort does not poison the instance: an external `pcall`/`xpcall` can catch it, and other calls can continue. Panic poisons every physical VM sharing the enclosing emitted runtime, including returned closures and suspended coroutines. Interpreter dispatch and return boundaries refuse further execution, even if a nested native `pcall` catches the original error. It does not kill the host, corrupt arbitrary memory, intentionally hang, prevent host error catching, or prevent loading an independent runtime. Equal-option selective regions that share one emitted runtime share its poison state; separately emitted runtimes do not.

An intrinsic must lie in an actual VM execution region. It never enables VM automatically. Builds reject native-only output, `NO_VM`/`NO_OBF` exclusions, unselected marked-mode source, wrong arity and unsupported uses. Convenience syntax still lowers inside native exclusions. GUI source execution rejects intrinsics and supports convenience syntax.

## Support matrix and diagnostics

| Feature | Lua 5.1 | Lua 5.3 |
|---|---|---|
| Convenience syntax except `//=` | Yes | Yes |
| `//=` | Build error | Native floor division |
| All nine intrinsics, Classic/Karity/MOV | Yes | Yes |
| Whole-file VM / `--@VM` | Yes | Yes |
| Partial VM/native boundaries | Existing unsupported-target error | Yes |
| Packer | Existing unsupported-target error | Yes |

Existing pass capability restrictions remain in force (for example, source NumberObf/StringObf on Lua 5.1). KES does not disable protections or translate unsupported passes into native fallbacks. No syntax is added for `++`, `!=`, `^^=`, const/defer/is; `--` remains a Lua comment.

Frontend errors report original Unicode line/column positions. `lower_source` returns a `LoweringResult` containing source ranges and `original_offset()` for integrations that need generated-to-original positions. Unchanged text maps exactly; generated expansions are anchored to the original statement range, with exact common prefixes/suffixes. Mapping is linear in the emitted text and does not diff large repetitive sources quadratically. This map describes the KES stage; subsequent source/output passes have their own coordinate changes. The GUI highlights KES tokens and shows frontend errors in the source gutter and diagnostic strip.

Run `python test/run_kes_regression.py` and `python test/run_kes_integration_regression.py`. Both are included in `python test/run_ci.py`. Syntax tests use native oracles and explicit effect/arity assertions; intrinsic tests compare actual serialized state and failure/re-entry contracts rather than pretending an intrinsic has native Lua semantics.

See [KES cost measurements](performance/kes.md) for frontend, output-size and execution comparisons, reproduction, and the substantial startup cost possible when applying CFF to both the VM and the Packer loader.
