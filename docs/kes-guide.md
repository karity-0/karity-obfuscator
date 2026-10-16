# KES syntax guide

[**English**](kes-guide.md) | [한국어](kes-guide.ko.md)

**KES (Karity Extended Syntax)** adds convenient syntax to Lua. It is enabled automatically: Karity converts it to standard Lua before processing. You can also use it with **Run Source (F5)** in the GUI.

[README](../README.md) · [Full reference](kes.md) · [Performance measurements](performance/kes.md)

## At a glance

```lua
local player = nil
local name = player?.profile?.name ?? "Guest"

local total = 0
for i = 1, 5 do
    if i % 2 == 0 then continue end
    total += i
end

local result = total >= 9 ? "PASS" : "FAIL"
print(name, total, result) -- Guest  9  PASS
```

## Compound assignment

| KES | Meaning |
|---|---|
| `a += b` | `a = a + b` |
| `a -= b` | `a = a - b` |
| `a *= b` | `a = a * b` |
| `a /= b` | `a = a / b` |
| `a %= b` | `a = a % b` |
| `a ^= b` | `a = a ^ b` — exponentiation |
| `a ..= b` | `a = a .. b` — string concatenation |
| `a //= b` | `a = a // b` — floor division, Lua 5.3 only |

Table targets work too. In `items[getIndex()] += 1`, `getIndex()` runs once. Evaluation order is **table → key → old value → right operand → assignment**.

## Nil handling and conditional expressions

| Syntax | Behavior |
|---|---|
| `value ?? fallback` | Use `fallback` only when `value` is nil |
| `config.timeout ??= 30` | Assign only when the current value is nil |
| `user?.profile?.name` | Each `?.` produces nil when its receiver is nil |
| `condition ? yes : no` | Choose `yes` for a truthy condition, otherwise `no` |

```lua
local enabled = false ?? true       -- keeps false
local count = 0 ?? 10               -- keeps 0
local name = nil ?? "Guest"         -- "Guest"
local result = true ? false : "no"  -- keeps false
```

Only a needed right operand or the selected branch runs. `?.` handles nil only: `false?.name` raises an ordinary Lua indexing error. Optional calls, methods and `?.[key]` syntax are not supported.

Precedence, from lowest to highest: **ternary → `??` → `or` → `and` → existing Lua operators**. Ternary and `??` associate to the right. Parentheses make mixed expressions easier to read.

Use spaces around the ternary `:`: `ok ? obj:read() : fallback()`. Each `??`, `?.` and ternary expression returns exactly **one value**.

## Continue

`continue` skips the rest of the current iteration. It works in `for`, `while`, `repeat` and nested loops, targeting the nearest loop.

```lua
for i = 1, 5 do
    if i % 2 == 0 then continue end
    print(i) -- 1, 3, 5
end
```

In a `repeat` loop, `continue` still evaluates the `until` condition. A local declaration skipped by continue has a nil value in that condition. `break` and `return` retain their usual meanings.

## Numeric literals

```lua
local flags = 0b1010_1010 -- 170
local budget = 1_000_000  -- 1000000
local mask = 0xFF_FF      -- 65535
```

Place `_` between digits only. `1__000`, `1_` and `0x_FF` are errors. Large-number precision and integer behavior follow the selected Lua version.

## VM-only APIs

These APIs require code that **actually executes inside a VM**. Unlike ordinary KES syntax, they cannot run with the GUI's Run Source (F5). Enable the VM in your settings or use [selection markers](selective-obfuscation.md) to select a VM region.

| Call | Behavior |
|---|---|
| `KARITY_GET_SCRIPT_HASH()` | Runtime integrity value, not a source-file hash |
| `KARITY_GET_VM_COUNT()` | Number of VMs in the current runtime |
| `KARITY_GET_VM_ID()` | Zero-based VM ID for the current function |
| `KARITY_GET_LAYOUT_HASH()` | Instruction encoding layout hash |
| `KARITY_GET_CODE_LENGTH()` | Physical VM instruction count of the current function |
| `KARITY_ABORT()` | Stop the current execution with an error |
| `KARITY_ASSERT(condition)` | Abort if the condition is nil or false |
| `KARITY_UNREACHABLE()` | Always abort when reached |
| `KARITY_PANIC()` | Invalidate the shared runtime instance and stop |

After catching **Abort**, other calls can continue. **Panic** prevents reuse of the same runtime even if its error is caught, including its other VMs, returned closures and coroutines. A separately loaded instance remains independent.

Call APIs directly by their reserved names. Aliasing them, declaring variables with those names, passing the wrong number of arguments or calling them in `NO_VM`/`NO_OBF` regions causes a build error. Using an API does not automatically enable the VM.

## Scope and limits

- Ordinary KES syntax works without a VM. Lua 5.1/5.3 are supported; `//=` requires 5.3.
- All nine VM APIs support Classic, Karity and MOV on Lua 5.1/5.3. Existing pass and selective VM restrictions remain in the [full reference](kes.md#support-matrix-and-diagnostics).
- Convert KES source through Karity before running it in an ordinary Lua interpreter. Syntax-like text inside strings and comments stays unchanged.
- Lazy expressions add function-call overhead. See the [full reference](kes.md) for semantics and limits, and the [performance report](performance/kes.md) for measurements.
