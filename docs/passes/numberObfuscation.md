# Number Obfuscation

`number_obf` replaces Lua numeric literals with randomized, semantically
equivalent expressions while preserving Lua 5.3 integer and floating-point
behavior.

### Example

```lua
-- input
48
```

```lua
-- possible output
(211720+0XaEd08)~((-6.201171875e-2+-0x0.04F+(-0x27.074)+~-0x1.78p+6+0X1.C4fd5Cb6p+19)//1&-1)
```

The exact representation is randomized per generation.

It is available in:

- `passes`
- `vm_output_passes`
- `packer_output_passes`

Implementation:

- `obfuscator/passes/number_obfuscation.py`
- VM-output integration: `obfuscator/vm/output_emitter.py`
- regression tests:
  - `test/run_number_obf_regression.py`
  - `test/run_vm_output_emitter_regression.py`

---

## Current implementation

The primary implementation is `NumberObfuscationPass`.

The regular source-pass path uses Tree-sitter and replaces every eligible
`number` node with an equivalent generated expression.

The pass also exposes:

```python
obfuscate_token(token: str) -> str
```

This token-level interface is used by the VM-output emitter so numeric literals
can be transformed without reparsing the complete generated VM source for every
literal stage.

---

## Integer transformation

Integer literals use two main representation families.

### Recursive integer expressions

The normal integer generator recursively decomposes a value using randomized
equivalent arithmetic and bitwise expressions.

Current operators include:

- XOR
- addition
- subtraction

Conceptually:

```text
V
→ A ^ (A ^ V)

V
→ A + (V - A)

V
→ A - (A - V)
```

The exact constants, nesting depth, decimal/hex representation, and hex letter
case are randomized.

The recursion depth is selected per literal.

### Float-backed integer expressions

Eligible integers may instead be represented through a floating-point
arithmetic chain and converted back into an integer.

Current constants:

```text
FLOAT_INT_CHANCE = 0.40
FLOAT_CHAIN_MIN = 5
FLOAT_CHAIN_MAX = 8
MAX_FLOAT_BACKED_INT = (1 << 39) - 1
```

The generator works in fixed quanta:

```text
QUANT_BITS = 12
QUANT = 4096
```

It builds a chain whose total is deliberately offset by a fractional amount,
then floors the final result back into the intended integer.

Generated terms can mix:

- decimal literals
- decimal scientific notation
- hexadecimal floating-point notation
- fixed hexadecimal fractions
- bitwise-derived integral terms
- positive and negative additive forms

The result is wrapped with one of several integer-normalization forms such as:

```lua
(expr // 1) | 0
(expr // 1) ~ 0
(expr // 1) & -1
(expr // 1) << 0
```

or equivalent XOR and double-complement variants.

The float-backed path is only used when the integer magnitude remains inside
the configured safe range.

---

## Numeric literal formatting

### Integers

Plain integer leaves may be emitted in decimal:

```lua
12345
```

or hexadecimal:

```lua
0x3039
```

Hexadecimal prefix and digit casing are randomized.

### Floats

Floating-point values can be represented using several equivalent styles:

- short decimal
- scientific decimal
- hexadecimal fixed-point
- hexadecimal exponent form

Examples:

```text
1.25
1.25e0
.125e+1
0x1.4p0
0x.14p+4
```

The formatter attempts to preserve the exact Python/Lua-compatible floating
value instead of introducing arbitrary decimal approximations.

Non-finite values are left in their original representation when possible.

---

## String-obfuscation interaction

### Historical behavior

`string_obf` has implemented its own numeric hiding layer since its original
implementation.

Each decoded string byte is currently emitted as an XOR pair:

```text
byte
→ A ~ (A ~ byte)
```

This means `string_obf` currently performs two responsibilities:

```text
string literal
→ byte reconstruction
→ numeric hiding
```

At the same time, `number_obf` already exists as the general-purpose numeric
obfuscation layer.

### Current behavior

In the ordinary AST pipeline, `NumberObfuscationPass` skips numeric literals
that are already located inside `string.char(...)`.

Conceptually:

```text
"hello"
→ string_obf
→ string.char(A ~ B, C ~ D, ...)
→ number_obf
→ generated operands are skipped
```

The VM-output structured emitter behaves differently.

When `string_obf` runs inside the emitter, generated numeric operands remain
typed as eligible `NumberLiteral` fragments. If `number_obf` appears later in
the configured stage order, those generated numbers are processed.

```text
"hello"
→ string_obf
→ generated numeric byte expressions
→ number_obf
→ generated numbers are obfuscated
```

Numbers inside an already-existing `string.char(...)` expression captured from
the source remain ineligible.

This creates a semantic difference between the ordinary source path and the
VM-output emitter.

### Proposed simplification

A cleaner design is to remove numeric hiding from `string_obf` entirely.

Under this model, `string_obf` would only lower strings into byte reconstruction:

```text
"hello"
→ string_obf
→ string.char(104, 101, 108, 108, 111)
```

If `number_obf` runs afterward:

```text
string.char(104, 101, 108, 108, 111)
→ number_obf
→ string.char(
    NUMOBF(104),
    NUMOBF(101),
    NUMOBF(108),
    NUMOBF(108),
    NUMOBF(111)
)
```

Responsibilities then become:

- `string_obf` owns string decoding and `string.char` construction
- `number_obf` owns numeric representation
- pass ordering determines whether generated string bytes are number-obfuscated
- the ordinary `string.char(...)` exclusion can be removed
- the string-specific XOR generator becomes unnecessary

This also reduces the number of numeric operands generated per byte.

Current representation:

```text
N string bytes
→ 2N numeric literals
```

Proposed representation:

```text
N string bytes
→ N numeric literals
```

Although each remaining literal may expand into a more complex `number_obf`
expression, removing the fixed XOR pair may offset part of the size and
generation cost.

### Security trade-off

The current representation has a predictable structure:

```text
string.char(A ~ B, C ~ D, ...)
```

Each byte is an independent constant expression and can be recovered with a
simple XOR-folding pass.

Replacing the fixed string-specific XOR encoding with the generic
`number_obf` backend would increase representation diversity because string
bytes would use the same randomized integer-expression families as other
numeric literals.

The resulting expressions are still constant-valued and can ultimately be
reduced by a capable evaluator.

The main benefit is therefore not fundamentally preventing constant recovery,
but centralizing numeric obfuscation and automatically applying its diversity
to string-generated bytes.

### Performance trade-off

The historical form performs one XOR expression per byte:

```text
A ~ B
```

The proposed form may generate deeper arithmetic, bitwise, or float-backed
expressions for each byte.

However, it also removes the two-numeric-operands-per-byte design.

The relevant comparison is therefore:

```text
current:
1 byte
→ 2 constants
→ 1 XOR

proposed:
1 byte
→ 1 constant
→ 1 number_obf expression
```

Before changing the representation, benchmark:

- generated source bytes per input string byte
- compiled Lua bytecode size
- VM-output size
- build time
- startup/runtime cost
- constant-folding recovery cost

If full `number_obf` is too expensive for every byte, a lighter numeric
generation path for string-generated literals may provide a better
size-to-analysis-cost ratio.

---

## VM output integration

Generated VM Lua can grow to many megabytes, so `number_obf` does not use the
normal:

```text
parse
→ replace
→ render
→ parse again
```

cycle for every VM-output literal stage.

Instead, `VmLiteralEmitter` keeps literals in a small fragment representation:

```text
Raw
NumberLiteral
StringLiteral
BooleanLiteral
```

Tree-sitter captures the original literals once.

Configured literal stages then transform those fragments directly.

Conceptually:

```text
StringLiteral(...)
    ↓ string_obf
generated numeric byte-reconstruction fragments
    ↓ number_obf
generated numeric expressions
```

This preserves configured pass ordering without reparsing the entire VM source.

---

## Stage layering

An important invariant is that literals generated by one configured stage
remain visible to later stages.

For example:

```text
string_obf
→ generates numeric byte-reconstruction operands
→ later number_obf processes those numbers
```

Repeated stages are also supported:

```text
number_obf
→ number_obf
```

The first stage generates an expression containing new numeric leaves.

Those leaves remain typed as `NumberLiteral` fragments and become inputs to the
second stage.

A stage does not recursively process the literals it creates during that same
stage.

This preserves the historical parse-after-each-pass semantics while avoiding
whole-source reparsing.

---

## Generated-number tokenization

`NumberObfuscationPass.obfuscate_token()` currently returns Lua source text.

The VM emitter scans the controlled generated expression with
`_GENERATED_NUMBER_RE` and converts its numeric leaves back into typed
`NumberLiteral` fragments.

This is required so later `number_obf` stages can still observe numbers created
by earlier stages.

The current flow is therefore:

```text
typed numeric literal
→ generated expression text
→ numeric-leaf tokenization
→ typed numeric literals
```

This is a transitional design between text-based expression generation and a
fully structured numeric expression IR.

---

## Exact VM regions

Some VM-generated numeric regions must not be rewritten.

The emitter currently marks numbers as ineligible when they are:

- exact 64-bit hexadecimal constants
- inside `KARITY_EXACT_BEGIN` / `KARITY_EXACT_END` graph regions
- inside protected `string.char(...)` expressions captured from the source

The first two exclusions protect exact-width or compiled graph assumptions.

The `string.char(...)` exclusion reflects the current implementation and may be
removed if string numeric hiding is fully delegated to `number_obf`.

---

## Validation

Generated expressions are checked for syntax patterns that have caused Lua
parsing hazards.

Expressions containing:

```text
--
```

are rejected because they may accidentally form a Lua comment token.

Expressions containing:

```text
(+
```

are also rejected to avoid invalid unary-plus forms.

If parsing or numeric conversion fails, `obfuscate_token()` falls back to the
original token.

---

## Randomness and reproducibility

The pass uses Python's global `random` module throughout expression generation.

Deterministic builds therefore depend on the surrounding pipeline configuring a
reproducible random seed before the pass runs.

The same input and seed should produce the same generated representation.

Release builds should not use a fixed diagnostic seed.

---

## Regression coverage

`test/run_number_obf_regression.py` exercises integer-expression generation
across many values and 128 random seeds.

Boundary-style values include:

```text
-1
0
1
127
128
255
256
4095
4096
65535
0x7fffffff
0xffffffff
```

The test also includes an additional generated set of larger integers.

Every generated expression is executed by Lua and checked against its expected
value.

The same regression also verifies:

```text
string_obf → number_obf
```

across 128 seeds and tests number obfuscation in the packer-output pipeline.

`test/run_vm_output_emitter_regression.py` additionally verifies:

- one Tree-sitter literal parse for the direct emitter path
- generated string/boolean numbers remain visible to later number stages
- repeated `number_obf` stages preserve layering
- current source-captured `string.char` exclusions are preserved
- generated VM output preserves runtime semantics

---

## Performance characteristics

Number obfuscation is expansion-heavy.

One input number can produce many numeric leaves and a substantially larger Lua
expression.

On ordinary source files this cost is usually small, but generated VM output can
contain hundreds of thousands of numeric literals.

The VM-output emitter exists specifically to avoid repeatedly parsing that
expanded source.

The remaining cost is approximately driven by:

```text
number of eligible NumberLiteral fragments
×
cost of randomized expression generation
×
number of generated numeric leaves
```

Large `number_obf` stages can therefore become dominated by Python-side:

- random generation
- expression construction
- fragment allocation
- generated-number tokenization
- final rendering

rather than parsing itself.

---

## Design invariants

Changes to this pass should preserve the following properties:

1. Generated expressions evaluate to the exact original Lua numeric value.
2. Lua 5.3 integer behavior must not silently become floating-point behavior.
3. Float representation must not introduce unintended precision changes.
4. Earlier pass output remains visible to later configured passes.
5. A stage must not recursively consume its own newly generated literals.
6. Repeated `number_obf` stages must still create additional layers.
7. Current `string.char` exclusions must remain internally consistent until the
   proposed string/number responsibility split is implemented.
8. Exact-width VM regions must remain untouched where required.
9. Failed parsing or formatting must safely fall back to the original token.
10. Seeded test builds must remain reproducible.

---

## Known architectural debt

### Text-based numeric expression generation

`NumberObfuscationPass` still generates expressions as strings.

The VM emitter then scans those controlled expressions using
`_GENERATED_NUMBER_RE` to recover their numeric leaves.

This avoids whole-source reparsing but still creates an internal round trip:

```text
structured literal
→ generated text
→ regex tokenization
→ structured literals
```

A structured numeric-expression IR could eliminate this boundary.

### Python object and allocation cost

The VM emitter stores generated numeric leaves as individual
`NumberLiteral` fragments.

Very large VM outputs can therefore create hundreds of thousands or millions of
Python objects and strings.

This is a likely optimization target now that repeated whole-source parsing has
largely been removed.

### Global random API

Generation performs many calls through Python's global `random` module.

For extremely large VM-output stages, random generation itself may become a
measurable hot path.

Useful profiling targets include:

- RNG calls
- string formatting
- recursive expression generation
- `_GENERATED_NUMBER_RE`
- fragment allocation
- list growth
- rendering

Only after those costs are measured should a compact representation or native
hot path be considered.

---

## Possible future work

These are design directions rather than committed tasks.

### Structured numeric expression IR

Replace text-producing helpers with structured nodes such as:

```text
Literal
Add
Sub
Xor
BitNot
FloorDiv
Shift
And
Or
Neg
```

For example:

```text
NumberLiteral(123)

→

Xor(
    NumberLiteral(A),
    NumberLiteral(A ^ 123)
)
```

Later `number_obf` stages could traverse these nodes directly.

Only the final renderer would produce Lua source.

### Compact fragment storage

If Python object allocation remains a bottleneck, replace
one-Python-object-per-fragment storage with a compact tagged representation or
arena.

### Template-based generation

Common expression shapes could be selected from reusable templates while only
their constants and formatting vary per literal.

This may reduce Python formatting and allocation overhead while preserving
build diversity.

### Native hot path

If profiling shows that Python computation remains the dominant cost after
structural optimizations, numeric-expression generation or rendering could move
to a small native module.

This should come after eliminating avoidable text and representation
round-trips.

---

## Related files

```text
obfuscator/passes/number_obfuscation.py
obfuscator/vm/output_emitter.py
obfuscator/registry.py
test/run_number_obf_regression.py
test/run_vm_output_emitter_regression.py
```