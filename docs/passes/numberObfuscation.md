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

Karity 1.2.0's `string_obf` generates randomized multi-statement arithmetic and
bitwise reconstruction programs instead of fixed XOR pairs. Its keys, seeds,
state updates and output indices are ordinary numeric tokens. When `number_obf`
follows it, all of these tokens are eligible for number obfuscation.

The same rule applies to existing `string.char(...)` arguments. Both the source
pass and the structured VM emitter have removed the string-char exclusion.
The emitter exposes the generated program's numeric leaves directly, preserving
stage order without reparsing the complete VM output.

StringObf keeps exact 24-bit working words and bounded shifts/multipliers;
NumberObf preserves each original numeric value. See
[String Obfuscation](stringObfuscation.md) for generation strategies, cost limits
and CFF/VM composition.

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

These exclusions protect exact-width or compiled graph assumptions. Numeric
operands of `string.char(...)` are eligible like other source numbers.

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
- source-captured `string.char` operands are processed
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
7. String-reconstruction numbers and `string.char` operands remain eligible
   for later number stages in both source and structured emitter paths.
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