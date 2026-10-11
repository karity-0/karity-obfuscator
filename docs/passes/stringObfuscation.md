# String Obfuscation

Karity 1.2.0's `string_obf` replaces fixed XOR pairs with a newly generated
reconstruction program for each literal occurrence. There is no V2 pass,
shared decoder, or additional high-strength mode.

```json
{
  "passes": ["string_obf", "number_obf", "function_obf", "rename_obf", "localize_globals", "vm"],
  "selection_modes": {"string_obf": "marked"}
}
```

With `marked`, `local s = STRING_OBF("secret")` selects that literal. With `all`
(the default), every string literal is selected. A macro automatically enables
the pass even if `string_obf` is absent from `passes`. NO_OBF exclusions remain
effective. Source strings and generated VM/packer strings use the same generator.

## Reconstruction program

Lua literals are decoded to bytes, including UTF-8, decimal/hex escapes, embedded
NULs and long-bracket newline normalization. Bytes are split into random chunks
of one to three bytes and packed into unsigned 24-bit words. Calculation order
is shuffled independently of the final string order.

Each group uses two to four reusable working registers (one for a one-byte
literal), a changing shared state, a key and scratch storage. Each chunk receives
a random sequence of arithmetic, XOR, masked multiplication, ROL/ROR, or MBA
steps. Rotations use shifts, OR and masks. MBA addition uses
`(x ~ y) + ((x & y) << 1)`; MBA XOR uses `(x | y) - (x & y)`.
Multiplication uses odd factors so it is invertible modulo `2^24`. Build-time
inverse evaluation calculates seeds; runtime code executes the forward steps.

The generated instructions reuse and overwrite registers. A bounded number of
scratch dead stores may be inserted among necessary computations. Keys depend
on the changing shared state, and later groups also depend on a previously
reconstructed word. Steps for independent working words are interleaved while
maintaining each word's dependencies. All arithmetic working values are masked
to 24 bits; shifts are positive and below 24. Ordinary NumberObf can transform
all numeric leaves without an exemption for `string.char` operands.

Each occurrence independently chooses a materialization strategy:

- Numeric: retain packed numeric words until the final string-building stage.
- Partial: materialize small chunks as their reconstruction completes.
- Mixed: materialize some chunks early and retain others as numeric words.

The completed pieces are assembled in their original order. Partial strings
contain at most three source bytes; full plaintext is produced only at the end.

## Evaluation and scope

Every replacement is a parenthesized expression with a private function scope
and exactly one result (an empty string needs only a zero-argument `string.char`).
It works in initializers, arguments (including Lua's quoted shorthand calls),
return lists, tables, keys and conditions. It captures no user arguments, so
varargs and multiple-return adjustment are unchanged. Generated names reserve
the source's identifiers and planned VM identifiers.

Reconstruction stays at the original expression evaluation point, including
inside short-circuit operands and loop bodies. No code moves across user
statements and no global cache is introduced. All working tables and values leave
scope when the helper returns; extra `nil` cleanup instructions are unnecessary.
As with the previous string pass, generated code requires the standard string
library; it also uses `table.concat` and `string.sub` for assembly.

## Other passes and cost limits

Place `string_obf` before `function_obf` when CFF should distribute reconstruction
statements across control-flow states. Place NumberObf and renaming after
StringObf to process its constants and bindings. The pass does not rerun other
passes or add a second CFF layer itself. Applying VM afterward virtualizes the
generated instructions. Applying StringObf only in `vm_output_passes` protects
the emitted runtime's strings rather than the original source bytecode constants.
The example config's `high` and `max` source profiles put StringObf before
FunctionObf. Existing custom pass orders remain effective. Enable FunctionObf's
`nested` option when reconstructing literals inside user functions.

Strings up to 16 bytes and eight chunks use an unrolled, independently varied
schedule per group, with two to three steps per word. Other strings use a fresh
two-to-three-step schedule per working register,
randomized record-field layout and shuffled records. The schedule is reused
only within that literal: seeds and state-derived keys differ between records.
This bounds the instruction graph and number of local variables independently
of the literal length. Encoded record storage and runtime work remain linear in
the byte length. There is no per-byte local variable and no large `string.char`
argument list, avoiding Lua's local/register and argument limits.

When enabled in the same source/output scope, [Literal Mosaic](../literal-mosaic.md)
generates the numeric reconstruction operands using bounded NumberObf/MemeStrings
strategies. Those operands carry protected provenance, so later literal passes
do not expand them again. The mutable reconstruction program and its subsequent
CFF protection remain in place. Original source numbers still receive full NumberObf.

NumberObf and CFF still add cost to these programs. Repeated literal passes and
extreme output-pass combinations can expand source substantially; default
StringObf does not automatically repeat them. No reconstruction cache is hoisted
out of loops because that could change the timing of library lookups.

`--seed` reproduces test builds. Repeated equal literals consume fresh randomness
and have distinct programs even within one seeded build. This raises the cost of
static pattern-based recovery; runtime capture of finished strings and full
program emulation remain possible.

## Validation

`test/run_string_obf_regression.py` covers all bytes and strategies, each operation,
size boundaries, large-string graph limits, expression evaluation, macros,
selection, seeded diversification, and NumberObf/CFF/Rename/emitter composition.
The existing number, selection, VM output and packer suites cover integrated
runtime execution. The shared CI manifest includes the new regression suite.
