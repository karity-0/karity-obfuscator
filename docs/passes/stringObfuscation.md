# String Obf

`string_obf` restores the compact byte reconstruction used before Karity 1.2.0.
Each byte independently chooses XOR, addition, subtraction, remainder, modular
multiplication, integer division, or masking. Inverse operands are computed at
build time, so all runtime results are exact bytes in 0..255.

```lua
string.char((516~612),(811-706),(835%257))
```

The illustration shows the shape, not a fixed encoding. Operands always use a
bounded producer from the shared [Literal Mosaic](../literal-mosaic.md) service,
independently of the Number Obf source pass. MemeStrings participates only when
enabled in the same scope. Generated numeric provenance prevents later numeric
passes from expanding the same operands again; original source numbers still
follow their independent pass selections.

Calls contain at most 16 byte arguments. Up to four calls concatenate directly;
long strings use a table constructor and table.concat, bounding argument counts
and concatenation recursion. Empty strings use a zero-argument string.char.
Results stay at the original expression position, have exactly one return value,
and preserve UTF-8/binary bytes, escapes and Lua long-string newline handling.

The pass requires Lua 5.3 native bitwise and integer operations. It is available
in source, VM output and packer output lists. `STRING_OBF("secret")` automatically
enables it for that literal; selection_modes and NO_OBF apply normally.

## String Flow Obf

The staged mutable reconstruction introduced in 1.2.0 is now the independent
[`string_flow_obf`](stringFlowObfuscation.md) pass, with `STRING_FLOW_OBF("secret")`
as its marker. It interleaves shared state, working words and shuffled records.
Choose one string strategy per scope. Explicit string macros take precedence
over the other strategy's whole-source selection.

Strong/Maximum presets and shipped high/max source profiles keep the staged
algorithm under its new name. Custom `string_obf` selections now choose the
compact algorithm. Move former staged settings to `string_flow_obf_options`;
`string_obf_options` remains a legacy alias for Flow settings only.
