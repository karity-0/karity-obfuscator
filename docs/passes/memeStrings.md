# Meme / Fun Strings

Enable `meme_strings` in `passes`, `vm_output_passes`, or
`packer_output_passes`, or select **Meme / Fun Strings** in the GUI.

```sh
python main.py input.lua --passes meme_strings,minify
```

Every numeric literal has a 35% chance of replacement, regardless of whether
a phrase matches its value. Exact matches can use `(#"lol")` for `3`.
Other integers use string lengths plus or minus a correction, for example
`(#"bruh" + (#"lol"))` for `7`. Corrections may themselves use string lengths;
recursion is capped at two arithmetic levels to bound output growth.
Residual integer literals use hexadecimal to preserve Lua 5.3 integer wraparound.

Floating-point literals use an exact zero correction, for example
`((0.1) + (#"lol" - #"uwu"))`, avoiding rounding errors from subtracting a
phrase length from the original float. Float types and unary negative zero
are preserved. Decimal literals overflowing the integer range follow this
same float path.

Phrase lengths count UTF-8 bytes, including Unicode phrases. Parentheses
preserve precedence, including powers and unary minus. Comments and existing
strings are never rewritten. The usual build seed controls selection.

The phrase pool also includes six variants wrapped in U+202E (RIGHT-TO-LEFT
OVERRIDE) and U+202C (POP DIRECTIONAL FORMATTING). Supporting viewers display
the phrase in reverse character order. Both controls stay inside the quoted
Lua string; each contributes three UTF-8 bytes to its length. Generated Lua
contains the actual control characters, while the Python phrase list spells
them with Unicode escapes for readability.

Place this pass after string transformations to keep the fun strings visible.
For VM/packer output, `meme_strings` before `number_obf` keeps the phrases visible
while NumberObf transforms their residual numbers with its full expression and
literal-format engine. Both run in the shared literal emitter. This order avoids
wrapping every generated NumberObf operand in more string arithmetic. Existing
explicit NumberObf → MemeStrings configurations retain their former behavior.
Source passes execute before VM compilation; use `vm_output_passes` or
`packer_output_passes` to put the phrases in the generated runtime or loader.
The high/max profiles enable `strip_info`, `rename_obf`, `meme_strings`,
`number_obf`, `minify` for both VM and packer output. They retain visible memes
and varied numeric notation without another FunctionObf/StringObf round on the
generated runtime. The additional literal stages still increase output size and
processing/runtime cost; they are not merely text decoration.
