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

Place this pass after string transformations to keep the fun strings visible.
VM output automatically runs it after the structured literal emitters and
before post passes such as minification.
Source passes execute before VM compilation; use `vm_output_passes` or
`packer_output_passes` to put the phrases in the generated runtime or loader.
This optional pass is not enabled automatically by the existing profiles.
