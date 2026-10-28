# String Encode and String Mosaic

`string_encode` opts source, VM output or packer output into the shared
String Mosaic spelling policy. It adds no decoder, helper, runtime API or cache.
It remains independent of String Obf and String Flow Obf reconstruction.

| Target | Forms |
|---|---|
| Lua 5.1 | Single/double quotes, variable-level long brackets, decimal and short escapes |
| Lua 5.3 | Also hex and Unicode escapes, and `\z` with horizontal whitespace |

Each occurrence can use one literal or up to four fragments joined with `..`.
Fragments independently choose plain quotes, mixed escapes or long brackets.
Concat and long-bracket expressions are parenthesized to preserve precedence,
shorthand-call syntax, table keys, length operators and exactly one result.

```lua
local value = ("Ka" .. [=[ri]=] .. "\x74" .. '\u{79}')
```

Long-bracket levels are chosen to avoid closing-delimiter collisions, including
collisions at the end of a fragment. Default spelling never inserts physical
newlines: `\z` uses spaces/tabs, and fragments containing LF use quoted escapes
instead of long brackets. Original LF, CR and CRLF bytes retain their values.
Internal callers can explicitly allow multiline values; even then, no random
discarded newline is added to a value without LF.

CR and unsafe controls stay escaped. Long brackets are used only for valid UTF-8
that round-trips unchanged; arbitrary binary and malformed UTF-8 remain byte
escapes. Unicode escapes consume complete canonical UTF-8 code points. Lua 5.1
input escapes retain their native meaning. Original spaces, tabs and CR/LF bytes
are preserved even when `\z` discards whitespace in the source spelling.
Decimal escapes cannot absorb the next encoded unit.

Decoded literals are cached only within a pass; equal occurrences receive fresh
spelling. `--seed` reproduces a build. Generated fragments stay typed in the VM
emitter, so later String Obf/Flow can process them without misreading a concat
expression as a literal. Source/output activation remains independent; NO_OBF
exclusions still apply. Balanced, Strong and Maximum enable String Mosaic on
VM output; Maximum also enables it on the packer loader. Fast retains its
existing lightweight output list.

## Shared generation

`obfuscator/passes/string_mosaic.py` owns spelling strategies and `StringPolicy`.
`LiteralMosaic.strings()` supplies the active target and activation policy.
String Encode delegates to that service; it has no duplicate encoder.
Bare literals, host/native literal helpers and terminal API lookup keys share
the same byte quoting implementation. Terminal keys follow String Encode only
when selected; this needs no bootstrap API. Function junk strings follow the
active policy. Meme length expressions request a single quoted atom to preserve
numeric budgets and avoid adding concat work.

Callers can request literal-only spelling or prohibit newlines. Disabled styling
uses deterministic portable quoting. Transport blob layout/branding still follows
its own storage options; the service does not change KARITY/ or the signature.
