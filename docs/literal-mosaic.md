# Literal Mosaic

Literal Mosaic is an internal scoped expression service, not another pass or
another obfuscation layer. It shares `NumberExpressionEngine` with NumberObf
and `MemeExpressionEngine` with MemeStrings. No pass registry entry is added.

## Call flow and activation

`Pipeline.run` creates a service after resolving the real base pass list,
including passes enabled by source selections. StringObf scopes each original
literal, reconstructs its existing numeric/data dependency program, and sends
its generated operands to `transform_generated`. FunctionObf scopes each
original function and asks `NumericTransport.generated_expression` for bounded
state/transition/junk constants. The service returns a protected `CodeText`.
Later NumberObf/MemeStrings skip its numeric leaves. Original source numbers
still use the full existing NumberObf generator.

| Enabled in this scope | Allowed new generated strategies |
|---|---|
| Neither | Existing intrinsic pass generation only |
| NumberObf | Existing number formatting and bounded arithmetic |
| MemeStrings | UTF-8 byte-length expressions and necessary plain constants |
| Both | Both families, subject to the caller's budget |

Source, VM output and packer output have independent actual pass lists. Output
boundaries share settings and profiling counters, never source activation
flags. CLI pass overrides therefore affect the service through the resolved
pipeline. `selection_modes` and Number/Meme regions are checked using the
original location being transformed. A source macro cannot silently enable
an output pass. A marked child function restores its parent's scope on exit.
Context variables restore scope even on exceptions.

VM internal emitters retain their existing explicit protection algorithms.
`vm_internal` disables optional Mosaic strategies; it does not disable their
configured original literal stages. This change does not rewrite VM handlers,
dispatchers, state coupling, relocation, blob protection or hot arithmetic.
The scoped service is available for future, individually budgeted generator
call sites. The current high/max lightweight output pass lists retain
StripInfo, RenameObf, MemeStrings, NumberObf and Minify.

## Generation and cost

```python
from obfuscator.passes.literal_mosaic import LiteralMosaic, use_mosaic

service = LiteralMosaic(['number_obf', 'meme_strings'], lua_version='5.3',
                        options={'style': 'exotic', 'cost': 'auto'})
with use_mosaic(service):
    expression = service.number(73, context='function_constant', hot=True,
                                max_chars=192, max_operations=3)
```

`number` accepts an integer or float, including NaN, infinities and negative
zero. Booleans are rejected. Lua 5.3 integers must fit signed 64 bits. The
minimum integer uses a hexadecimal bit pattern because decimal magnitude
9223372036854775808 followed by unary minus would become a float.

Style and cost are separate controls. Compact avoids nested generated
arithmetic and favors short float formatting. Balanced permits bounded
arithmetic and mixed notation. Exotic increases selection of integral float
notation with an integer conversion, rather than merely changing hex case.
The existing NumberObf engine supplies decimal/hex integers, scientific
notation, decimal and hexadecimal floats, leading-dot forms, arithmetic and
bitwise families. A generated-only `mosaic_int` entry point adds cheap
multiply/divide, modulo, AND/OR, NOT and shift alternatives using that engine's
existing literal formatting. Source `obfuscate_token` and its seeded algorithms
are unchanged. Literal formatting never changes the required Lua type.
The full original number strategy is available for cold generated values only
when the operation budget permits it; it is always retained for source NumberObf.

`auto` allows three operations on hot paths and twelve on cold paths. Low,
medium and high cap operations at 3, 12 and 20 respectively. All caps intersect
the service settings and the caller's existing limits. Default service limits
are 192 characters and 12 operations; FunctionObf's default three-operation
limit takes precedence. A single bounded fallback selects a simpler expression
if necessary. Unrepresentable explicit budgets produce a diagnostic, not an
unbounded random retry. Native compiler probes, CFF splitting and instruction
budgets remain authoritative after expression generation.

Meme generation uses UTF-8 byte lengths, including the existing RLO/PDF phrase
pool. Generated constants default to a 0.15 candidate rate; the existing
source/output MemeStrings pass still uses exactly 0.35. Failed candidates can
fall back to literals, so candidate rate is not an emitted ratio. Lua 5.1
generation avoids native bit operators, floor division and hexadecimal floats;
large values use double-compatible literal/zero-correction expressions.

StringObf's split lengths, mutable states, MBA/reconstruction operations and
expression wrapper are preserved. Only generated numeric operands change.
StringObf still precedes FunctionObf, and its reconstruction statements still
receive CFF and compiler-measured grouping/splitting. Generated operands become
protected after their first budgeted generation; unlimited subsequent numeric
and meme layering would defeat that budget. This intentionally changes generated
operand protection, while preserving original-source NumberObf and the
StringObf/CFF/VM structure.

## Provenance

The existing `CodeText` carries protected spans, StringObf reconstruction
ranges, and origin labels through edits, slicing and joining. Labels include
source numbers, original string reconstructions, StringObf constants,
FunctionObf constants, meme expressions, VM constants and
`context/mosaic:strategy`. No variable-name or expression-shape matching decides
whether a number is generated.

`NumericTransport` temporarily serializes registered identities as private
comments through FunctionObf's textual rewrites. Finish removes all markers
and restores metadata. Unknown registered-prefix markers and unmatched pairs
raise errors. This does not promise to detect a third-party transform that
discards both markers and all metadata. Metadata belongs to the internal
transformation pipeline, not Lua files reloaded by a separate build. Minification
and final serialized files are intentional text boundaries; raw final output
contains no provenance markers. Reprocessing an emitted file is a new input.

An already handled expression is transported once as a whole, rather than
registering its numeric leaves separately. Unicode byte/character coordinates
use a compact unsigned offset array (ASCII still needs no mapping), limiting
the memory cost of early emoji/RLO meme generation without changing offsets.

## Metrics and limits

Profiling (`--profile-report`) or `diversity_metrics: true` enables counters.
Metrics are disabled by default and consume no PRNG calls. They report:

- Strategy counts/ratios, generation origin and source/output phase counts.
- Numeric notation, operator families and overlapping expression classes.
- Complete average operation/character counts and estimated instruction cost.
- Sampled expression depth, normalized structural fingerprints and repeats.
- Budget fallbacks and numeric leaves skipped to prevent duplicate layers.

Quoted strings are tokenized as whole strings, so digits inside meme text do
not become numeric counts. Fingerprints normalize identifiers, strings and
numbers while preserving operators/structure and ignoring redundant parentheses.
Detailed AST analysis samples the first 128 expressions per phase/strategy;
lexical counters cover every generated expression. Reported maximum depth and
repeated patterns apply to that deterministic sample, not the entire output.
Fewer than 32 samples is marked insufficient. Instruction estimates are a
heuristic; FunctionObf separately measures actual Lua bytecode. No diversity
score or security-strength score is claimed.

Existing full StringObf/NumberObf/MemeStrings passes still require Lua 5.3.
The common generated-expression service and FunctionObf support portable Lua
5.1 strategies; this does not make the full high/max source presets portable
to Lua 5.1. GUI fine-grained options and generic string-generating Mosaic APIs
are intentionally deferred. No environment proxy or `_ENV` interception is
introduced.

See the [controlled performance report](performance/literal-mosaic.md) for
measurements, regression coverage and remaining costs.
