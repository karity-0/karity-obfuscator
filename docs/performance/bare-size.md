# Bare output size and source expansion

Bare emits executable Lua for program operations; opcode-blob backends store
instruction data and share an executor. Encoding/encryption is not compression
and can enlarge stored data. The size crossover depends on input shape, constant
storage, closure count and selected source/output passes.

## Protection-package change

The earlier adapter lowered a complete generic protection package into Bare:
22 security-owned IR functions and 1,574 instructions, accounting for about
118KB of raw generated function bodies for `print("hi")`. Its minified protected
sample was 86,198 bytes.

The revised adapter keeps guard decisions and guest boundaries in IR, contracts
atomic protection call groups, and shares native inspection/recovery primitives.
It selects optional write/string/getter/environment/tailcall paths from actual
use, shares numeric-loop conversion, and deduplicates constants across functions.
Native APIs, factory keys and line-probe banks use random numeric slots. The
existing dispersed line reader is reused. Constants occupy a compact printable
pool with random type tags and masked offsets, rather than escaped record lists.
The corresponding minimal-pass sample is **10,201 bytes**, about 88% smaller.
The protected base still has a fixed cost; it is not the old unprotected 230-byte
dispatcher sample.

## Measurements

Single-build samples on Lua 5.3, PRNG seed 7719, no signature or packer,
`strip_info,rename_obf,minify` output passes, one VM, numeric integrity enabled
at rate 1.0. Legacy diversity/virtualization options use
`test/run_vm_backend_regression.py:options` (mostly disabled); Bare ignores its
unsupported opcode/blob controls. These are output sizes, not speed or resistance
rankings. Generated source and output were executed with the matching native
Lua 5.3 runtime and compared.

| Input | Input bytes | Bare bytes | Karity bytes |
|---|---:|---:|---:|
| `print("hi")` | 11 | 10,201 | 63,820 |
| 100 straight-line additions | 1,481 | 16,598 | 75,507 |
| 1,000 straight-line additions | 14,504 | 64,997 | 124,005 |
| `print("hi")` with Anti Env | 11 | 51,680 | 93,874 |
| 100 small closures | 3,017 | 53,706 | 101,625 |
| 500 small closures | 15,817 | 230,291 | 236,277 |
| 1,000 small closures | 31,820 | 458,646 | 409,162 |

The addition case starts at `INPUT or 0` and repeats `total=total+(i%17+1)`.
The closure case builds `f[i]=function() return i end` with literal indices and
prints the first/last results. Anti Env is inserted before VM compilation, so
its own code also expands into Bare blocks. With 1,000 small closures, per-function
frame/capture/guard code makes Bare larger than Karity in this sample.

The separate shipped `fast` preset sample, with Bare and no signature, is
**31,377 bytes** for `print("hi")`; it enables additional transformations and is
not the minimal-pass row above. Literal mutation and other protection settings
can change these figures.

Local review artifacts and the measurement script are in `temp-bare-size/`.
`python temp-bare-size/measure.py` recreates the samples, configs and `sizes.json`
in this working checkout. The folder is an ignored review artifact, not a
required project dependency. Focused growth budgets and semantic/adversarial
checks are maintained in `test/run_source_protection_regression.py`.

## What Prometheus does

Prometheus also emits program-specific source blocks, so adding AntiTamper or
other source steps can increase its output. Its Medium preset runs AntiTamper
before Vmify; Strong applies Vmify twice. It does not remove this general size
tradeoff. [Presets](https://github.com/prometheus-lua/Prometheus/blob/master/src/presets.lua)

Its compiler consumes AST directly, accumulates statements inside a block,
reuses released temporary registers, and shares closure generators by argument
count. Its emitter merges independent adjacent assignments and creates threshold
dispatch over blocks. These reduce scaffolding without converting the program
to an encrypted opcode stream.
[Compiler](https://github.com/prometheus-lua/Prometheus/blob/master/src/prometheus/compiler/compiler.lua),
[blocks](https://github.com/prometheus-lua/Prometheus/blob/master/src/prometheus/compiler/block.lua),
[registers](https://github.com/prometheus-lua/Prometheus/blob/master/src/prometheus/compiler/register.lua),
[emitter](https://github.com/prometheus-lua/Prometheus/blob/master/src/prometheus/compiler/emit.lua)

Bare currently starts from the shared Lua bytecode-derived semantic IR and keeps
per-function native closures and precise lifetime handling. It does not yet have
Prometheus's AST expression lowering, shared arity-based closure factories, or
general parallel-assignment fusion. Sharing the protection primitives and
reducing unnecessary block splits do not remove those remaining differences.
