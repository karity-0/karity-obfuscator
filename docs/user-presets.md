# User presets and backend selection

The GUI's four user policies are `builtin:fast`, `builtin:balanced`,
`builtin:strong` and `builtin:maximum`. Their only definition is
`obfuscator/presets.py`; the CLI, GUI bootstrap and VM selection resolver share
it as a name-keyed `PRESETS` catalog (revision 5, version 1.6.0).
`fast`, `balanced`, `strong`, `maximum` are convenient CLI aliases when the
project does not define a profile with that name. Qualified IDs explicitly
select the builtins. The default backend remains Karity.

## Compatibility and persistence

`dev`, `fast-vm`, `high`, `max` retain the definitions in their JSON file. They
are legacy/project choices in advanced settings, not labels for the four user
buttons. `dev` remains diagnostic. Existing flat JSON is supported. Local
`config.json` does not replace the builtin catalog with its old profile values.
Existing saved GUI configurations load as resolved snapshots, including unknown
future fields, custom options, backend and selection settings. No catalog
revision is reapplied at startup. Switching away and back restores a policy's
customized snapshot; environment/signature/backend settings follow the current
selection. A backend-only edit does not mark a policy custom.

```sh
python main.py input.lua --profile builtin:balanced --vm-option backend=mov
python main.py input.lua --profile builtin:fast --deployment-check
python main.py input.lua --config obf_gui_config.json
```

`--deployment-check` checks baseline VM/anti-debug/anti-decompile, constant
integrity, visible output passes and disabled tracing. It permits one VM.
The original stricter `--release-check` retains its two-VM and other constraints;
fast/balanced do not satisfy that policy by default. Neither check proves
resistance to analysis. Release/deployment checks reject test seeds.
The GUI's deployment checkbox uses the baseline check for user presets and
the existing strict check for legacy/custom profiles. Its saved checked state
is retained when changing presets; one-VM user presets do not fail the legacy
two-VM rule merely because the checkbox was already checked.

## Source and final output have different roles

Fast defaults to stripping, anti-debug, anti-decompile, minification and VM.
Balanced adds BooleanObf, TableObf, Compact String Obf and localized globals to
the eligible source, so unmarked source receives more protection than Fast.
Neither enables whole-source CFF or Flow String by default; existing
macros/directives can still select these passes.

| Preset | Source protection | VM protection | Final output |
|---|---|---|---|
| Fast | Minimal transforms | Lightweight, 1 VM | Existing lightweight output |
| Balanced | Boolean + Table + Compact String | Medium, 1 VM | String Mosaic |
| Strong | Flow String + CFF + Number + source memes | High, 2 VMs | String Mosaic |
| Maximum | Strong with larger budgets + source renaming | Highest budgets, 3 VMs | Packer + String Mosaic + larger numeric diversity budgets |

Strong/maximum apply Boolean/Table/String Flow Obf -> FunctionObf -> NumberObf and
source memes to the whole eligible source. `all_source_functions` removes the
default SOURCE nesting-depth cutoff, without overriding explicit exclusions or
compiler/semantic safety fallbacks. Generated CFF helpers are not recursively
treated as new source functions. Explicit `nested=false` still takes precedence.
`max_pass_expansion_ratio` sets a compiled-instruction budget of `8/10/12/16`
times the input for the four tiers (with the existing 256-instruction floor).
Budget pressure uses compact CFF with lower junk/dead-state density, reported
in profiling; it retains the eligible source/reconstruction coverage. An
impossible budget fails after the existing bounded retry with diagnostics.
All tiers permit bounded loop splitting and
unrolling when FunctionObf runs. String reconstruction options also apply when
STRING_OBF enables the pass automatically. Selection reports remain authoritative
for excluded or unsupported constructs.

`STRING_OBF("...")` enables StringObf, not FunctionObf. To combine reconstruction
and CFF, mark the containing function with `--@FUNCTION_OBF`. Existing macro
meanings and `all`/`marked` modes are unchanged. Named VM macro profiles inherit
the selected backend unless they explicitly define one; builtin policies never
define a backend.

Every tier uses StripInfo, RenameObf, MemeStrings, NumberObf and Minify on the VM
output. General output CFF/StringObf are off; VM's own handler, dispatcher,
state and instruction protection remain enabled according to backend support.
Balanced/strong/maximum also enable StringEncode (String Mosaic) on VM output.
It changes literal spelling without a decoder or runtime helper and does not
insert physical newlines. Fast keeps its existing output list. Maximum packs
the result and applies String Mosaic and the visible Number/Meme passes to the
packer loader, with independent output scope and larger numeric budgets.
Maximum also renames source identifiers before minification and VM lifting.
Legacy max is unchanged.

The complete user policies currently require Lua 5.3: existing AntiDebug,
String/Boolean/Number/Meme and packer capability declarations still reject
unsupported Lua 5.1 source/output stages explicitly. Lua 5.1's supported custom
pipelines, CFF and native VM implementations retain their existing behavior;
the redesign does not claim that every preset runs on both Lua versions.

## Runtime numeric policy

User output boundaries enable `literal_mosaic.output_cost`. The existing number
and meme engines generate each eligible runtime literal once; its protected
provenance prevents a second numeric/meme expansion. Visual notation diversity
is independent of operation limits. Original source NumberObf retains the full
engine. Legacy output lists retain their original generation when output_cost
is absent.

When MemeStrings precedes NumberObf, the first structured numeric stage owns
both selected styles. The subsequent NumberObf replacement count is zero
because those literals were already generated once, not because number styling
was skipped; Mosaic strategies and notation counters show the combined work.

The runtime emitter marks its once-entered outer runtime as generated entry
code. On the existing syntax tree, numeric operands in loops and nested
callables are conservatively hot; outer initialization is cold. Unmarked
callable bodies are hot. No variable-name or expression-shape matching infers
roles. Unknown/third-party provenance is not assumed to execute only once.
Exact graph regions and existing exact 64-bit exclusions remain protected.

Numeric types, signed hexadecimal values, negative zero and decimal overflow
must retain Lua semantics. A budget fallback can choose a diverse literal
instead of arithmetic; its occurrence is reported by Mosaic metrics. Meme
candidate rates are not guarantees of emitted ratios. Small outputs may not
contain every notation or a meme. This is not a numeric security score.

## Backend capability reporting

Source passes and output styling work independently of the selected backend.
Karity supports encoded state, threading, graphs and delayed materialization.
Classic uses direct handlers; MOV uses lookup microcode and explicit HOST
boundaries. Karity-only features are not equivalent automatically to either.

The simple GUI uses two matching button groups for strength and backend.
VM buttons open a translucent full-window chooser with short backend summaries.
Click a card to apply it, use arrows to move focus, or Escape to cancel.
Preferences → GUI → Quick VM change restores direct switching; this preference
is saved independently of protection settings.
A short support link opens the explicit unsupported/fallback list in advanced
settings while retaining the requested values. Advanced controls use the same
capability metadata. Switching backends
does not replace a tier or its stored parameters. Declared fallbacks are shown
by name; required unsupported features fail the build. There are currently no
automatic declarations making Classic/MOV equivalent to Karity state protection.
CLI warnings and protection-plan/backend-IR dumps expose the same differences.

`state_dependency_limit` caps graph-selected state dependency arity (1..3) on
Karity. This creates an actual maximum-structure difference in addition to
graph/variant rates, helper counts and block spans. It is not applicable to
Classic/MOV. Their higher tiers still differ in source reconstruction/CFF and
supported common controls, not a claimed identical level of VM protection.

## Measurement

Use `tools/benchmark_user_presets.py` for serial external builds, native Lua
execution equality, output size and child peak working set. Ordinary and
`--diagnostic` runs are separate; diagnostics expose per-pass costs, CFF compiler
measurements and Mosaic diversity. `--ablation notation|no-unroll|no-pack|full-output|no-cff-budget`
creates explicitly labelled experiments, never production presets.
Windows memory excludes compiler grandchildren. Runtime wall time includes
process creation/startup and must not be presented as steady-state throughput.
See [measured settings and limitations](performance/user-presets.md).
