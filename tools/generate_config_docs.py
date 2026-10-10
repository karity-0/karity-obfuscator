from __future__ import annotations

import argparse
from pathlib import Path
import sys


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

from obfuscator.registry import (  # noqa: E402
    PASS_DESCRIPTIONS,
    PASS_REGISTRY,
    VM_OPTION_DOCS,
    get_pass_contexts,
)
from obfuscator.vm.backend import VM_BACKENDS, unsupported_vm_options
from obfuscator.vm.targets.pass_requirements import PASS_REQUIREMENTS


OUTPUT = ROOT_DIR / "docs" / "configuration.md"

VM_DETAILS = """\
`vm_options.backend` selects only the VM runtime execution model, independently
from the build profile. Karity and classic use the current compiler, instruction
layout, serializer/blob protection, dispatcher selection, integrity checks, and
output pipeline. `karity` remains the implicit choice when the option is omitted.
`classic` uses direct register storage and straightforward opcode handlers;
`default` is an alias for `karity`, matching an omitted backend.
Older builds mapped `default` to `classic`; use explicit `classic` to preserve
that runtime when migrating. See [backend architecture and capabilities](backends.md).

`mov` is a supported release backend with a hybrid runtime. Use it with
`--profile fast-vm --vm-option backend=mov`. Integer ADD/SUB/MUL/UNM/MOD/IDIV,
BAND/BOR/BXOR/SHL/SHR/BNOT and EQ/LT/LE lower into nibble lookup microcode;
Signed MOD/IDIV use a shared 64-step restoring-division recipe with Lua floor
correction, integer wraparound and explicit zero-divisor errors. NOT and
expected-truth tests use boolean lookup after native-value classification.
Division skips leading zero nibbles using moves and a counter transition table,
so small operands do not execute all 64 restoring-division bit rounds.
Integer SHL/SHR use six lookup/MOV stages for distances 1, 2, 4, 8, 16 and 32.
Microcode computes count sign, unsigned magnitude, direction reversal and the
64-bit range check, including minimum-integer counts. HOST preparation supplies
encoded operands and opcode direction without decoding the count or computing
digit positions. Integral floats and numeric strings retain Lua coercion.
Float/float EQ/LT/LE bitcast binary64 values into encoded nibbles, then use
lookup-generated ordering keys, NaN classification and signed-zero equality.
Float UNM copies binary64 payload digits and toggles the sign nibble through XOR
lookup. Host bitcasts convert the input/output representation; no native unary
arithmetic executes on this path, including signed zeros, infinities and NaNs.
Mixed integer/float EQ/LT/LE build exact 80-bit ordering keys through lookup
normalization, with a shared exponent and 63 fraction bits. No integer-to-float
conversion occurs, preserving precision beyond 2^53 and at the signed 64-bit limits.
String equality uses encoded byte-list lookup regardless of locale. String LT/LE
use the same microcode under C/POSIX collation; other locales and unavailable
locale queries retain host ordering. The current locale is checked per operation.
Embedded NUL bytes remain ordinary bytes, distinct from list termination.
Constructing the input byte lists requires linear allocation per comparison.
This boundary preserves [Lua's locale-sensitive string ordering](https://www.lua.org/source/5.3/lvm.c.html).
String LEN counts byte-list nodes using lookup carry propagation. All-string
CONCAT uses indirect MOV stores to join private operand copies, then retains the
result as an immutable encoded byte list. Register copies can share that list;
later length/concatenation operations need no native-string materialization.
Native consumers decode the finished stream with string.char/table.concat.
Numeric coercion and __concat effects still use host execution, preserving
right-to-left concatenation and coroutine suspension. Table/userdata LEN remains
a host operation. These list operations require linear traversal/allocation.
TEST/TESTSET and JMP select microcode addresses, with captured locals closed
before scope-exiting jumps. Integer results retain encoded digit storage across MOV
operations. Other operations (including `/`, power, binary floating-point arithmetic, coercions,
metamethods and native calls) cross explicit Lua host boundaries. Original operand
words remain in the blob for those fallbacks. This is not literal MOV-only Lua.
MOV-only is the target, not the current completion status: binary floating-point
arithmetic, coercing/metamethod concatenation, locale-specific ordering and Lua object/call semantics
still use host execution. Native fallback traps in the regression suite verify
the implemented integer, boolean and all numeric comparison paths.
Host opcodes share one indirect function-table call, with shuffled entries and
a distinct XOR key per VM. Native arithmetic fallback also uses function lookup.
The host functions still contain inspectable Lua operations; dispatch indirection
does not turn those operations into lookup microcode. Per-frame handler closures
preserve recursion, coroutine suspension and return/tail-call packets, at the
cost of additional closure allocation.
Multiple MOV interpreters use independent instruction IDs and digit codebooks.
Prototypes follow the shared vm_count assignment and calls/upvalues/tail-call
transitions cross representations through Lua values. The versioned microcode
extension is covered by shared blob encryption and integrity binding, and is
generated after instruction relocation. Common arithmetic recipes are linked
once into each VM's tape and shared across prototypes; call frames keep private
scratch storage and continuation addresses.

MOV is a supported release configuration; its hybrid HOST boundaries remain
part of the documented implementation, not a claim of complete MOV-only execution.
Valid unsupported options are retained but ignored. Invalid names/types/ranges
still fail validation. CLI emits one stderr warning listing supplied unsupported
options, including inherited profile values; `--print-config` stdout remains JSON.
GUI disables unsupported controls for the selected backend, preserves their
values when switching backends, and reports ignored options after a build.
The same capability map drives GUI metadata, warnings and MOV build profiling.

MOV retains junk insertion, integrity constants, blob forms, source/output passes
and packing. Each VM uses its own fixed microcode dispatcher with randomized IDs;
dispatcher_type, dispatcher_target_hiding, fake_handlers, mutate_handlers and
Karity graph/state/representation controls do not apply. Legacy split/fuse/defer
and block variants are disabled. The mov_lowering profile entry lists unsupported
controls and reports effective VM counts, lowered sites, expanded/stored
micro-instructions, shared recipes and extension bytes. MOV release-check
validates shared source protections, VM count,
junk insertion, integrity and blob form, excluding unused legacy dispatcher/
handler and Karity graph options. Use `--profile high --vm-option backend=mov
--release-check` for the complete profile and release validation.
Lookup microcode adds runtime and output overhead; measure actual workloads.

The remaining implementation notes in this section describe Karity's hardened
runtime model. In classic mode, runtime graph execution, encoded/dynamic register
mapping, cross-instruction continuations, runtime polymorphism, and handler/block
semantic variants are disabled. Controls outside that runtime layer—including
current dispatchers, fake and mutated handlers, junk instructions, blob form,
VM count, target hiding, integrity protection, and output passes—remain active.
Release validation therefore checks shared protections for both modes and checks
graph/variant rates only for the Karity runtime that implements them.

Integer arithmetic, bitwise, shift, and unary handlers are generated from
build-specific DAG IR and compiled ahead of time into specialized straight-line
Lua handlers. Their semantic order is shuffled per build, and sparse opcode tags
resolve dense banks through two independently emitted XOR-share tables instead of
a central `selector -> obvious operation` map. Runtime state then chooses among
equivalent compiled variants.

Arithmetic occurrences carry compact descriptors (family id, site id, selector
seed, state key, and diffusion policy) and share a build-specific compiled family
pool. Results feed site state and selected global/cross-frame state on every active
occurrence; heavy family paths run on the first hit and at sparse state-dependent
intervals.

Register values remain virtualized across dispatch boundaries. Integers use
build-specific per-value affine encodings fragmented into additive shares; the
multiplier family is selected from slot and epoch state, while offsets and shares
are derived rather than stored as plaintext keys. Booleans and nil use affine
canonical tokens. Floats, strings, tables, functions, userdata, and threads use
affine handles into a frame value vault, so the register bank does not directly
contain those program values.

Each write selects a new representation epoch. Selected control and call edges
also rotate long-lived values by transforming both shares directly, without
materializing the program value. ADD, SUB, and UNM use encoded-domain affine
transforms when their operands are integer representations; unsupported dynamic
operations decode only their required operands into handler-local temporaries and
immediately re-encode their results.

Logical registers do not directly index their persistent representation tables.
Value shares, companion shares, epochs, and type tags use four independent
build-specific affine permutations over the physical slot domain. Frames carry a
mapping generation, and sparse call/control ticks migrate every represented slot
to a fresh generation through collision-free replacement tables. Thus a logical
register's payload and metadata neither share an index nor remain at stable
physical locations across a long-running frame.

Selected integer ADD, SUB, and UNM instructions can stop at an encoded pending
packet rather than writing their destination immediately. The packet snapshots
destination-domain partial shares without retaining source logical indices,
survives unrelated dispatches and continuation frames, and is completed in the
encoded domain only when a later consumer reads the logical destination. Pending
metadata uses a fifth independent physical permutation. Non-integer operands and
active semantic-graph occurrences fall back to immediate execution so Lua
metamethod timing and diffusion state remain unchanged.

At runtime, each execution derives a fresh nonce without consuming the program's
`math.random` stream. Every frame carries a rolling route state updated after
instruction decode from VM-internal state, instruction identity, mapping
generation, and representation epochs. Sparse route decisions choose equivalent
semantic, arithmetic, value, control, and delayed-materialization recipes, so the
same serialized program produces different microtraces across executions without
feeding unpredictable state into bytecode decryption.

Eligible straight-line basic-block chunks can also be cloned into independently
compiled physical lanes. Each lane receives its own opcode aliases and may choose
different split, fusion, graph, and delayed-materialization plans. A compact
runtime route instruction selects the lane from rolling execution state, and a
direct physical edge rejoins the canonical successor. Control-transfer, skip,
return, and LOADKX/EXTRAARG boundaries remain single-copy routing anchors so jump
targets, metamethod order, and continuation behavior stay stable.

VM-internal CALL, TAILCALL, and RETURN transitions use heap continuation frames
instead of recursively returning through the host Lua stack. Calls and returns pass
through build-specific bounded cyclic routing graphs compiled to shuffled Lua
labels, without runtime graph-node closures or context-table traversal.

Selected jump, loop, iterator, and vararg sites remove the packet key after
rebinding their control operands to live site state. The opening key is recomputed
from the occurrence descriptor and state mixed with the global diffusion value and
cross-frame ledger, so the operands cannot be consumed through a packet-local key.
Load, table access, table assignment, comparison, arithmetic, closure creation,
and vararg transfer semantics execute inside build-time compiled control and
semantic graphs where supported.

Generated VM output plans `function_obf`, `rename_obf`, `localize_globals`, and
the `string_obf`/`boolean_obf`/`number_obf` literal stages from one shared
Tree-sitter context when no structural rewrite invalidates it. Identifier and
literal replacements are merged by a structured emitter, while generated
literals remain typed for later stages. This preserves cross-pass layering such
as string-reconstruction operands flowing into number obfuscation without parsing and
rendering the expanded VM source after every pass.

Handler, arithmetic, semantic, call, control, and loop graph sources are inserted
before that VM-output pipeline, so generated backend identifiers and literals are
renamed, localized, obfuscated, and minified with the rest of the VM. Exact-width
integer regions remain typed but bypass numeric rewriting where changing the
literal representation would invalidate a compiled bitwise graph.

Build-specific error probes derive a source-line state without an explicit
expected-line comparison. The state participates in the VM blob key, integrity
constant programs, instruction routing, and semantic state.
Removing line metadata through stripped-bytecode rehosting therefore changes the
same runtime material used to decrypt and reconstruct protected values.
"""


def fmt_default(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return f"`{value}`"


def render_pass(name: str, info: dict) -> list[str]:
    contexts = " | ".join(get_pass_contexts(name))
    lines = [
        f"## {name}",
        "",
        f"**label:** {info['label']}",
        "",
        f"**group:** {info['group']} pass",
        "",
        f"**type:** {contexts}",
        "",
        PASS_DESCRIPTIONS.get(name, "No description available."),
        "",
    ]
    if name in PASS_REQUIREMENTS:
        requirement = PASS_REQUIREMENTS[name]
        capabilities = ", ".join(sorted(c.value for c in requirement.capabilities))
        lines.extend([f"**Target requirements:** {capabilities}; minimum compatibility "
                      f"`{requirement.minimum_compatibility.value}`.", ""])
    if name == "vm":
        lines.extend([VM_DETAILS, ""])
    if name == "rename_obf":
        lines.extend([
            "`rename_obf_options.seed` optionally shuffles the short-name alphabet.",
            "`rename_obf_options.readable` enables descriptive debug names (default: `false`).",
            "These options apply to source, VM output and packer output rename stages.",
            "",
        ])
    if name == "function_obf":
        lines.extend([
            "Source nested functions are selected from the initial AST and transformed",
            "bottom-up. Functions generated by `function_obf` or junk emitters are not",
            "part of that provenance set and are never recursively reprocessed.",
            "",
            "`function_obf_options.boundary_mode` accepts `mixed`, `split`, or `cff`",
            "(default: `mixed`). `function_obf_options.nested` enables recursive SOURCE",
            "nested-function transformation (default: `true`), and",
            "`function_obf_options.nested_max_depth` limits nesting expansion",
            "(default: `4`, valid range: `0..16`).",
            "",
            "`cff`, `junk`, `inline`, and `wrapper` are independently selectable",
            "boolean switches (all default to `true`). Inlining and compound-loop",
            "transforms run as components of the CFF rewrite. Source directives can",
            "override these options per function; see [selective protection](selective-obfuscation.md).",
            "",
            "Loop/compound transformation is controlled by `loop_split` (default:",
            "`true`) and `loop_unroll` (default: `true`). Static integer numeric-for",
            "loops unroll up to `loop_unroll_max_iterations` (default: `4`).",
            "Eligible loops choose unrolling with the seed-driven `loop_unroll_rate`",
            "(default: `0.65`); other cases fall back to body splitting.",
            "`loop_max_generated_blocks` (default: `64`),",
            "`loop_max_expansion_ratio` (default: `128.0`), and `loop_max_depth`",
            "(default: `3`) bound recursive compound expansion.",
            "Compiler budgets: `max_jump_instructions` defaults to `32767` (a quarter",
            "of Lua 5.1/5.3's signed jump domain), `max_function_instructions` to",
            "`65535` (including helper prototypes). `max_pass_instructions` defaults",
            "to `131071 + 8 * input bytecode instructions`. Override it with an integer.",
            "Large regions automatically use measured, cost-balanced helpers; budget",
            "pressure selects shared-decode CFF with less junk/dead-state density.",
            "All selected source blocks remain in CFF. One compact retry is allowed;",
            "an unsatisfiable budget produces a diagnostic instead of unlimited retries.",
            "Generated state/junk numbers share NumberObf's engine and carry origin",
            "spans through edits. Later NumberObf/Meme stages skip these expressions;",
            "source numbers retain their existing protection. `generated_number_max_chars`",
            "(default `192`) and `generated_number_max_operations` (default `3`, range `1..3`) bound",
            "the generated expressions. Hot states use one arithmetic layer and Lua",
            "5.1-compatible syntax. Profiling records native costs and protection adjustments.",
            "`reconstruction_group_size` (default `4`, range `1..8`) groups consecutive",
            "StringObf reconstruction statements into basic blocks. Joins/branches/returns",
            "remain boundaries, data dependencies and execution order stay intact, and",
            "all reconstruction operations remain in CFF. Profiling records coalesced states.",
            "",
        ])

    docs_path = info.get("docs")
    if docs_path:
        lines.extend([
            f"See [`{name}` design and implementation notes]({docs_path}) "
            "for architecture, trade-offs, and future work.",
            "",
        ])
        
    return lines


def render_vm_options() -> list[str]:
    lines = ["## vm_options", ""]
    for name, info in VM_OPTION_DOCS.items():
        lines.extend([f"### {name}", "", info["description"], ""])
        values = info.get("values")
        if values:
            lines.extend(["| Value | Description |", "|---|---|"])
            for value, description in values:
                lines.append(f"| `{value}` | {description} |")
            lines.append("")
        if "range" in info:
            lines.extend([f"range: {info['range']}", ""])
        lines.extend([f"default: {fmt_default(info['default'])}", "", "---", ""])
    return lines


def render() -> str:
    lines = [
        "<!-- generated by tools/generate_config_docs.py; do not edit by hand -->",
        "",
        "# configuration",
        "",
        "## table of contents",
        "- [selective protection](#selective-protection)",
        "- [literal_mosaic](#literal_mosaic)",
        "- [profiles](#profiles)",
        "- [target](#target)",
        "- [signature](#signature)",
        "- feature passes",
    ]
    for name in PASS_REGISTRY:
        lines.append(f"  - [{name}](#{name})")
    lines.append("- [vm_options](#vm_options)")
    for name in VM_OPTION_DOCS:
        lines.append(f"  - [{name}](#{name})")

    lines.extend([
        "",
        "## selective protection",
        "Use `selection_modes` to choose `all` (the default for enabled passes) or",
        "`marked` for `string_obf`, `number_obf`, `boolean_obf`, `table_obf`,",
        "`function_obf`, `meme_strings`, and `vm`. Source macros/directives can enable an absent",
        "pass in marked mode. `selection_profiles` supplies named VM option presets",
        "in flat configs; named input profiles are also available to VM directives.",
        "Regions support complete sibling statements, partial function protection,",
        "and nested native exclusions. Selective VM boundaries require Lua 5.3.",
        "Selected VM regions with equal effective options share one runtime initialization.",
        "See the [selective protection guide](selective-obfuscation.md) and",
        "`config.selective.example.json` for syntax, precedence and limitations.",
        "`--selection-report PATH` writes original-line application results as JSON.",
        "",
        "## literal_mosaic",
        "`literal_mosaic` configures the internal shared generator; it is not a pass.",
        "It reuses NumberObf/MemeStrings only when those passes are enabled in the",
        "actual source or output pipeline, and respects marked source regions.",
        "FunctionObf's existing numeric and compiler budgets remain authoritative.",
        "Source NumberObf and the original MemeStrings replacement rate (0.35) are unchanged.",
        "",
        "| Option | Default | Values |",
        "|---|---|---|",
        "| `style` | `balanced` | `compact`, `balanced`, `exotic` |",
        "| `cost` | `auto` | `auto`, `low`, `medium`, `high` |",
        "| `generated_meme_rate` | `0.15` | 0 through 1, generated constants only |",
        "| `max_chars` | `192` | 64 through 4096, expression characters |",
        "| `max_operations` | `12` | 0 through 32, expression operations |",
        "| `diversity_metrics` | `false` | boolean; profiling also enables metrics |",
        "",
        "Style and cost are independent. Hot paths use at most three operations",
        "with `auto`; each caller can impose a smaller limit. Detailed AST metrics",
        "sample at most 128 expressions per phase/strategy without consuming random",
        "state. Counts describe visual variety, not security. See [Literal Mosaic](literal-mosaic.md).",
        "",
        "## profiles",
        "The default config uses named profiles so test and release builds can switch",
        "without manually editing pass lists.",
        "",
        "```bash",
        "python main.py input.lua --profile dev",
        "python main.py input.lua --profile fast-vm",
        "python main.py input.lua --profile high",
        "python main.py input.lua --profile max",
        "python main.py input.lua --profile max --release-check",
        "```",
        "",
        "`high` is the strongest preset intended for practical use. It enables the full",
        "source protection and packing stack with two diversified VMs while avoiding",
        "the most explosive output-pass combinations used by `max`.",
        "",
        "`max` is an experimental research profile for extreme protection combinations.",
        "It has no build-time or output-size target and is not intended for routine",
        "production use. Prefer `high`, `fast-vm`, or a tuned custom profile for practical",
        "builds.",
        "`--release-check` validates release-safety constraints; it does not make `max`",
        "the recommended production profile.",
        "",
        "`--seed` is for reproducible test builds. `--release-check` rejects seeded",
        "builds and weak VM settings before writing release output.",
        "",
        "## target",
        "",
        "`target.lua_version` selects `5.3` (default) or experimental `5.1`;",
        "`target.environment` selects `standalone` (default) or `cheatengine`.",
        "The VM backend remains in `vm_options.backend` and is independent of both.",
        "",
        "`target.compatibility` accepts `portable`, `runtime_specific` (default),",
        "or `binary_specific`, in increasing order of permitted dependencies.",
        "VM and packer function-dump integrity requires a compatible runtime dump ABI,",
        "so Portable rejects those stages. It does not silently weaken their integrity.",
        "Current integrity does not fingerprint executable files; binary-specific host",
        "references are a separate materialization feature.",
        "`target.disabled_capabilities` can remove APIs unavailable in an embedded host.",
        "`target.runtime_abi` is optional descriptive metadata, not an ABI verifier.",
        "",
        "CLI overrides are `--lua-version`, `--target-environment`, and `--compatibility`.",
        "The GUI exposes the same choices in Lua toolchain. Selecting Cheat Engine",
        "declares host capabilities; it does not automatically enable native protection.",
        "`target.host_images` is an optional list of executable/DLL paths (`--host-image`",
        "can be repeated). It requires VM, Cheat Engine capabilities and Binary specific.",
        "Matching immutable byte strings are read from the selected loaded modules;",
        "other constants retain existing serialization. The resolver uses module RVAs",
        "and excludes writable, executable, relocated and import-table storage.",
        "See [host image materialization](host-image-materialization.md) for validation limits.",
        "",
        "Lua 5.1 supports explicit matching executables or a library; otherwise it uses Lupa.",
        "Packing and source passes requiring native bit operators or `_ENV` are",
        "rejected before compilation. VM output passes run before target adaptation",
        "and must emit syntax compatible with the final target. See [Lua targets](lua-targets.md).",
        "",
        "## signature",
        "",
        "`signature.mode` accepts `default`, `none`, `fake`, `generated`, or `custom`.",
        "Fake mode combines the selected `well_known` and `generated` candidate pools;",
        "generated mode selects only from generator patterns. Patterns support `{name}`",
        "`{version}`, and `{hash}`. Hashes are random 64-character lowercase hexadecimal",
        "strings, reproducible with the same random seed. Repeated `{hash}` placeholders",
        "in one pattern share a value; the selected signature stays fixed for the pipeline.",
        "`signature.custom` and `signature.fake.custom_pattern` contain",
        "comment text only: Lua comment delimiters are removed before rendering.",
        "",
        "```json",
        '{"signature": {',
        '  "mode": "fake",',
        '  "fake": {',
        '    "sources": ["well_known", "generated"],',
        '    "generator_patterns": ["Protected with {name} V{version}"],',
        '    "custom_pattern": "{name}\\nVersion {version}"',
        '  },',
        '  "custom": ""',
        '}}',
        "```",
        "",
    ])

    for name, info in PASS_REGISTRY.items():
        lines.extend(render_pass(name, info))
    lines.extend(render_vm_options())
    return "\n".join(lines).rstrip() + "\n"


def backend_document() -> tuple[Path, str]:
    path = ROOT_DIR / "docs/backends.md"
    text = path.read_text(encoding="utf-8")
    start, end = "<!-- BEGIN BACKEND OPTIONS -->", "<!-- END BACKEND OPTIONS -->"
    assert text.count(start) == text.count(end) == 1
    rows = ["| Option | Karity | Classic | MOV |", "|---|---|---|---|"]
    for name in VM_OPTION_DOCS:
        cells = ["No" if name in unsupported_vm_options(backend) else "Yes" for backend in VM_BACKENDS]
        rows.append(f"| `{name}` | " + " | ".join(cells) + " |")
    before, tail = text.split(start)
    _, after = tail.split(end)
    return path, before + start + "\n\n" + "\n".join(rows) + "\n\n" + end + after


def main() -> int:
    parser = argparse.ArgumentParser(description="generate docs/configuration.md")
    parser.add_argument("--check", action="store_true", help="fail if the document is not up to date")
    args = parser.parse_args()

    for info in PASS_REGISTRY.values():
        if info.get("docs") and not (ROOT_DIR / "docs" / info["docs"]).is_file():
            raise ValueError(f"missing pass documentation: {info['docs']}")
    content = render()
    backend_path, backend_content = backend_document()
    if args.check:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
        if current != content:
            print(f"{OUTPUT} is out of date", file=sys.stderr)
            return 1
        if backend_path.read_text(encoding="utf-8") != backend_content:
            print(f"{backend_path} capability table is out of date", file=sys.stderr)
            return 1
        return 0

    OUTPUT.write_text(content, encoding="utf-8")
    backend_path.write_text(backend_content, encoding="utf-8")
    print(f"wrote {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
