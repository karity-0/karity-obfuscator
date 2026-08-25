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


OUTPUT = ROOT_DIR / "docs" / "configuration.md"

VM_DETAILS = """\
Integer arithmetic, bitwise, shift, and unary handlers are generated from
build-specific DAG IR and compiled ahead of time into specialized straight-line
Lua handlers. Sparse selectors choose the compiled handler from the VM id,
instruction position, and accumulated diffusion state.

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
    if name == "vm":
        lines.extend([VM_DETAILS, ""])
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
        "- [profiles](#profiles)",
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
        "## profiles",
        "The default config uses named profiles so test and release builds can switch",
        "without manually editing pass lists.",
        "",
        "```bash",
        "python main.py input.lua --profile dev",
        "python main.py input.lua --profile fast-vm",
        "python main.py input.lua --profile max",
        "python main.py input.lua --profile max --release-check",
        "```",
        "",
        "`--seed` is for reproducible test builds. `--release-check` rejects seeded",
        "builds and weak VM settings before writing release output.",
        "",
        "## signature",
        "",
        "`signature.mode` accepts `default`, `none`, `fake`, `generated`, or `custom`.",
        "Fake mode combines the selected `well_known` and `generated` candidate pools;",
        "generated mode selects only from generator patterns. Patterns support `{name}`",
        "and `{version}`. `signature.custom` and `signature.fake.custom_pattern` contain",
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


def main() -> int:
    parser = argparse.ArgumentParser(description="generate docs/configuration.md")
    parser.add_argument("--check", action="store_true", help="fail if the document is not up to date")
    args = parser.parse_args()

    content = render()
    if args.check:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
        if current != content:
            print(f"{OUTPUT} is out of date", file=sys.stderr)
            return 1
        return 0

    OUTPUT.write_text(content, encoding="utf-8")
    print(f"wrote {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
