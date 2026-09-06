from __future__ import annotations

import random
import re
import string
from dataclasses import dataclass

from .base import PostPass


DEFAULT_SIGNATURE = "-- obfuscated using karity obfuscator!\n"
DEFAULT_GENERATOR_PATTERNS = (
    "Obfuscated using {name} obfuscator!",
    "Protected with {name} V{version}",
    "{name} Lua Protection\nBuild V{version}",
    "Secured by {name}\nVersion: {version}",
)

WELL_KNOWN_SIGNATURES = (
    ("AztupBrew(Fork of IronBrew2): obfuscation; Version 2.7.2", "block"),
    ("IronBrew:tm: obfuscation; Version 2.7.2", "block"),
    (
    r""".____                  ________ ___.    _____                           __
|    |    __ _______   \_____  \\_ |___/ ____\_ __  ______ ____ _____ _/  |_  ___________
|    |   |  |  \__  \   /   |   \| __ \   __\  |  \/  ___// ___\\__  \\   __\/  _ \_  __ \
|    |___|  |  // __ \_/    |    \ \_\ \  | |  |  /\___ \\  \___ / __ \|  | (  <_> )  | \/
|_______ \____/(____  /\_______  /___  /__| |____//____  >\___  >____  /__|  \____/|__|
        \/          \/         \/    \/                \/     \/     \/
         \_Welcome to LuaObfuscator.com   (Alpha 0.10.9) ~  Much Love, Ferib""",
    "block"
    ),
    ("This file was generated using Luraph Obfuscator v3", "line"),

    ("This file was protected using Luraph Obfuscator v14.5", "block"),

    ("Protected by Mnx Obfuscator | Public Enemy", "line"),

    ("This file was protected with MoonSec V3", "line"),

    ("This script was generated using the MoonVeil Obfuscator v1.4.5", "line"),

    ("v1.0.0 https://no/wearedevs.lua/obfuscator", "line"),

    ("This file was obfuscated using PSU Obfuscator 4.0.A", "line"),

    ("Synapse Xen v1.1.2\nVM Hash: 1a23bafcf4d256aecd1204a7df4d22a1b4123521abbcfddea8ed0bc12425", "block"),

    ("Obfuscated With Xemon", "line")

)

_COMMENT_TOKEN_RE = re.compile(r"--(?:\[(=*)\[)?|\](=*)\]")
_PLACEHOLDERS = {"name", "version"}


def strip_comment_tokens(value: str) -> str:
    """Remove Lua line/long-comment delimiters from user-controlled text."""
    if not isinstance(value, str):
        return ""
    return _COMMENT_TOKEN_RE.sub("", value).strip()


def sanitize_generator_pattern(value: str) -> str:
    value = strip_comment_tokens(value)
    formatter = string.Formatter()
    try:
        fields = {
            field_name
            for _, field_name, _, _ in formatter.parse(value)
            if field_name is not None
        }
    except ValueError:
        return ""
    if not fields.issubset(_PLACEHOLDERS):
        return ""
    return value


def _generated_compound_name() -> str:
    prefixes = (
        "Astra", "Nebula", "Eclipse", "Phantom", "Vanta", "Zenith", "Cipher",
        "Nova", "Lunar", "Solar", "Void", "Shadow", "Spectra", "Nexus",
        "Vertex", "Quantum", "Arcane", "Obsidian", "Crimson", "Silent",
        "Hyper", "Omega", "Delta", "Alpha", "Vector", "Flux", "Hex",
        "Aether", "Nyx", "Onyx", "Zero", "Dark", "Night", "Ghost",
        "Iron", "Black", "Crystal", "Mystic", "Chaos", "Static",
        "Polar", "Inferno", "Frost", "Storm", "Titan", "Cosmic",
        "Neon", "Prism", "Echo", "Mirage", "Rift", "Pulse",
        "Astro", "Dragon", "Turtle", "Unknown", "Binary", "Mythos"
    )

    cores = (
        "Guard", "Crypt", "Shield", "Lock", "Veil", "Sec", "Brew",
        "Protect", "Armor", "Vault", "Core", "Forge", "Mask", "Hide",
        "Obfus", "Scramble", "Morph", "Shift", "Cloak", "Wrap",
        "Byte", "Code", "Script", "Lua", "VM", "Virtual", "Hex",
        "Cipher", "Encode", "Shadow", "Ghost", "Barrier", "Wall",
        "Kernel", "Matrix", "Engine", "Layer", "Node", "Frame",
        "Pulse", "Flux", "Nexus", "Sentinel", "Aegis", "Seal",
        "Mist", "Brew", "Guard", "Protector", "Obfuscator",
        "Defender", "Packer", "Pack", "Machine", "Obfuscation"
    )

    suffixes = (
        "", "", "",
        "X", "X2", "X3", "Pro", "Plus", "Prime", "Ultra",
        "Labs", "Lab", "VM", "Lua", "Sec", "Dev", "Core",
        "NX", "EX", "RX", "VX", "IX", "ium", "ify", "Ware",
        "Works", "Tech", "Project", "Engine", "V2", "V3",
        "Service"
    )
    return f"{random.choice(prefixes)}{random.choice(cores)}{random.choice(suffixes)}"


def _generated_syllable_name() -> str:
    """Build a pronounceable brand-like name from 2-4 pseudo-syllables."""
    onsets = (
        "b", "c", "d", "f", "g", "h", "j", "k", "l", "m", "n",
        "p", "qu", "r", "s", "t", "v", "w", "x", "z", "br", "cr",
        "dr", "gr", "kr", "pr", "st", "tr", "vr",
    )
    nuclei = (
        "a", "e", "i", "o", "u", "ae", "ai", "ia", "io", "oa",
        "oi", "ou", "y",
    )
    codas = (
        "", "", "", "n", "r", "s", "x", "l", "m", "th", "v",
    )
    suffixes = ("", "", "", "X", "Labs", "Sec", "VM", "ium", "ify")
    syllable_count = random.choices((2, 3, 4), weights=(5, 4, 1), k=1)[0]
    stem = "".join(
        f"{random.choice(onsets)}{random.choice(nuclei)}{random.choice(codas)}"
        for _ in range(syllable_count)
    )
    return f"{stem.capitalize()}{random.choice(suffixes)}"


def _generated_name() -> str:
    # Keep both families equally likely regardless of their internal pool sizes.
    if random.random() < 0.5:
        return _generated_compound_name()
    return _generated_syllable_name()


def _generated_version() -> str:
    forms = (
        lambda: str(random.randint(2, 6)),
        lambda: f"{random.randint(1, 5)}.{random.randint(0, 9)}",
        lambda: f"{random.randint(1, 4)}.{random.randint(0, 9)}.{random.randint(0, 9)}",
    )
    return random.choice(forms)()


def _render_comment(text: str, style: str = "auto") -> str:
    text = strip_comment_tokens(text)
    if not text:
        return ""
    if style == "auto":
        style = random.choice(("line", "block")) if "\n" in text else "line"
    if style == "block":
        return f"--[[\n{text}\n]]\n"
    return "".join(f"-- {line}\n" if line else "--\n" for line in text.splitlines())


@dataclass(frozen=True)
class SignatureOptions:
    mode: str = "default"
    fake_sources: tuple[str, ...] = ("well_known", "generated")
    generator_patterns: tuple[str, ...] = DEFAULT_GENERATOR_PATTERNS
    custom_pattern: str = ""
    custom: str = ""

    @classmethod
    def from_config(cls, config: dict | None) -> "SignatureOptions":
        config = config if isinstance(config, dict) else {}
        fake = config.get("fake") if isinstance(config.get("fake"), dict) else {}
        sources = fake.get("sources", ["well_known", "generated"])
        patterns = fake.get("generator_patterns", list(DEFAULT_GENERATOR_PATTERNS))
        if not isinstance(sources, list):
            sources = []
        if not isinstance(patterns, list):
            patterns = []
        return cls(
            mode=config.get("mode", "default"),
            fake_sources=tuple(item for item in sources if isinstance(item, str)),
            generator_patterns=tuple(item for item in patterns if isinstance(item, str)),
            custom_pattern=(
                fake.get("custom_pattern", config.get("custom_pattern", ""))
                if isinstance(fake.get("custom_pattern", config.get("custom_pattern", "")), str)
                else ""
            ),
            custom=config.get("custom", "") if isinstance(config.get("custom", ""), str) else "",
        )


class OutputSignaturePass(PostPass):
    """Select and prepend exactly one final output signature."""

    def __init__(self, options: SignatureOptions | dict | None = None):
        if isinstance(options, SignatureOptions):
            self.options = options
        else:
            self.options = SignatureOptions.from_config(options)
        self._prefix = self._select_prefix()

    @property
    def prefix(self) -> str:
        return self._prefix

    def _generated_candidates(self) -> list[str]:
        patterns = [sanitize_generator_pattern(item) for item in self.options.generator_patterns]
        custom_pattern = sanitize_generator_pattern(self.options.custom_pattern)
        if custom_pattern:
            patterns.append(custom_pattern)
        patterns = [item for item in patterns if item]
        if not patterns:
            patterns = list(DEFAULT_GENERATOR_PATTERNS)
        return [
            _render_comment(pattern.format(
                name=_generated_name(),
                version=_generated_version(),
            ))
            for pattern in patterns
        ]

    def _select_prefix(self) -> str:
        mode = self.options.mode
        if mode == "none":
            return ""
        if mode == "default":
            return DEFAULT_SIGNATURE
        if mode == "custom":
            return _render_comment(self.options.custom, "line")
        if mode == "generated":
            return random.choice(self._generated_candidates())
        if mode != "fake":
            return DEFAULT_SIGNATURE

        candidates: list[str] = []
        if "well_known" in self.options.fake_sources:
            candidates.extend(_render_comment(text, style) for text, style in WELL_KNOWN_SIGNATURES)
        if "generated" in self.options.fake_sources:
            candidates.extend(self._generated_candidates())
        return random.choice(candidates) if candidates else ""

    def run(self, script: str) -> str:
        if not self.prefix:
            return script
        if script.startswith(self.prefix):
            return script
        if script.startswith("#!"):
            line_end = script.find("\n")
            if line_end >= 0:
                return f"{script[:line_end + 1]}{self.prefix}{script[line_end + 1:]}"
        return f"{self.prefix}{script}"
