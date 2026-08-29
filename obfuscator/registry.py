"""
패스 레지스트리.

main.py / GUI / vm_pass.py 의 _obfuscate_vm_output 에서
모두 이 레지스트리를 통해 패스를 이름으로 선택하도록 통일한다.

패스 추가 시 여기 한 줄만 등록하면
- CLI (--passes)
- GUI (체크박스)
- VM output 재난독화 (vm_output_passes)
모두에서 자동으로 사용 가능해진다.
"""
from __future__ import annotations

import re

from .vm import VMPass
from .vm.backend import normalize_vm_backend
from .passes.output_signature import (
    DEFAULT_GENERATOR_PATTERNS,
    sanitize_generator_pattern,
    strip_comment_tokens,
)

from .passes import (
    StringEncodePass,
    StringObfuscationPass,
    NumberObfuscationPass,
    BooleanObfuscationPass,
    TableObfuscationPass,
    FunctionObfuscationPass,
    RenameObfuscationPass,
    LocalizeGlobalsPass,
    RemoveCommentPass,
    MinifyPass,
    AntiDebugPass,
    AntiDecompilePass,
    PackerPass,
    OutputSignaturePass,
)


PASS_REGISTRY: dict[str, dict] = {
    "remove_comment": {
        "cls": RemoveCommentPass,
        "label": "Remove Comment",
        "group": "pre",
    },
    "string_encode": {
        "cls": StringEncodePass,
        "label": "Encode String",
        "group": "base",
    },
    "string_obf": {
        "cls": StringObfuscationPass,
        "label": "String Obfuscation",
        "group": "base",
    },
    "boolean_obf": {
        "cls": BooleanObfuscationPass,
        "label": "Boolean Obfuscation",
        "group": "base",
    },
    "number_obf": {
        "cls": NumberObfuscationPass,
        "label": "Number Obfuscation",
        "group": "base",
        "docs": "passes/numberObfuscation.md"
    },
    "table_obf": {
        "cls": TableObfuscationPass,
        "label": "Table Obfuscation",
        "group": "base",
    },
    "function_obf": {
        "cls": FunctionObfuscationPass,
        "label": "Function Obfuscation",
        "group": "base",
    },
    "rename_obf": {
        "cls": RenameObfuscationPass,
        "label": "Rename Obfuscation",
        "group": "base",
    },
    "localize_globals": {
        "cls": LocalizeGlobalsPass,
        "label": "Localize Globals",
        "group": "base",
    },
    "minify": {
        "cls": MinifyPass,
        "label": "Minify",
        "group": "post",
    },
    "vm": {
        "cls": VMPass,
        "label": "VM",
        "group": "post",
    },
    "anti_debug": {
        "cls": AntiDebugPass,
        "label": "Anti-Debug Wrapper",
        "group": "pre",
    },
    "anti_decompile": {
        "cls": AntiDecompilePass,
        "label": "Anti-Decompile (unluac trap)",
        "group": "base",
    },
    "pack": {
        "cls": PackerPass,
        "label": "Packer (deflate + load)",
        "group": "post",
    },
}


CONFIG_PASS_LISTS = ("passes", "vm_output_passes", "packer_output_passes")
VALID_DISPATCHERS = {"ifelseif", "tailcall", "table", "bsearch", "mixed"}
VALID_BLOB_FORMS = {"string", "table", "numeric", "random"}
OUTPUT_PASS_EXCLUDES = {"vm", "pack"}
VALID_SIGNATURE_MODES = {"default", "none", "fake", "generated", "custom"}
VALID_SIGNATURE_SOURCES = {"well_known", "generated"}

PASS_DESCRIPTIONS = {
    "remove_comment": "Removes comments from the source code before AST parsing.",
    "string_encode": "Encodes string literals.",
    "string_obf": "Obfuscates string literals.",
    "boolean_obf": "Obfuscates boolean literals.",
    "number_obf": "Obfuscates number literals.",
    "table_obf": "Obfuscates table variables.",
    "function_obf": "Obfuscates functions using control-flow flattening and junk blocks.",
    "rename_obf": "Renames local identifiers.",
    "localize_globals": "Converts global variable accesses to local aliases where possible.",
    "minify": "Reduces script size by removing unnecessary whitespace.",
    "vm": "Virtualizes Lua bytecode using the custom Lua 5.3 VM.",
    "anti_debug": "Inserts anti-debugging checks.",
    "anti_decompile": "Adds source-level traps that make decompiler output less useful.",
    "pack": "Compresses and wraps the final output in a self-extracting loader.",
}

VM_OPTION_DOCS = {
    "backend": {
        "description": "VM runtime execution model. Missing values select the current karity runtime.",
        "default": "karity",
        "values": [
            ("karity", "hardened graph and encoded-register runtime"),
            ("classic", "direct-register and direct-handler runtime on the current VM pipeline"),
            ("default", "compatibility alias for classic"),
        ],
    },
    "dispatcher_type": {
        "description": "VM dispatcher shape.",
        "default": "ifelseif",
        "values": [
            ("ifelseif", "if/elseif chain dispatcher"),
            ("tailcall", "function table + tail-call dispatcher"),
            ("table", "alias for the function-table tail-call dispatcher"),
            ("bsearch", "nested binary-search if/else tree over the opcode"),
            ("splitN", "split handlers across N smaller if/elseif dispatcher functions, for example split4"),
            ("bsplitN", "split handlers across N smaller binary-search dispatcher functions, for example bsplit6"),
            ("mixed", "randomly choose a dispatcher per VM"),
        ],
    },
    "dispatcher_target_hiding": {
        "description": "Mask fixed virtual-opcode targets and couple equality dispatch to live VM state.",
        "default": False,
    },
    "semantic_state_threading": {
        "description": "Thread source-semantic instruction and value state through register representations, calls, and VM runtime state.",
        "default": False,
    },
    "argument_virtualization": {
        "description": "Shuffle, pad, and state-mask VM call arguments instead of passing sequential argument arrays.",
        "default": False,
    },
    "upvalue_virtualization": {
        "description": "Store closed upvalues as affine shares and hidden reference-vault handles.",
        "default": False,
    },
    "table_virtualization": {
        "description": "Lower VM-created tables into split shadow storage until they cross a native boundary.",
        "default": False,
    },
    "branch_virtualization": {
        "description": "Seal comparison results in live-state control packets before selecting VM branches.",
        "default": False,
    },
    "blob_form": {
        "description": "How the encrypted bytecode blob is stored in the output.",
        "default": "random",
        "values": [
            ("string", "single base36 string literal"),
            ("table", "base36 blob split into scrambled string-table chunks"),
            ("numeric", "scrambled table of 32-bit integers rebuilt at runtime"),
            ("random", "randomly choose per obfuscation run"),
        ],
    },
    "vm_count": {
        "description": "Number of independent VM interpreters. Higher values increase diversity and file size.",
        "default": 1,
    },
    "fake_handlers": {
        "description": "Insert unreachable fake opcode handlers.",
        "default": True,
    },
    "mutate_handlers": {
        "description": "Apply control-flow and junk mutations to VM handlers.",
        "default": True,
    },
    "junk_instructions": {
        "description": "Insert junk virtual instructions.",
        "default": True,
    },
    "junk_rate": {
        "description": "Probability of inserting junk virtual instructions.",
        "default": 0.15,
        "range": "0.0 to 1.0",
    },
    "integrity_constants": {
        "description": "Encode selected integer constants as VM integrity expressions.",
        "default": False,
    },
    "integrity_constant_rate": {
        "description": "Probability that an eligible integer constant uses an integrity expression.",
        "default": 0.25,
        "range": "0.0 to 1.0",
    },
    "graph_execution_rate": {
        "description": "Fraction of VM sites that execute heavy compiled handlers and cross-frame diffusion.",
        "default": 0.1,
        "range": "0.0 to 1.0",
    },
    "cross_instruction_rate": {
        "description": "Fraction of eligible ADD, SUB, and UNM instructions emitted as lazy producers whose encoded result is materialized by a later consumer.",
        "default": 0.2,
        "range": "0.0 to 1.0",
    },
    "runtime_polymorphism_rate": {
        "description": "Fraction of eligible VM execution sites whose equivalent microtrace recipe is selected from a per-execution rolling route state.",
        "default": 0.2,
        "range": "0.0 to 1.0",
    },
    "runtime_trace": {
        "description": "Emit the final runtime route hash to stderr for diagnostics. Keep disabled in normal and release builds.",
        "default": False,
    },
    "block_variant_rate": {
        "description": "Fraction of eligible straight-line basic-block chunks cloned into independently compiled runtime-selectable variants.",
        "default": 0.08,
        "range": "0.0 to 1.0",
    },
    "block_variant_count": {
        "description": "Number of physical variants emitted for each selected basic-block chunk.",
        "default": 3,
        "range": "2 to 4",
    },
    "block_variant_max_instructions": {
        "description": "Maximum original instruction count in one runtime-polymorphic block chunk.",
        "default": 6,
        "range": "2 to 32",
    },
    "helper_variant_count": {
        "description": "Independent build-time implementations emitted per hot VM helper.",
        "default": 3,
        "range": "1 to 4",
    },
    "helper_diversity_rate": {
        "description": "Fraction of hot helper call sites wired to a non-baseline per-VM implementation.",
        "default": 0.35,
        "range": "0.0 to 1.0",
    },
    "semantic_diversity_rate": {
        "description": "Fraction of eligible opcode aliases lowered without the common semantic graph entry point.",
        "default": 0.35,
        "range": "0.0 to 1.0",
    },
}


class ConfigError(ValueError):
    pass


class ReleaseCheckError(ValueError):
    pass


def get_pass_names(group: str | None = None) -> list[str]:
    """그룹별 패스 이름 목록. group=None이면 전체."""
    if group is None:
        return list(PASS_REGISTRY.keys())
    return [name for name, info in PASS_REGISTRY.items() if info["group"] == group]


def get_pass_contexts(name: str) -> list[str]:
    if name in OUTPUT_PASS_EXCLUDES:
        return ["passes"]
    return list(CONFIG_PASS_LISTS)


def get_profile_names(config: dict) -> list[str]:
    profiles = config.get("profiles")
    if not isinstance(profiles, dict):
        return []
    return list(profiles.keys())


def resolve_config_profile(config: dict, profile_name: str | None = None) -> dict:
    """Return the selected profile config. Legacy flat configs still work."""
    if not isinstance(config, dict):
        raise ConfigError("config root must be an object")

    profiles = config.get("profiles")
    if profiles is None:
        if profile_name:
            raise ConfigError("--profile was given, but this config has no profiles")
        resolved = dict(config)
        validate_config(resolved)
        return resolved

    if not isinstance(profiles, dict) or not profiles:
        raise ConfigError("'profiles' must be a non-empty object")

    selected = profile_name or config.get("profile")
    if not selected:
        raise ConfigError("profile config requires a top-level 'profile' value or --profile")
    if selected not in profiles:
        known = ", ".join(sorted(profiles))
        raise ConfigError(f"unknown profile '{selected}'. available profiles: {known}")
    if not isinstance(profiles[selected], dict):
        raise ConfigError(f"profile '{selected}' must be an object")

    common = {
        key: value
        for key, value in config.items()
        if key not in ("profile", "profiles")
    }
    resolved = {**common, **profiles[selected]}
    resolved["_profile"] = selected
    validate_config(resolved)
    return resolved


def validate_config(config: dict) -> None:
    for key in CONFIG_PASS_LISTS:
        value = config.get(key, [])
        if not isinstance(value, list) or not all(isinstance(name, str) for name in value):
            raise ConfigError(f"'{key}' must be a list of pass names")

        unknown = [name for name in value if name not in PASS_REGISTRY]
        if unknown:
            known = ", ".join(get_pass_names())
            raise ConfigError(f"unknown pass in '{key}': {', '.join(unknown)}. known passes: {known}")

    _reject_nested_output_passes(config, "vm_output_passes")
    _reject_nested_output_passes(config, "packer_output_passes")
    _validate_vm_options(config.get("vm_options", {}))
    _validate_signature(config.get("signature", {}))


def validate_release_config(config: dict) -> None:
    validate_config(config)
    errors: list[str] = []
    passes = config.get("passes", [])
    vm_options = config.get("vm_options", {})
    backend = normalize_vm_backend(vm_options.get("backend"))

    required_passes = ("vm", "anti_debug", "anti_decompile")
    for name in required_passes:
        if name not in passes:
            errors.append(f"passes must include '{name}'")

    vm_count = vm_options.get("vm_count", 1)
    if not isinstance(vm_count, int) or isinstance(vm_count, bool) or vm_count < 2:
        errors.append("vm_options.vm_count should be >= 2 for release builds")

    for key in ("fake_handlers", "mutate_handlers", "junk_instructions"):
        if vm_options.get(key) is not True:
            errors.append(f"vm_options.{key} must be true")

    if float(vm_options.get("junk_rate", 0.0)) <= 0.0:
        errors.append("vm_options.junk_rate should be > 0.0")

    if vm_options.get("integrity_constants") is not True:
        errors.append("vm_options.integrity_constants must be true")

    if float(vm_options.get("integrity_constant_rate", 0.0)) <= 0.0:
        errors.append("vm_options.integrity_constant_rate should be > 0.0")

    if backend == "karity":
        if float(vm_options.get("graph_execution_rate", 0.0)) <= 0.0:
            errors.append("vm_options.graph_execution_rate should be > 0.0")

        if float(vm_options.get("cross_instruction_rate", 0.0)) <= 0.0:
            errors.append("vm_options.cross_instruction_rate should be > 0.0")

        if float(vm_options.get("runtime_polymorphism_rate", 0.0)) <= 0.0:
            errors.append("vm_options.runtime_polymorphism_rate should be > 0.0")

    if vm_options.get("runtime_trace") is True:
        errors.append("vm_options.runtime_trace must be false for release builds")

    if backend == "karity":
        if float(vm_options.get("block_variant_rate", 0.0)) <= 0.0:
            errors.append("vm_options.block_variant_rate should be > 0.0")

        if int(vm_options.get("helper_variant_count", 0)) < 2:
            errors.append("vm_options.helper_variant_count should be >= 2")

        if float(vm_options.get("helper_diversity_rate", 0.0)) <= 0.0:
            errors.append("vm_options.helper_diversity_rate should be > 0.0")

        if float(vm_options.get("semantic_diversity_rate", 0.0)) <= 0.0:
            errors.append("vm_options.semantic_diversity_rate should be > 0.0")

        if int(vm_options.get("block_variant_count", 0)) < 2:
            errors.append("vm_options.block_variant_count should be >= 2")

    if vm_options.get("blob_form") != "random":
        errors.append("vm_options.blob_form must be 'random'")

    if vm_options.get("dispatcher_type") != "mixed":
        errors.append("vm_options.dispatcher_type should be 'mixed'")

    if errors:
        raise ReleaseCheckError("release-check failed:\n- " + "\n- ".join(errors))


def _reject_nested_output_passes(config: dict, key: str) -> None:
    nested = [name for name in config.get(key, []) if name in OUTPUT_PASS_EXCLUDES]
    if nested:
        raise ConfigError(f"'{key}' cannot contain post-build passes: {', '.join(nested)}")


def _validate_vm_options(options: dict) -> None:
    if not isinstance(options, dict):
        raise ConfigError("'vm_options' must be an object")

    try:
        normalize_vm_backend(options.get("backend"))
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc

    dispatcher = options.get("dispatcher_type")
    if dispatcher is not None:
        is_split = isinstance(dispatcher, str) and re.fullmatch(r"b?split[1-9][0-9]*", dispatcher)
        if dispatcher not in VALID_DISPATCHERS and not is_split:
            values = ", ".join(sorted(VALID_DISPATCHERS)) + ", splitN, bsplitN"
            raise ConfigError(f"invalid vm_options.dispatcher_type '{dispatcher}'. expected: {values}")

    blob_form = options.get("blob_form")
    if blob_form is not None and blob_form not in VALID_BLOB_FORMS:
        values = ", ".join(sorted(VALID_BLOB_FORMS))
        raise ConfigError(f"invalid vm_options.blob_form '{blob_form}'. expected: {values}")

    vm_count = options.get("vm_count")
    if vm_count is not None:
        if not isinstance(vm_count, int) or isinstance(vm_count, bool) or vm_count < 1:
            raise ConfigError("vm_options.vm_count must be an integer >= 1")

    for key in ("junk_rate", "integrity_constant_rate", "graph_execution_rate",
                "cross_instruction_rate", "runtime_polymorphism_rate",
                "block_variant_rate", "helper_diversity_rate",
                "semantic_diversity_rate"):
        value = options.get(key)
        if value is not None:
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise ConfigError(f"vm_options.{key} must be a number between 0.0 and 1.0")
            if not 0.0 <= float(value) <= 1.0:
                raise ConfigError(f"vm_options.{key} must be between 0.0 and 1.0")

    for key in ("fake_handlers", "mutate_handlers", "junk_instructions",
                "integrity_constants", "runtime_trace",
                "dispatcher_target_hiding", "semantic_state_threading",
                "argument_virtualization", "upvalue_virtualization",
                "table_virtualization", "branch_virtualization"):
        value = options.get(key)
        if value is not None and not isinstance(value, bool):
            raise ConfigError(f"vm_options.{key} must be true or false")

    for key, minimum, maximum in (
        ("block_variant_count", 2, 4),
        ("block_variant_max_instructions", 2, 32),
        ("helper_variant_count", 1, 4),
    ):
        value = options.get(key)
        if value is not None:
            if not isinstance(value, int) or isinstance(value, bool):
                raise ConfigError(f"vm_options.{key} must be an integer")
            if not minimum <= value <= maximum:
                raise ConfigError(
                    f"vm_options.{key} must be between {minimum} and {maximum}"
                )


def _validate_signature(signature: dict) -> None:
    if not isinstance(signature, dict):
        raise ConfigError("'signature' must be an object")
    mode = signature.get("mode", "default")
    if mode not in VALID_SIGNATURE_MODES:
        values = ", ".join(sorted(VALID_SIGNATURE_MODES))
        raise ConfigError(f"invalid signature.mode '{mode}'. expected: {values}")

    custom = signature.get("custom", "")
    if not isinstance(custom, str):
        raise ConfigError("signature.custom must be a string")
    if mode == "custom" and not strip_comment_tokens(custom):
        raise ConfigError("signature.custom must contain comment text in custom mode")

    fake = signature.get("fake", {})
    if not isinstance(fake, dict):
        raise ConfigError("signature.fake must be an object")
    custom_pattern = fake.get("custom_pattern", signature.get("custom_pattern", ""))
    if not isinstance(custom_pattern, str):
        raise ConfigError("signature.fake.custom_pattern must be a string")
    sources = fake.get("sources", ["well_known", "generated"])
    if not isinstance(sources, list) or not all(isinstance(item, str) for item in sources):
        raise ConfigError("signature.fake.sources must be a list of source names")
    unknown = [item for item in sources if item not in VALID_SIGNATURE_SOURCES]
    if unknown:
        raise ConfigError(f"unknown signature source: {', '.join(unknown)}")
    if mode == "fake" and not sources:
        raise ConfigError("signature.fake.sources must select at least one source in fake mode")
    patterns = fake.get("generator_patterns", list(DEFAULT_GENERATOR_PATTERNS))
    if not isinstance(patterns, list) or not all(isinstance(item, str) for item in patterns):
        raise ConfigError("signature.fake.generator_patterns must be a list of strings")
    uses_generator = mode == "generated" or (mode == "fake" and "generated" in sources)
    usable_patterns = [sanitize_generator_pattern(item) for item in patterns]
    usable_custom_pattern = sanitize_generator_pattern(custom_pattern)
    if uses_generator and not any(usable_patterns) and not usable_custom_pattern:
        raise ConfigError("generated signatures require a generator pattern or custom pattern")


def build_pipeline_from_config(config: dict, pipeline_cls, show_header: bool = True):
    """
    config 예시:
        {
            "passes": ["string_obf", "boolean_obf", "number_obf", "vm"],
            "vm_output_passes": ["string_obf", "minify"],  # 선택, VMPass에 전달됨
            "packer_output_passes": [],
            "vm_options": {"fake_handlers": true, "mutate_handlers": true}  # 선택
        }
    """
    validate_config(config)

    # Signature selection happens once so VM/packer integrity dumps can account
    # for the exact number of lines that the final output pass will prepend.
    signature_options       = config.get("signature", {}) if show_header else {"mode": "none"}
    signature_pass          = OutputSignaturePass(signature_options)
    pipeline                = pipeline_cls(show_header=False)
    vm_output_passes        = config.get("vm_output_passes", [])
    packer_output_passes    = config.get("packer_output_passes", []) 
    vm_options              = config.get("vm_options", {})
    has_packer              = "pack" in config.get("passes", [])

    for name in config.get("passes", []):
        info = PASS_REGISTRY.get(name)

        cls = info["cls"]
        if cls is VMPass:
            pipeline.add(cls(
                vm_output_passes=vm_output_passes,
                vm_options=vm_options,
                output_prefix="" if has_packer else signature_pass.prefix,
            ))
        elif cls is PackerPass:
            pipeline.add(cls(
                packer_output_passes=packer_output_passes,
                output_prefix=signature_pass.prefix,
            ))
        else:
            pipeline.add(cls())

    pipeline.add(signature_pass)
    return pipeline
