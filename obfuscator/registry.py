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
    "dispatcher_type": {
        "description": "VM dispatcher shape.",
        "default": "ifelseif",
        "values": [
            ("ifelseif", "classic if/elseif dispatcher"),
            ("tailcall", "function table + tail-call dispatcher"),
            ("table", "alias for the function-table tail-call dispatcher"),
            ("bsearch", "nested binary-search if/else tree over the opcode"),
            ("splitN", "split handlers across N smaller if/elseif dispatcher functions, for example split4"),
            ("bsplitN", "split handlers across N smaller binary-search dispatcher functions, for example bsplit6"),
            ("mixed", "randomly choose a dispatcher per VM"),
        ],
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


def validate_release_config(config: dict) -> None:
    validate_config(config)
    errors: list[str] = []
    passes = config.get("passes", [])
    vm_options = config.get("vm_options", {})

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

    for key in ("junk_rate", "integrity_constant_rate"):
        value = options.get(key)
        if value is not None:
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise ConfigError(f"vm_options.{key} must be a number between 0.0 and 1.0")
            if not 0.0 <= float(value) <= 1.0:
                raise ConfigError(f"vm_options.{key} must be between 0.0 and 1.0")

    for key in ("fake_handlers", "mutate_handlers", "junk_instructions", "integrity_constants"):
        value = options.get(key)
        if value is not None and not isinstance(value, bool):
            raise ConfigError(f"vm_options.{key} must be true or false")


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

    pipeline                = pipeline_cls(show_header=show_header)
    vm_output_passes        = config.get("vm_output_passes", [])
    packer_output_passes    = config.get("packer_output_passes", []) 
    vm_options              = config.get("vm_options", {})

    for name in config.get("passes", []):
        info = PASS_REGISTRY.get(name)

        cls = info["cls"]
        if cls is VMPass:
            pipeline.add(cls(vm_output_passes=vm_output_passes, vm_options=vm_options))
        elif cls is PackerPass:
            pipeline.add(cls(packer_output_passes=packer_output_passes))
        else:
            pipeline.add(cls())

    return pipeline
