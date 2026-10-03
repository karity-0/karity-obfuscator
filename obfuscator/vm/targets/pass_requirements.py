"""Capability declarations for generated source and runtime boundaries."""
from .capabilities import Capability as C, CompatibilityPolicy as P, TargetRequirements as R


# Unlisted passes only rewrite syntax without adding target API requirements.
PASS_REQUIREMENTS = {
    "string_obf": R({C.NATIVE_BITOPS}),
    "boolean_obf": R({C.NATIVE_BITOPS}),
    "number_obf": R({C.NATIVE_BITOPS, C.INTEGER_ARITHMETIC}),
    "meme_strings": R({C.INTEGER_ARITHMETIC}),
    # Bounded arithmetic state encoding and predicates use common Lua syntax.
    "function_obf": R(),
    "anti_debug": R({C.NATIVE_BITOPS}),
    "anti_decompile": R({C.NATIVE_BITOPS}),
    "localize_globals": R({C.ENV_TABLE}),
    # Both emitters hash runtime function dumps, tying output to a compatible
    # dump ABI. They do not fingerprint executable files or module offsets.
    "vm": R({C.DEBUG_LIBRARY, C.FUNCTION_DUMP}, P.RUNTIME_SPECIFIC),
    "pack": R({C.DEBUG_LIBRARY, C.FUNCTION_DUMP, C.TEXT_CHUNK_LOAD,
               C.NATIVE_BITOPS, C.INTEGER_ARITHMETIC, C.ENV_TABLE}, P.RUNTIME_SPECIFIC),
}


# VM output passes transform a Lua 5.3 intermediate dialect, but the 5.1
# target no longer translates arbitrary expressions after those passes. A
# pass that emits bitwise/integer syntax must therefore satisfy the *final*
# target's capabilities. Localizing globals is the one source/output
# distinction: the VM finalizer supplies a lexical _ENV inside its function.
VM_OUTPUT_PASS_REQUIREMENTS = {
    **PASS_REQUIREMENTS,
    "localize_globals": R(),
}


def validate_pass_target(name, profile):
    profile.require(PASS_REQUIREMENTS.get(name, R()), "pass " + name)
    if name == "vm":
        profile.require(profile.adapter().requirements, "VM target runtime")


def validate_vm_output_pass_target(name, profile):
    # These are whole-script wrappers/stages, not transformations of the
    # return-function body that the VM dumper hashes and reloads.
    if name in {"vm", "pack", "anti_debug"}:
        raise ValueError(f"VM output pass {name} cannot wrap the VM function")
    from ...registry import PASS_REGISTRY
    if name not in PASS_REGISTRY:
        raise ValueError(f"unknown VM output pass: {name}")
    profile.require(
        VM_OUTPUT_PASS_REQUIREMENTS.get(name, R()),
        "VM output pass " + name,
    )
