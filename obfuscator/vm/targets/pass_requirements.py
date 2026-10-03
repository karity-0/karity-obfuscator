"""Capability declarations for generated source and runtime boundaries."""
from .capabilities import Capability as C, CompatibilityPolicy as P, TargetRequirements as R


# Unlisted passes only rewrite syntax without adding target API requirements.
PASS_REQUIREMENTS = {
    "string_obf": R({C.NATIVE_BITOPS}),
    "boolean_obf": R({C.NATIVE_BITOPS}),
    "number_obf": R({C.NATIVE_BITOPS, C.INTEGER_ARITHMETIC}),
    "function_obf": R({C.NATIVE_BITOPS, C.INTEGER_ARITHMETIC}),
    "anti_decompile": R({C.NATIVE_BITOPS}),
    "localize_globals": R({C.ENV_TABLE}),
    # Both emitters hash runtime function dumps, tying output to a compatible
    # dump ABI. They do not fingerprint executable files or module offsets.
    "vm": R({C.DEBUG_LIBRARY, C.FUNCTION_DUMP}, P.RUNTIME_SPECIFIC),
    "pack": R({C.DEBUG_LIBRARY, C.FUNCTION_DUMP, C.TEXT_CHUNK_LOAD,
               C.NATIVE_BITOPS, C.INTEGER_ARITHMETIC, C.ENV_TABLE}, P.RUNTIME_SPECIFIC),
}


def validate_pass_target(name, profile):
    profile.require(PASS_REQUIREMENTS.get(name, R()), "pass " + name)
    if name == "vm":
        profile.require(profile.adapter().requirements, "VM target runtime")
