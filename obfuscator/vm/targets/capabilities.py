"""Requirements shared by source passes, target runtimes and materializers."""
from dataclasses import dataclass
from enum import Enum


class CompatibilityPolicy(str, Enum):
    PORTABLE = "portable"
    RUNTIME_SPECIFIC = "runtime_specific"
    BINARY_SPECIFIC = "binary_specific"

    def allows(self, minimum: "CompatibilityPolicy") -> bool:
        levels = tuple(type(self))
        return levels.index(self) >= levels.index(type(self)(minimum))


class TargetEnvironment(str, Enum):
    STANDALONE = "standalone"
    CHEAT_ENGINE = "cheatengine"


class Capability(str, Enum):
    ENV_TABLE = "env_table"
    GETFENV = "getfenv"
    DEBUG_LIBRARY = "debug_library"
    FUNCTION_DUMP = "function_dump"
    BINARY_CHUNK_LOAD = "binary_chunk_load"
    TEXT_CHUNK_LOAD = "text_chunk_load"
    NATIVE_BITOPS = "native_bitops"
    INTEGER_ARITHMETIC = "integer_arithmetic"
    GOTO = "goto"
    LOCAL_MEMORY_READ = "local_memory_read"
    POINTER_READ = "pointer_read"
    AUTO_ASSEMBLER = "auto_assembler"
    NATIVE_ALLOCATION = "native_allocation"
    NATIVE_EXECUTION = "native_execution"


@dataclass(frozen=True)
class TargetRequirements:
    capabilities: frozenset[Capability] = frozenset()
    minimum_compatibility: CompatibilityPolicy = CompatibilityPolicy.PORTABLE

    def __post_init__(self):
        object.__setattr__(self, "capabilities", frozenset(Capability(c) for c in self.capabilities))
        object.__setattr__(self, "minimum_compatibility", CompatibilityPolicy(self.minimum_compatibility))

    def unmet(self, capabilities, compatibility) -> tuple[str, ...]:
        missing = sorted(c.value for c in self.capabilities - frozenset(capabilities))
        if not CompatibilityPolicy(compatibility).allows(self.minimum_compatibility):
            missing.append("compatibility:" + self.minimum_compatibility.value)
        return tuple(missing)


LUA_COMMON = frozenset({Capability.DEBUG_LIBRARY, Capability.FUNCTION_DUMP,
                        Capability.BINARY_CHUNK_LOAD, Capability.TEXT_CHUNK_LOAD})
LUA_VERSION_CAPABILITIES = {
    "5.1": LUA_COMMON | {Capability.GETFENV},
    "5.3": LUA_COMMON | {Capability.ENV_TABLE, Capability.NATIVE_BITOPS,
                         Capability.INTEGER_ARITHMETIC, Capability.GOTO},
}
HOST_CAPABILITIES = {
    TargetEnvironment.STANDALONE: frozenset(),
    TargetEnvironment.CHEAT_ENGINE: frozenset({
        Capability.LOCAL_MEMORY_READ, Capability.POINTER_READ,
        Capability.AUTO_ASSEMBLER, Capability.NATIVE_ALLOCATION,
        Capability.NATIVE_EXECUTION,
    }),
}
