"""Independent source/runtime version and VM backend dimensions."""
from dataclasses import dataclass
from ..backend import normalize_vm_backend
from .capabilities import (
    Capability, CompatibilityPolicy, TargetEnvironment, TargetRequirements,
    LUA_VERSION_CAPABILITIES, HOST_CAPABILITIES,
)


@dataclass(frozen=True)
class TargetProfile:
    lua_version: str = "5.3"
    backend: str = "karity"
    environment: TargetEnvironment = TargetEnvironment.STANDALONE
    compatibility: CompatibilityPolicy = CompatibilityPolicy.RUNTIME_SPECIFIC
    disabled_capabilities: frozenset[Capability] = frozenset()
    runtime_abi: str | None = None
    host_images: tuple[str, ...] = ()

    def __post_init__(self):
        if self.lua_version not in ("5.1", "5.3"):
            raise ValueError("lua_version must be 5.1 or 5.3")
        object.__setattr__(self, "backend", normalize_vm_backend(self.backend))
        object.__setattr__(self, "environment", TargetEnvironment(self.environment))
        object.__setattr__(self, "compatibility", CompatibilityPolicy(self.compatibility))
        object.__setattr__(self, "disabled_capabilities",
                           frozenset(Capability(c) for c in self.disabled_capabilities))
        if self.runtime_abi is not None and (not isinstance(self.runtime_abi, str) or not self.runtime_abi.strip()):
            raise ValueError("runtime_abi must be a nonempty string or null")
        if not isinstance(self.host_images, (tuple, list)) or not all(
                isinstance(path, str) and path.strip() and '\0' not in path for path in self.host_images):
            raise ValueError("host_images must be a list of nonempty paths")
        object.__setattr__(self, "host_images", tuple(self.host_images))
        if self.host_images:
            self.require(TargetRequirements({Capability.LOCAL_MEMORY_READ},
                                             CompatibilityPolicy.BINARY_SPECIFIC), "host images")

    def constant_provider(self):
        if not self.host_images:
            return None
        from .image_resolver import CEBinaryResolver
        from .materialization import HostImageProvider
        resolver = CEBinaryResolver()
        return HostImageProvider(self, tuple(resolver.resolve(path) for path in self.host_images))

    @property
    def capabilities(self) -> frozenset[Capability]:
        return (LUA_VERSION_CAPABILITIES[self.lua_version] |
                HOST_CAPABILITIES[self.environment]) - self.disabled_capabilities

    def unmet(self, requirements: TargetRequirements) -> tuple[str, ...]:
        missing = requirements.unmet(self.capabilities, self.compatibility)
        host_access = requirements.capabilities & HOST_CAPABILITIES[TargetEnvironment.CHEAT_ENGINE]
        if host_access and not self.compatibility.allows(CompatibilityPolicy.RUNTIME_SPECIFIC):
            missing += ("compatibility:runtime_specific",)
        return tuple(dict.fromkeys(missing))

    def supports(self, requirements: TargetRequirements) -> bool:
        return not self.unmet(requirements)

    def require(self, requirements: TargetRequirements, feature: str) -> None:
        missing = self.unmet(requirements)
        if missing:
            raise ValueError(f"{feature} is unavailable for target {self.environment.value}/"
                             f"Lua {self.lua_version}: {', '.join(missing)}")

    @classmethod
    def from_config(cls, config: dict):
        options = config.get("target", {})
        if not isinstance(options, dict):
            raise ValueError("target must be an object")
        unknown = set(options) - {"lua_version", "environment", "compatibility",
                                  "disabled_capabilities", "runtime_abi", "host_images"}
        if unknown:
            raise ValueError(f"unknown target options: {', '.join(sorted(unknown))}")
        disabled = options.get("disabled_capabilities", [])
        if not isinstance(disabled, list) or not all(isinstance(c, str) for c in disabled):
            raise ValueError("target.disabled_capabilities must be a list of names")
        return cls(backend=config.get("vm_options", {}).get("backend", "karity"), **options)

    def adapter(self):
        from .lua53 import Lua53Target
        from .lua51 import Lua51Target
        return {"5.1": Lua51Target, "5.3": Lua53Target}[self.lua_version]()
