from __future__ import annotations

from .backends import backend_capabilities, backend_names
from .backends.base import KARITY_OPTIONS

class _BackendNames:
    def __iter__(self):
        return iter(backend_names())

    def __contains__(self, name):
        return name in backend_names()


VM_BACKENDS = _BackendNames()
VM_BACKEND_ALIASES = {"default": "karity"}


def unsupported_vm_options(backend: object) -> frozenset[str]:
    canonical = normalize_vm_backend(backend)
    return frozenset(option for option in KARITY_OPTIONS
                     if vm_option_resolution(canonical, option)["outcome"] == "disable")


def vm_option_resolution(backend: object, option: str) -> dict[str, str]:
    from .protection import ProtectionRequest, option_feature, resolve_capabilities
    capabilities = backend_capabilities(normalize_vm_backend(backend))
    feature = option_feature(option)
    if feature is None:
        return {"outcome": "native" if option in capabilities.supported_options or option == "requirements" else "disable"}
    resolution = resolve_capabilities((ProtectionRequest(feature),), capabilities)
    if resolution.fallbacks:
        return {"outcome": "fallback", "target": resolution.fallbacks[0][1]}
    return {"outcome": "native" if resolution.active else "disable"}


def normalize_vm_backend(value: object) -> str:
    """Return a canonical runtime id; omitted options keep Karity behavior."""
    if value is None:
        return "karity"
    if not isinstance(value, str):
        raise ValueError("vm_options.backend must be a string")
    backend = VM_BACKEND_ALIASES.get(value, value)
    if backend not in VM_BACKENDS:
        values = ", ".join((*VM_BACKENDS, *VM_BACKEND_ALIASES))
        raise ValueError(
            f"invalid vm_options.backend '{value}'. expected: {values}"
        )
    return backend
