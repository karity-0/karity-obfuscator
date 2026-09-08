from __future__ import annotations

from .backends import backend_capabilities
from .backends.base import KARITY_OPTIONS

VM_BACKENDS = ("karity", "classic", "mov")
VM_BACKEND_ALIASES = {"default": "karity"}

# Derived from backend declarations so validation, GUI metadata and lowering use
# one capability source.
VM_UNSUPPORTED_OPTIONS = {
    name: KARITY_OPTIONS - backend_capabilities(name).supported_options
    for name in VM_BACKENDS
}


def unsupported_vm_options(backend: object) -> frozenset[str]:
    canonical = normalize_vm_backend(backend)
    return VM_UNSUPPORTED_OPTIONS[canonical]


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
