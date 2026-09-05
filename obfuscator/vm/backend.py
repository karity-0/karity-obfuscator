from __future__ import annotations

VM_BACKENDS = ("karity", "classic", "mov")
VM_BACKEND_ALIASES = {"default": "classic"}


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
