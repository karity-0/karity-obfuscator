from __future__ import annotations

VM_BACKENDS = ("karity", "classic", "mov")
VM_BACKEND_ALIASES = {"default": "karity"}

# Controls bypassed by the direct runtimes. Shared by validation, UI and profiles.
_KARITY_ONLY = frozenset((
    "graph_execution_rate", "cross_instruction_rate", "runtime_polymorphism_rate",
    "runtime_trace", "block_variant_rate", "block_variant_count",
    "block_variant_max_instructions", "helper_variant_count", "helper_diversity_rate",
    "semantic_diversity_rate", "semantic_state_threading", "argument_virtualization",
    "upvalue_virtualization", "table_virtualization", "branch_virtualization",
))
VM_UNSUPPORTED_OPTIONS = {
    "karity": frozenset(),
    "classic": _KARITY_ONLY,
    "mov": _KARITY_ONLY | {"dispatcher_type", "dispatcher_target_hiding",
                           "fake_handlers", "mutate_handlers"},
}


def unsupported_vm_options(backend: object) -> frozenset[str]:
    return VM_UNSUPPORTED_OPTIONS[normalize_vm_backend(backend)]


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
