"""VM backend registry.

Backends consume the same semantic IR and protection plan.  The adapters keep
the current serializer/runtime implementation stable while making capability
and lowering decisions explicit.
"""
from .base import BackendContext, LoweredIR, VMBackend
from .classic import ClassicBackend
from .karity import KarityBackend
from .mov import MovBackend


_BACKENDS: dict[str, VMBackend] = {
    "classic": ClassicBackend(),
    "karity": KarityBackend(),
    "mov": MovBackend(),
}


def get_backend(name: str) -> VMBackend:
    try:
        return _BACKENDS[name]
    except KeyError as exc:
        raise ValueError(f"unknown VM backend adapter: {name}") from exc


def backend_capabilities(name: str):
    return get_backend(name).capabilities


__all__ = (
    "BackendContext", "LoweredIR", "VMBackend", "get_backend",
    "backend_capabilities",
)
