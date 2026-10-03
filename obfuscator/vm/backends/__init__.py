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
    "karity": KarityBackend(),
    "classic": ClassicBackend(),
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
    "backend_capabilities", "get_domain_backend", "register_domain_backend",
)


def backend_names() -> tuple[str, ...]:
    return tuple(_BACKENDS)


def register_backend(backend: VMBackend) -> None:
    """Register a backend before constructing a build or UI metadata."""
    if not backend.name or backend.name in _BACKENDS or backend.name == "default":
        raise ValueError(f"duplicate or invalid backend name: {backend.name}")
    if backend.capabilities.name != backend.name:
        raise ValueError("backend capability name mismatch")
    for source, target in backend.capabilities.fallbacks:
        if source == target or not backend.capabilities.supports(target):
            raise ValueError(f"invalid backend fallback: {source} -> {target}")
    _BACKENDS[backend.name] = backend


def backend_choices() -> list[tuple[str, str]]:
    return [(name, backend.description) for name, backend in _BACKENDS.items()] + [
        ("default", "alias for karity (the default runtime)")]


_DOMAIN_BACKENDS = None


def _domain_registry():
    global _DOMAIN_BACKENDS
    from .domains import ExecutionDomain
    from .native import CENativeBackend
    if _DOMAIN_BACKENDS is None:
        _DOMAIN_BACKENDS = {ExecutionDomain.VM: _BACKENDS,
                            ExecutionDomain.NATIVE: {CENativeBackend.name: CENativeBackend()}}
    return _DOMAIN_BACKENDS


def get_domain_backend(domain, name):
    """Select a lowering implementation without adding native to VM choices."""
    from .domains import ExecutionDomain
    try:
        return _domain_registry()[ExecutionDomain(domain)][name]
    except (KeyError, ValueError) as error:
        raise ValueError(f"unknown {domain} domain backend: {name}") from error


def register_domain_backend(backend):
    from .domains import ExecutionDomain
    domain = ExecutionDomain(backend.domain)
    if domain == ExecutionDomain.VM:
        register_backend(backend)
        return
    implementations = _domain_registry().setdefault(domain, {})
    if not backend.name or backend.name in implementations:
        raise ValueError(f"duplicate or invalid {domain.value} backend: {backend.name}")
    if not all(callable(getattr(backend, name, None)) for name in ('lower', 'optimize', 'emit')):
        raise ValueError('domain backend requires lower, optimize and emit')
    implementations[backend.name] = backend
