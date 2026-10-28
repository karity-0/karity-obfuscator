"""One shared initialization probe; native mechanics remain bootstrap-safe.

This stage is not the auxiliary-IR integration. The template separates native
stack/worker collection from comparisons so actual validation can be protected
through the existing IR machinery without duplicating a second protocol.
"""
from pathlib import Path


def bootstrap_source(native_namespace: str) -> str:
    source=(Path(__file__).parent/'runtimes/runtime_probes.lua').read_text(encoding='utf-8')
    if source.count('__PROBE_NATIVE__')!=1:
        raise ValueError('runtime probe native namespace boundary is missing')
    return source.replace('__PROBE_NATIVE__',native_namespace)
