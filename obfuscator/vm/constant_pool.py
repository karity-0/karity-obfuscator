"""Unused strings in the real guest root pool, independent of the fake header."""
from dataclasses import replace
from collections.abc import Iterable

from .ir.model import IRValue, SemanticIR


# Edit this list to add or replace pool strings; an empty list disables insertion.
DECOY_STRINGS = [
    "string1",
]
RETENTION_KEY = 'retained_pool_strings'


def inject_decoy_strings(ir: SemanticIR) -> SemanticIR:
    required = tuple(dict.fromkeys((*ir.root.debug_metadata.get(RETENTION_KEY, ()),
                                   *(text.encode('utf8') for text in DECOY_STRINGS))))
    constants = [v for v in ir.root.values if v.kind == 'constant']
    existing = {v.literal.encode('utf8') if isinstance(v.literal, str) else v.literal
                for v in constants if isinstance(v.literal, (str, bytes))}
    additions: list[IRValue] = []
    for value in required:
        if value in existing:
            continue
        index = len(constants) + len(additions)
        additions.append(IRValue(f'{ir.root.id}:k{index}', 'constant', index, literal=value))
        existing.add(value)
    if not additions and ir.root.debug_metadata.get(RETENTION_KEY, ()) == required:
        return ir
    return replace(ir, root=replace(ir.root, values=ir.root.values + tuple(additions),
        debug_metadata={**ir.root.debug_metadata, RETENTION_KEY: required}))


def validate_retention(lowered, required: tuple[bytes, ...]) -> None:
    if not required:
        return
    root = lowered.semantic_ir.root
    if root.debug_metadata.get(RETENTION_KEY) != required:
        raise ValueError('retained pool strings contract lost during lowering')
    sources: list[tuple[str, Iterable[object]]] = [
        ('semantic lowering', (v.literal for v in root.values if v.kind == 'constant'))]
    if lowered.backend == 'bare':
        sources.append(('Bare storage', lowered.backend_data['source_protection'].constants))
    else:
        materialized = lowered.backend_data.get('materialization')
        physical = materialized.functions if materialized else lowered.backend_data['layout'].functions
        sources.append(('physical storage', physical.source.constants))
    for stage, values in sources:
        present = {v.encode('utf8') if isinstance(v, str) else v
                   for v in values if isinstance(v, (str, bytes))}
        if set(required) - present:
            raise ValueError('retained pool strings missing at ' + stage)
