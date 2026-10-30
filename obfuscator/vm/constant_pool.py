"""Unused strings in the real guest root pool, independent of the fake header."""
from dataclasses import replace

from .ir.model import IRValue, SemanticIR


# Edit this list to add or replace pool strings; an empty list disables insertion.
DECOY_STRINGS = [
    "string1",
]


def inject_decoy_strings(ir: SemanticIR) -> SemanticIR:
    constants = [v for v in ir.root.values if v.kind == 'constant']
    existing = {v.literal.encode('utf8') if isinstance(v.literal, str) else v.literal
                for v in constants if isinstance(v.literal, (str, bytes))}
    additions: list[IRValue] = []
    for text in DECOY_STRINGS:
        value = text.encode('utf8')
        if value in existing:
            continue
        index = len(constants) + len(additions)
        additions.append(IRValue(f'{ir.root.id}:k{index}', 'constant', index, literal=value))
        existing.add(value)
    return replace(ir, root=replace(ir.root, values=ir.root.values + tuple(additions))) if additions else ir
