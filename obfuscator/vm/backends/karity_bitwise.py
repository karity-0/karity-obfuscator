"""Select integer-share consumers; native boundaries terminate their lifetime.

Single operations, joins and nonadjacent uses are supported. Each snapshot owns
its input shares, so overwrites and operand/destination aliases are safe. Active
graphs continue to use their original protection boundary.
"""
from .runtime_layout import RuntimeLayout, iter_functions

OPERATIONS = frozenset(('BIT_AND', 'BIT_OR', 'BIT_XOR', 'BIT_NOT',
                        'SHIFT_LEFT', 'SHIFT_RIGHT'))
SELECTORS = {20: 2, 21: 3, 22: 4, 23: 5, 24: 6, 26: 2}


def select_aliases(layout: RuntimeLayout) -> tuple[frozenset[int], ...]:
    selected: list[set[int]] = [set() for _ in range(layout.vm_count)]
    if not layout.encoded_bitwise:
        return tuple(frozenset() for _ in selected)
    for function in iter_functions(layout.functions):
        aliases = layout.vm_maps[function.vm_id][0]
        for item in function.code:
            ins = item.instruction
            if ins.operation in OPERATIONS and item.vop in aliases.get(ins.op, ()):
                selected[function.vm_id].add(item.vop)
    return tuple(frozenset(values) for values in selected)
