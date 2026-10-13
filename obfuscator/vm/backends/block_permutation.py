"""Permute complete physical layout units; relink all address consumers once."""
from dataclasses import replace
from .handler_layout import PhysicalInstruction, PSEUDO_BLOCK_GOTO, _SBXOPS, _TESTOPS
from .handler_ir import HandlerInstruction


def permute_blocks(function, vm_map, *, rate, max_jumps, rng):
    code = function.code
    stats = {'units': 0, 'moved_units': 0, 'bridges': 0, 'before': len(code), 'after': len(code)}
    function.permutation = stats
    if not rate or len(function.chunks) < 3:
        stats['skip'] = 'disabled' if not rate else 'too_few_units'
        return function
    # Layout chunks already contain complete split/fuse/stream and variant
    # bundles. Bond the successor slot owned by skips and extension consumers.
    units = []
    for start, end in function.chunks:
        if units:
            previous = code[start - 1].instruction
            bonded = (previous.op in _TESTOPS or previous.op == 3 and previous.c
                      or previous.op == 2 or previous.op == 43 and previous.c == 0)
            if bonded:
                units[-1] = (units[-1][0], end)
                continue
        units.append((start, end))
    stats['units'] = len(units)
    selected = [i for i in range(1, len(units)) if rng.random() < rate]
    # Moving k units can disrupt at most 2k fallthrough boundaries.
    if len(selected) > max_jumps // 2:
        selected = sorted(rng.sample(selected, max_jumps // 2))
    if len(selected) < 2:
        stats['skip'] = 'selection_or_bridge_budget'
        return function
    order = list(range(len(units)))
    shuffled = rng.sample(selected, len(selected))
    if shuffled == selected:
        shuffled = shuffled[1:] + shuffled[:1]
    for position, unit in zip(selected, shuffled):
        order[position] = unit

    def falls_out(start, end):
        for index in range(start, end):
            raw = code[index].instruction
            if raw.op in _TESTOPS or raw.op == 3 and raw.c:
                if index + 2 == end:
                    return True
            elif raw.op not in {30, 37, 38, 40, 58, 59} and index + 1 == end:
                return True
        return False

    mapping = {}
    placed = []
    bridges = []
    new_chunks = []
    for position, unit in enumerate(order):
        new_start = len(placed)
        start, end = units[unit]
        for old in range(start, end):
            mapping[old] = len(placed)
            placed.append((old, code[old]))
        next_unit = order[position + 1] if position + 1 < len(order) else len(units)
        if falls_out(start, end) and next_unit != unit + 1:
            bridges.append((len(placed), end))
            placed.append((None, None))
        new_chunks.append((new_start, len(placed)))
    mapping[len(code)] = len(placed)
    if len(bridges) > max_jumps or len(placed) > 0x3FFFF:
        stats['skip'] = 'address_or_bridge_budget'
        return function
    bridge_targets = dict(bridges)
    result = []
    aliases = vm_map[0][PSEUDO_BLOCK_GOTO]
    for index, (old, item) in enumerate(placed):
        if old is None:
            raw = HandlerInstruction(PSEUDO_BLOCK_GOTO).with_bx(mapping[bridge_targets[index]])
            result.append(PhysicalInstruction(raw, rng.choice(aliases), (), ()))
            continue
        raw = item.instruction
        if raw.op in _SBXOPS:
            target = old + 1 + raw.sbx
            offset = mapping[target] - index - 1 + 131071
            if not 0 <= offset <= 0x3FFFF:
                stats['skip'] = 'relative_jump_range'
                return function
            raw = raw.with_bx(offset)
        elif raw.op == PSEUDO_BLOCK_GOTO:
            raw = raw.with_bx(mapping[raw.bx])
        result.append(replace(item, instruction=raw))
    function.code = result
    function.routes = [[mapping[target - 1] + 1 for target in route] for route in function.routes]
    function.canonical = tuple(mapping[target] for target in function.canonical)
    function.chunks = tuple(new_chunks)
    stats.update(moved_units=sum(a != b for a, b in enumerate(order)), bridges=len(bridges),
                 after=len(result), order=order)
    return function
