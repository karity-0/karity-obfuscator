"""Small ordered recipe strategies over the common value/effect analysis.

Effectful steps never borrow cached operands or elide stores. They execute the
backend's original handler, in order, including metamethods and protection work.
"""

NUMERIC = frozenset(('ADD', 'SUB', 'MUL', 'NEGATE'))
INTEGER_BITS = frozenset(('BIT_AND', 'BIT_OR', 'BIT_XOR', 'BIT_NOT',
                          'SHIFT_LEFT', 'SHIFT_RIGHT'))
SCALAR = NUMERIC | INTEGER_BITS
ORDERED = frozenset(('GET_TABLE', 'GET_UPVALUE_TABLE', 'GET_UPVALUE', 'GLOBAL_GET',
                     'MOVE', 'MOD', 'POW', 'DIV', 'FLOOR_DIV',
                     'LENGTH', 'LOGICAL_NOT'))
SUPPORTED = SCALAR | ORDERED


def rejection(instruction, facts, version, backend):
    op = instruction.operation
    if op not in (SCALAR if backend == 'prototype' else SUPPORTED):
        return 'unsupported_operation_boundary'
    if instruction.metadata.get('protection_origin') and backend == 'prototype':
        return 'protection_origin'
    effect = facts.effects.get(instruction.id)
    if effect is None:
        return 'unreachable'
    allowed=frozenset(('upvalue_read',)) if backend!='prototype' and op in ('GET_UPVALUE','GET_UPVALUE_TABLE') else frozenset()
    if effect.boundaries-allowed:
        return 'lifetime_or_effect_boundary'
    if backend != 'prototype':
        # Ordered, single-destination handlers cannot change PC/top or suspend
        # the VM executor through its CALL continuation. Native metamethod
        # calls/yields remain inside the exact original handler.
        return None
    if facts.liveness.open_extents:
        return 'open_register_top'
    if facts.liveness.captured_before[instruction.id]:
        return 'active_capture'
    if not effect.pure:
        return 'unknown_or_metamethod'
    if op in INTEGER_BITS and (version != '5.3' or any(
            facts.operand(instruction, v.role).kind != 'integer'
            for v in instruction.operands if v.role != 'destination')):
        return 'unproven_integer_bit_operation'
    if any(facts.operand(instruction, v.role).kind not in ('integer', 'float', 'number')
           for v in instruction.operands if v.role != 'destination'):
        return 'unproven_numeric'
    return None


def ordered(instructions, facts):
    """Unknown/metamethod and additional operations need exact handler replay."""
    return any(i.operation not in SCALAR or not facts.effects[i.id].pure
               for i in instructions)


def materialized(instructions, facts, backend):
    if backend == 'prototype':
        return False
    return (backend == 'karity' or bool(facts.liveness.open_extents)
            or ordered(instructions, facts)
            or any(i.metadata.get('protection_origin') or
                   set(i.outputs) & facts.liveness.captured_before[i.id]
                   for i in instructions))
