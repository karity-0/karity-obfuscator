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
TERMINAL = frozenset(('CALL', 'TEST', 'EQUAL', 'LESS_THAN', 'LESS_EQUAL'))
SUPPORTED = SCALAR | ORDERED | TERMINAL


def inputs(instruction):
    """Value reads only; control/arity fields remain in original event words."""
    for operand in instruction.operands:
        if operand.role in ('destination', 'results') or operand.kind == 'immediate':
            continue
        if operand.kind == 'register_range':
            # Open argument tops are deliberately not inferred from frame size.
            from ..ir.model import IROperand
            for register in range(operand.value, operand.value + operand.count):
                yield IROperand(operand.role, 'register', register)
        else:
            yield operand


def rejection(instruction, facts, version, backend):
    op = instruction.operation
    if op not in (SCALAR if backend == 'prototype' else SUPPORTED):
        return 'unsupported_operation_boundary'
    if instruction.metadata.get('protection_origin') and backend == 'prototype':
        return 'protection_origin'
    effect = facts.effects.get(instruction.id)
    if effect is None:
        return 'unreachable'
    if op == 'CALL':
        args = next(v for v in instruction.operands if v.role == 'arguments')
        if args.count is None:
            return 'open_call_arguments'
    allowed = (frozenset(('open_top',)) if op == 'CALL' else
               frozenset(('upvalue_read',)) if backend!='prototype' and op in ('GET_UPVALUE','GET_UPVALUE_TABLE') else frozenset())
    if effect.boundaries-allowed:
        return 'lifetime_or_effect_boundary'
    if backend != 'prototype':
        # Terminal handlers may change PC/top or suspend the executor, but no
        # subsequent recipe step is allowed to execute before their resume.
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


def linear_chains(function, facts, backend):
    """Adjacent single-entry fallthrough blocks, without changing the IR/CFG.

    No branch is speculated, no join or back edge is swallowed, and the physical
    lowerer must still prove contiguous operand slots. Explicit jumps remain
    boundaries: their route/close events cannot be treated as a fallthrough.
    """
    from ..ir.operations import OPERATIONS
    chains=[]
    for block in function.blocks:
        if chains and backend!='prototype':
            previous=chains[-1][-1];last=previous.instructions[-1]
            if (previous.successors==(block.id,) and facts.predecessors[block.id]=={previous.id}
                    and block.id!=function.blocks[0].id
                    and OPERATIONS[last.operation].edges is None
                    and last.operation not in TERMINAL):
                chains[-1].append(block)
                continue
        chains.append([block])
    return tuple(tuple(chain) for chain in chains)
