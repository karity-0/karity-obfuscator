"""Bounded primitive expressions and dependence-safe native local assignments.

Only nonallocating, nonthrowing primitive work enters a run. Captures, guest spill
registers, protection/morph instructions, calls and control edges remain barriers.
Guest reference clears are emitted by the original instruction path.
"""
from dataclasses import dataclass
from functools import lru_cache
from ..ir.model import IRInstruction


PRIMITIVES = frozenset(('nil', 'boolean', 'integer', 'float', 'number'))
OPS = frozenset(('LOAD_CONST', 'LOAD_BOOL', 'MOVE', 'LOGICAL_NOT', 'ADD', 'SUB',
    'MUL', 'NEGATE', 'BIT_AND', 'BIT_OR', 'BIT_XOR', 'BIT_NOT', 'SHIFT_LEFT', 'SHIFT_RIGHT'))


@lru_cache(maxsize=1024)
def _native_cost(code, local_slots, version):
    from ...passes.function_costs import measure
    declarations = 'local '+','.join([*('_Br'+str(i) for i in local_slots), '_BX'])+'\n'
    cost = measure(declarations+code, version=version)
    return cost.get('total_instructions') if 'error' not in cost else None


@dataclass
class Assignment:
    instruction: IRInstruction
    target: int
    expression: str
    reads: frozenset[int]
    depth: int = 1
    graph: bool = False


def _expression(emitter, instruction, overrides=None):
    from .bare_emitter import _BINARY, _UNARY
    fields = {o.role: o for o in instruction.operands}
    overrides = overrides or {}
    def value(role):
        operand = fields[role]
        if operand.kind == 'register' and operand.value in overrides:
            return '(' + overrides[operand.value] + ')'
        return emitter.operand(operand)
    op = instruction.operation
    if op in ('LOAD_CONST', 'LOAD_BOOL'):
        return value('value')
    if op == 'MOVE':
        return value('source')
    if op in _UNARY:
        return _UNARY[op] + '(' + value('source') + ')'
    return '(' + value('left') + ')' + _BINARY[op] + '(' + value('right') + ')'


def _assignment(emitter, instruction):
    if (instruction.operation not in OPS or len(instruction.targets)>1 or emitter.program.poisoned
            or 'protection_origin' in instruction.metadata or instruction.metadata.get('bare_call_skip')):
        return None
    effect = emitter.facts.effects[instruction.id]
    if not effect.pure or effect.may_call or effect.boundaries:
        return None
    destination = next(o for o in instruction.operands if o.role == 'destination')
    if destination.value>=emitter.local_count or destination.value in emitter.captured:
        return None
    for operand in instruction.operands:
        if operand.role == 'destination':
            continue
        if operand.kind == 'register':
            scratch = emitter.scratch_base is not None and operand.value>=emitter.scratch_base
            if operand.value in emitter.captured or operand.value>=emitter.local_count and not scratch:
                return None
            fact = emitter.facts.before[instruction.id].get(operand.value)
            if fact is None or fact.kind not in PRIMITIVES:
                return None
        elif operand.kind == 'constant':
            if type(emitter.constants[operand.value]) not in (type(None), bool, int, float):
                return None
        elif operand.kind != 'immediate':
            return None
    return Assignment(instruction, destination.value, _expression(emitter, instruction),
        frozenset(o.value for o in instruction.operands if o.kind == 'register' and o.role != 'destination'))


def _old_primitive(emitter, assignment):
    instruction, target = assignment.instruction, assignment.target
    fact = emitter.facts.before[instruction.id].get(target)
    if fact is not None and fact.kind in PRIMITIVES:
        return True
    # Non-parameter native locals are nil on entry. Never leave an old guest
    # object in an eliminated destination by treating an unknown parameter so.
    entry = f'{emitter.function.id}:entry:r{target}'
    definitions = emitter.facts.definitions[instruction.id][target]
    for definition in definitions:
        if definition == entry and target >= emitter.function.params:
            continue
        producer = emitter.facts.producers.get(definition)
        if producer is None:
            return False
        if producer.operation in ('LOAD_BOOL', 'LOAD_NIL', 'LOGICAL_NOT'):
            continue
        if producer.operation == 'LOAD_CONST':
            value = next(o for o in producer.operands if o.role == 'value')
            if type(emitter.constants[value.value]) in (type(None), bool, int, float):
                continue
        elif producer.operation == 'MOVE':
            source = next(o.value for o in producer.operands if o.role == 'source')
            fact = emitter.facts.before[producer.id].get(source)
            if fact is not None and fact.kind in PRIMITIVES:
                continue
        elif producer.operation in OPS and emitter.facts.effects[producer.id].pure:
            continue
        return False
    return bool(definitions)


def emit(emitter, instructions, block, *, planned=True):
    result = []
    run: list[Assignment] = []
    statistics = emitter.program.optimization

    def flush():
        batch: list[Assignment] = []
        reads: set[int] = set()
        writes: set[int] = set()
        def output():
            if batch:
                expressions = [s.expression for s in batch]
                while len(expressions)>1 and expressions[-1]=='nil':
                    expressions.pop()
                parallel = ','.join(emitter.r(s.target) for s in batch)+'='+','.join(expressions)+'\n'
                sequential = ''.join(emitter.r(s.target)+'='+s.expression+'\n' for s in batch)
                accepted = False
                if len(batch)>1 and len(parallel)<=len(sequential):
                    before = _native_cost(sequential,emitter.local_slots,emitter.program.version)
                    after = _native_cost(parallel,emitter.local_slots,emitter.program.version)
                    accepted = (before is not None and after is not None and after<=before
                                and (after<before or len(parallel)<len(sequential)))
                result.append(parallel if accepted else sequential)
                if len(batch)>1:
                    statistics['parallel_assignments' if accepted else 'parallel_rejections'] += len(batch)-1
        for statement in run:
            target=emitter.physical(statement.target)
            physical_reads={emitter.physical(r) for r in statement.reads}
            if (len(batch) >= 24 or target in writes or target in reads
                    or writes & physical_reads):
                output();batch.clear();reads.clear();writes.clear()
            batch.append(statement);reads.update(physical_reads);writes.add(target)
        output();run.clear()

    for instruction in instructions:
        node=getattr(emitter,'expression_plan',{}).get(instruction.id) if planned else None
        if node is not None and node.elided:continue
        copy=emitter.coalesced_copy(instruction) if node is None else None
        if copy is not None:
            flush();result.append(copy);continue
        if emitter.local_releases.get(instruction.id):
            flush();result.append(emitter.instruction(instruction,block));continue
        if node is not None:
            from .bare_expressions import render,reads
            statement=Assignment(instruction,node.target,render(emitter,node),reads(node),graph=True)
        else:statement = _assignment(emitter, instruction)
        if statement is None:
            flush()
            result.append(emitter.instruction(instruction, block))
            continue
        # Every read/result in this run is a proved non-reference primitive.
        # Such dead registers cannot prolong guest object lifetimes.
        statistics['primitive_clears_elided'] += len((set(instruction.inputs) | set(instruction.outputs))
                                                    - emitter.liveness.after[instruction.id])
        if run and not statement.graph and not run[-1].graph:
            previous = run[-1]
            uses = sum(o.kind == 'register' and o.role != 'destination' and o.value == previous.target
                       for o in instruction.operands)
            live = f'{emitter.function.id}:r{previous.target}' in emitter.liveness.after[instruction.id]
            if (uses == 1 and (not live or previous.target == statement.target)
                    and previous.depth < 8 and _old_primitive(emitter, previous)):
                expression = _expression(emitter, instruction, {previous.target: previous.expression})
                if len(expression) <= 512:
                    statement.expression = expression
                    statement.reads = (statement.reads - {previous.target}) | previous.reads
                    statement.depth += previous.depth
                    run.pop()
                    statistics['expression_fusions'] += 1
        run.append(statement)
    flush()
    return ''.join(result)
