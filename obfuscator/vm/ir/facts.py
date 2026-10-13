"""Conservative value/effect and def-use facts shared by small IR strategies."""
from dataclasses import dataclass
from collections import deque
from .liveness import analyze_liveness
from .operations import OPERATIONS


@dataclass(frozen=True, eq=False)
class ValueFact:
    kind: str = 'unknown'
    known: bool = False
    value: object = None

    def __eq__(self, other):
        if not isinstance(other,ValueFact) or (self.kind,self.known)!=(other.kind,other.known):return False
        if not self.known:return True
        if type(self.value) is float and type(other.value) is float:
            import struct
            return struct.pack('>d',self.value)==struct.pack('>d',other.value)
        return type(self.value) is type(other.value) and self.value==other.value


UNKNOWN = ValueFact()
INTEGER = ValueFact('integer')
NUMBER = ValueFact('number')
_INTEGER_OPS = frozenset(('ADD','SUB','MUL','NEGATE','BIT_AND','BIT_OR','BIT_XOR',
                          'BIT_NOT','SHIFT_LEFT','SHIFT_RIGHT'))


def literal_fact(value, version):
    kind = ('nil' if value is None else 'boolean' if type(value) is bool else
            'integer' if type(value) is int and version == '5.3' else
            'float' if type(value) in (int,float) else 'string' if isinstance(value,(str,bytes)) else 'unknown')
    return ValueFact(kind, True, value) if kind != 'unknown' else UNKNOWN


def merge_facts(values):
    first=values[0]
    if all(v == first and (not v.known or repr(v.value)==repr(first.value)) for v in values):
        return first
    kinds={v.kind for v in values}
    if len(kinds)==1:
        return ValueFact(first.kind)
    if kinds <= {'integer','float','number'}:
        return NUMBER
    return UNKNOWN


@dataclass(frozen=True)
class Effect:
    pure: bool
    may_call: bool
    boundaries: frozenset[str]


@dataclass
class FunctionFacts:
    function: object
    version: str
    constants: dict
    before: dict
    definitions: dict
    producers: dict
    predecessors: dict
    dominance: dict
    block_indices: dict
    locations: dict
    effects: dict
    liveness: object

    def operand(self, instruction, role):
        operand=next(v for v in instruction.operands if v.role==role)
        if operand.kind=='constant':return self.constants[operand.value]
        if operand.kind=='register':return self.before[instruction.id].get(operand.value,UNKNOWN)
        return UNKNOWN

    def dominates(self, first, second):
        return bool(self.dominance.get(second,0) & (1 << self.block_indices[first]))

    def reaches(self, start, target):
        blocks={b.id:b for b in self.function.blocks}
        pending=[start];seen=set()
        while pending:
            node=pending.pop()
            if node==target:return True
            if node not in seen:
                seen.add(node);pending.extend(blocks[node].successors)
        return False


def analyze_function(function, version):
    blocks={b.id:b for b in function.blocks}
    predecessors={key:set() for key in blocks}
    for block in blocks.values():
        for target in block.successors:predecessors[target].add(block.id)
    live=analyze_liveness(function)
    constants={v.index:literal_fact(v.literal,version) for v in function.values if v.kind=='constant'}
    registers=tuple(v.index for v in function.values if v.kind=='register')
    reg_index={v.id:v.index for v in function.values if v.kind=='register'}
    before={};definitions={};effects={}
    locations={i.id:(b.id,pos) for b in function.blocks for pos,i in enumerate(b.instructions)}
    producers={i.id:i for b in function.blocks for i in b.instructions}

    def evaluate(instruction, facts):
        operands={v.role:v for v in instruction.operands if v.role!='capture'}
        def get(role):
            v=operands[role]
            return constants[v.value] if v.kind=='constant' else facts.get(v.value,UNKNOWN)
        op=instruction.operation
        if op=='LOAD_CONST':return get('value')
        if op=='LOAD_BOOL':return literal_fact(operands['value'].value,version)
        if op in ('MOVE','TEST_SET'):return get('source' if op=='MOVE' else 'condition')
        if op=='LOGICAL_NOT':return ValueFact('boolean')
        if op in _INTEGER_OPS:
            args=[get('source')] if op in ('NEGATE','BIT_NOT') else [get('left'),get('right')]
            if version=='5.3' and all(v.kind=='integer' for v in args):return INTEGER
            if op in ('ADD','SUB','MUL','NEGATE') and all(v.kind in ('integer','float','number') for v in args):
                return ValueFact('float') if any(v.kind=='float' for v in args) else NUMBER
        return UNKNOWN

    edges={}
    initial_defs={r:frozenset((f'{function.id}:entry:r{r}',)) for r in registers}
    pending=deque((function.blocks[0].id,)) if function.blocks else deque()
    queued=set(pending)
    while pending:
        key=pending.popleft();queued.discard(key);block=blocks[key]
        incoming=[edges[(p,key)] for p in predecessors[key] if (p,key) in edges]
        if key==function.blocks[0].id:incoming.append(({},initial_defs))
        if not incoming:continue
        keys=set().union(*(state[0].keys() for state in incoming))
        facts={r:merge_facts([f.get(r,UNKNOWN) for f,_ in incoming]) for r in keys}
        facts={r:v for r,v in facts.items() if v.kind!='unknown'}
        defs={r:frozenset().union(*(d[r] for _,d in incoming)) for r in registers}
        for instruction in block.instructions:
            before[instruction.id]=dict(facts);definitions[instruction.id]=dict(defs)
            op=instruction.operation;contract=OPERATIONS[op]
            value=evaluate(instruction,facts)
            pure=op in {'MOVE','LOAD_CONST','LOAD_BOOL','LOAD_NIL','LOGICAL_NOT'} or (
                op in _INTEGER_OPS and value.kind in {'integer','float','number'})
            may_call='call' in contract.effects and not pure
            boundaries=set(contract.effects & {'upvalue_read','upvalue_write','capture'})
            if instruction.id in live.open_extents:boundaries.add('open_top')
            if op in {'VARARG','PACK_VARARG'}:boundaries.add('vararg')
            if op in {'FOR_PREP','FOR_LOOP','ITER_LOOP','ITER_CALL'}:boundaries.add('loop')
            if op=='JUMP' and next(v.value for v in instruction.operands if v.role=='close_from') is not None:
                boundaries.add('close')
            if op in {'RETURN','TAIL_CALL'} and live.captured_before[instruction.id]:boundaries.add('close')
            effects[instruction.id]=Effect(pure,may_call,frozenset(boundaries))
            if may_call or 'upvalue_write' in contract.effects:
                for name in live.captured_before[instruction.id]:
                    r=reg_index[name];facts.pop(r,None);defs[r]=frozenset((instruction.id+':clobber',))
            integer_loop=False
            if op in {'FOR_PREP','FOR_LOOP'}:
                start=next(v.value for v in instruction.operands if v.role=='loop_state')
                integer_loop=version=='5.3' and all(facts.get(r,UNKNOWN).kind=='integer' for r in range(start,start+3))
            for name in instruction.outputs:
                if name not in reg_index:continue
                r=reg_index[name];defs[r]=frozenset((instruction.id,))
                result=literal_fact(None,version) if op=='LOAD_NIL' else INTEGER if integer_loop else value
                if result.kind=='unknown':facts.pop(r,None)
                else:facts[r]=result
        outgoing={}
        for index,target in enumerate(block.successors):
            edge_facts=dict(facts);edge_defs=dict(defs);last=block.instructions[-1]
            if index==1 and last.operation in {'TEST_SET','FOR_LOOP','ITER_LOOP'}:
                for name in last.outputs:
                    if name not in reg_index:continue
                    r=reg_index[name];old=before[last.id].get(r,UNKNOWN)
                    if last.operation=='FOR_LOOP':
                        old=merge_facts([old,edge_facts.get(r,UNKNOWN)])
                        edge_defs[r]=edge_defs[r] | definitions[last.id][r]
                    else:edge_defs[r]=definitions[last.id][r]
                    if old.kind=='unknown':edge_facts.pop(r,None)
                    else:edge_facts[r]=old
            state=(edge_facts,edge_defs)
            if target in outgoing:
                old_facts,old_defs=outgoing[target]
                names=old_facts.keys() | edge_facts.keys()
                edge_facts={r:merge_facts([old_facts.get(r,UNKNOWN),edge_facts.get(r,UNKNOWN)]) for r in names}
                edge_defs={r:old_defs[r] | edge_defs[r] for r in registers}
                state=(edge_facts,edge_defs)
            outgoing[target]=state
        for target,state in outgoing.items():
            if edges.get((key,target))!=state:
                edges[(key,target)]=state
                if target not in queued:pending.append(target);queued.add(target)

    indices={key:i for i,key in enumerate(blocks)}
    reachable={function.blocks[0].id} if function.blocks else set()
    pending=list(reachable)
    while pending:
        for target in blocks[pending.pop()].successors:
            if target not in reachable:reachable.add(target);pending.append(target)
    mask=sum(1 << indices[key] for key in reachable)
    dom={key:mask for key in reachable}
    if reachable:
        entry=function.blocks[0].id;dom[entry]=1 << indices[entry]
        changed=True
        while changed:
            changed=False
            for key in blocks:
                if key not in reachable or key==entry:continue
                merged=mask
                for p in predecessors[key] & reachable:merged &= dom[p]
                value=merged | (1 << indices[key])
                if dom[key]!=value:dom[key]=value;changed=True
    return FunctionFacts(function,version,constants,before,definitions,producers,predecessors,
                         dom,indices,locations,effects,live)
