"""Interference-based storage reuse for ordinary Bare native temporaries.

Parameters, captured cells, dynamic ranges and explicit junk/morph registers
keep dedicated storage. Logical IR/lifetimes never change; releases consult
physical ownership at their original instruction point.
"""
from itertools import combinations


def native_prefix(function):
    """Conservative pre/post-protection bound used by existing guard proofs."""
    scratch=function.debug_metadata.get('security_scratch_base')
    original=function.max_stack_size if scratch is None else scratch
    starts=[o.value for b in function.blocks for i in b.instructions for o in i.operands
            if o.kind=='register_range' and (o.count is None or o.count>32)]
    return (0 if function.params>=128 else
            min(original,max(0,140-function.params),48,min(starts,default=original)))


def allocate(emitter, *, expand=True):
    function=emitter.function
    initial=emitter.local_count
    # Keep parameters/helpers and expression temporaries below Lua's separate
    # local and VM-register limits. Long fixed calls/returns need extra space.
    peak=max((o.count+(3 if i.operation in ('CALL','TAIL_CALL') else 1)
              for b in function.blocks for i in b.instructions
              if i.operation in ('CALL','TAIL_CALL','RETURN') for o in i.operands
              if o.role in ('arguments','values') and o.kind=='register_range'
              and o.count is not None),default=0)
    budget=max(0,min(140-function.params,240-function.params-max(60,peak+12)))
    emitter.native_budget=budget
    maximum=initial
    if expand and not (emitter.wide or emitter.program.poisoned or function.debug_metadata.get('security_owned')):
        maximum=min(emitter.original_stack,emitter.dynamic_start)
    # Try coloring the complete static prefix first: many logical registers
    # can fit into few physical locals. A bounded second attempt avoids a
    # repeated search over every prefix when the live frame exceeds budget.
    candidates=dict.fromkeys((maximum,max(initial,min(maximum,budget)),initial))
    for limit in candidates:
        result=_allocate(emitter,limit)
        if limit==initial or len(set(result.values()))<=budget:
            break
    emitter.local_count=limit
    emitter.program.optimization['native_slots_elided'] += limit-len(set(result.values()))
    if limit>initial:
        emitter.program.optimization['native_prefix_expansions'] += 1
        emitter.program.optimization['native_registers_promoted'] += limit-initial
    return result


def _allocate(emitter, limit):
    function=getattr(emitter,'storage_function',emitter.function)
    identity = {r:r for r in range(limit)}
    if ((function.debug_metadata.get('security_owned') and not function.debug_metadata.get('security_optimization_safe'))
            or emitter.program.poisoned):
        return identity
    pinned = set(range(function.params)) | emitter.captured
    for block in function.blocks:
        for instruction in block.instructions:
            if instruction.metadata.get('protection_origin') in ('junk','ir_morph') or instruction.metadata.get('morph_origin'):
                for operand in instruction.operands:
                    if operand.kind == 'register':pinned.add(operand.value)
                    elif operand.kind == 'register_range':
                        pinned.update(range(operand.value,min(limit,operand.value+(operand.count or limit))))
    eligible = set(range(limit))-pinned
    graph: dict[int,set[int]] = {r:set() for r in eligible}
    prefix = function.id+':r'
    def registers(names):
        return {int(name[len(prefix):]) for name in names
                if name.startswith(prefix) and name[len(prefix):].isdigit() and int(name[len(prefix):]) in eligible}
    previous=None
    def interfere(values):
        nonlocal previous
        if values==previous:return
        previous=values
        for a,b in combinations(sorted(values),2):
            graph[a].add(b);graph[b].add(a)
    copies = []
    for block in function.blocks:
        for instruction in block.instructions:
            interfere(registers(emitter.liveness.before[instruction.id]))
            interfere(registers(emitter.liveness.after[instruction.id]) | registers(instruction.outputs))
            if instruction.operation=='MOVE' and instruction.outputs and 'protection_origin' not in instruction.metadata:
                fields={o.role:o.value for o in instruction.operands}
                if fields['source'] in eligible and fields['destination'] in eligible:
                    copies.append((fields['source'],fields['destination']))
    parent={r:r for r in eligible}
    members={r:{r} for r in eligible}
    def find(r):
        while parent[r]!=r:
            parent[r]=parent[parent[r]];r=parent[r]
        return r
    for source,destination in copies:
        a,b=find(source),find(destination)
        if a==b or any(graph[r] & members[b] for r in members[a]):continue
        parent[b]=a;members[a].update(members.pop(b))
    classes={r:values for r,values in members.items()}
    colors: dict[int,int]={}
    palette=sorted(eligible)
    for root,values in sorted(classes.items(),key=lambda item:(-len(set().union(*(graph[r] for r in item[1]))),min(item[1]))):
        adjacent={find(other) for r in values for other in graph[r]}
        occupied={colors[other] for other in adjacent if other in colors}
        colors[root]=next(color for color in palette if color not in occupied)
    result={**identity,**{r:colors[find(r)] for r in eligible}}
    # Allocation bugs fail at build time rather than corrupting a guest frame.
    if any(result[a]==result[b] for a in graph for b in graph[a]):
        raise RuntimeError('Bare register allocation violates interference')
    return result
