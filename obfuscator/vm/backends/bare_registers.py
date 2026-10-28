"""Interference-based storage reuse for ordinary Bare native temporaries.

Parameters, captured cells, dynamic ranges and explicit junk/morph registers
keep dedicated storage. Logical IR/lifetimes never change; releases consult
physical ownership at their original instruction point.
"""
from itertools import combinations


def native_prefix(function):
    """Shared pre/post-protection frame bound for nonallocating result stores."""
    scratch=function.debug_metadata.get('security_scratch_base')
    original=function.max_stack_size if scratch is None else scratch
    starts=[o.value for b in function.blocks for i in b.instructions for o in i.operands
            if o.kind=='register_range' and (o.count is None or o.count>32)]
    return (0 if function.params>=128 else
            min(original,max(0,140-function.params),48,min(starts,default=original)))


def allocate(emitter):
    function, limit = emitter.function, emitter.local_count
    identity = {r:r for r in range(limit)}
    if function.debug_metadata.get('security_owned') or emitter.program.poisoned:
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
    def interfere(values):
        for a,b in combinations(sorted(values),2):
            graph[a].add(b);graph[b].add(a)
    copies = []
    for block in function.blocks:
        for instruction in block.instructions:
            interfere(registers(emitter.liveness.before[instruction.id]))
            interfere(registers(emitter.liveness.after[instruction.id]) | registers(instruction.outputs))
            if instruction.operation=='MOVE' and 'protection_origin' not in instruction.metadata:
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
    emitter.program.optimization['native_slots_elided'] += limit-len(set(result.values()))
    return result
