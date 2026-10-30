"""Bounded expression plans with storage lifetimes, not protected-IR rewrites."""
from dataclasses import dataclass, field, replace
from collections import Counter

from ..ir.liveness import analyze_liveness
from .bare_lifetimes import preserve_locals
from .bare_statements import Assignment, _assignment, _expression, _old_primitive, _native_cost


@dataclass(frozen=True)
class Atom:
    kind: str
    value: object


@dataclass(eq=False)
class Node:
    assignment: Assignment
    arguments: dict
    before: dict
    index: int
    value_key: object = None
    alias: object = None
    elided: bool = False
    dead: bool = False

    @property
    def target(self):return self.assignment.target


@dataclass
class Region:
    block: object
    nodes: list
    statistics: Counter = field(default_factory=Counter)


def _children(node, original=False):
    return (node.alias,) if node.alias is not None and not original else tuple(node.arguments.values())


def _key(value):
    if isinstance(value,Atom):return value.kind,type(value.value).__name__,repr(value.value)
    return value.value_key


def _leaves(value):
    if isinstance(value,Node) and value.elided:
        return [leaf for child in _children(value) for leaf in _leaves(child)]
    return [value]


def reads(node):
    return frozenset(value.target if isinstance(value,Node) else value.value
        for child in _children(node) for value in _leaves(child)
        if isinstance(value,Node) or value.kind=='register')


def _size(value):
    if not isinstance(value,Node) or not value.elided:return 0
    return 1+sum(_size(child) for child in _children(value))


def render(emitter,node):
    def value(ref):
        if isinstance(ref,Node):return render(emitter,ref) if ref.elided else emitter.r(ref.target)
        from ..ir.model import IROperand
        return emitter.operand(IROperand('value',ref.kind,ref.value))
    if node.alias is not None:return value(node.alias)
    overrides={operand.value:value(node.arguments[operand.role])
               for operand in node.assignment.instruction.operands
               if operand.kind=='register' and operand.role in node.arguments}
    return _expression(emitter,node.assignment.instruction,overrides)


def _available(node):
    for child in _children(node):
        for value in _leaves(child):
            if isinstance(value,Node):register=value.target
            elif value.kind=='register':register=value.value
            else:continue
            if node.before.get(register,Atom('register',register))!=value:return False
    return True


def _region(emitter,block,assignments):
    definitions: dict[int,Node]={}
    cache: dict[object,list[Node]]={}
    values: dict[tuple,int]={}
    nodes=[]
    for index,assignment in enumerate(assignments):
        instruction=assignment.instruction;fields={o.role:o for o in instruction.operands}
        op=instruction.operation
        roles=('value',) if op in ('LOAD_CONST','LOAD_BOOL') else (
            ('source',) if op in ('MOVE','LOGICAL_NOT','NEGATE','BIT_NOT') else ('left','right'))
        arguments={role:definitions.get(fields[role].value,Atom('register',fields[role].value))
                   if fields[role].kind=='register' else Atom(fields[role].kind,fields[role].value)
                   for role in roles}
        node=Node(assignment,arguments,dict(definitions),index)
        key=(op,tuple((role,_key(value)) for role,value in arguments.items()))
        if op in ('MOVE','LOAD_CONST','LOAD_BOOL'):
            node.value_key=_key(next(iter(arguments.values())))
        else:
            node.value_key=('value',values.setdefault(key,len(values)))
            for previous in reversed(cache.get(node.value_key,())):
                if definitions.get(previous.target) is previous:
                    node.alias=previous;break
            cache.setdefault(node.value_key,[]).append(node)
        nodes.append(node);definitions[node.target]=node
    parents: dict[Node,list[Node|None]]={n:[] for n in nodes}
    original_counts: Counter[Node]=Counter()
    for node in nodes:
        for value in _children(node):
            if isinstance(value,Node):parents[value].append(node)
        for value in _children(node,original=True):
            if isinstance(value,Node):original_counts[value]+=1
    prefix=emitter.function.id+':r'
    live=emitter.liveness.after[assignments[-1].instruction.id]
    for register,node in definitions.items():
        if prefix+str(register) in live:parents[node].append(None)
    statistics=Counter(common_expressions=sum(n.alias is not None for n in nodes))
    for node in reversed(nodes):
        if not _old_primitive(emitter,node.assignment):continue
        if not parents[node] and (original_counts[node] or node.alias is not None):
            node.elided=True;node.dead=True;statistics['graph_dead_temporaries']+=1
            for value in _children(node):
                if isinstance(value,Node):parents[value].remove(node)
            continue
        if len(parents[node])!=1:continue
        owner=parents[node][0]
        if owner is None:continue
        while owner.elided:
            next_owner=parents[owner][0] if len(parents[owner])==1 else None
            if next_owner is None:break
            owner=next_owner
        if owner.elided:continue
        node.elided=True
        if (_available(owner) and 1+sum(_size(v) for v in _children(owner))<=8
                and len(render(emitter,owner))<=512):
            statistics['graph_expression_fusions']+=1
            if owner.index>node.index+1:statistics['nonadjacent_fusions']+=1
        else:node.elided=False
    if not any(n.elided or n.alias is not None for n in nodes):return None
    return Region(block,nodes,statistics)


def _regions(emitter):
    regions=[]
    for block in emitter.function.blocks:
        run: list[Assignment]=[]
        def flush():
            if len(run)>1:
                region=_region(emitter,block,run)
                if region is not None:regions.append(region)
            run.clear()
        for instruction in block.instructions:
            statement=None if (emitter.local_releases.get(instruction.id)
                or instruction.metadata.get('morph_origin')) else _assignment(emitter,instruction)
            if statement is None:flush()
            else:
                run.append(statement)
                if len(run)==64:flush()
        flush()
    return regions


def _sequential(emitter,region):
    return ''.join(emitter.r(n.target)+'='+render(emitter,n)+'\n' for n in region.nodes if not n.elided)


def _storage(emitter,regions):
    prefix=emitter.function.id+':r'
    access={n.assignment.instruction.id:(tuple(prefix+str(r) for r in sorted(reads(n))),
             () if n.elided else (prefix+str(n.target),))
            for region in regions for n in region.nodes}
    # Elided nodes do not execute their inputs either. This private def/use
    # projection is only consumed by liveness/allocation, never serialized IR.
    access={key:(() if not outputs else inputs,outputs) for key,(inputs,outputs) in access.items()}
    view=replace(emitter.function,blocks=tuple(replace(b,instructions=tuple(
        replace(i,inputs=access[i.id][0],outputs=access[i.id][1]) if i.id in access else i
        for i in b.instructions)) for b in emitter.function.blocks))
    live=analyze_liveness(view)
    releases: dict[str,tuple[int,...]]={}
    edges: dict[tuple[str,str],tuple[int,...]]={}
    hints=emitter.program.lowered.backend_data['bare_result_hints'][view.id]
    live=preserve_locals(view,live,emitter.facts,hints,releases,edges)
    return view,live,releases,edges


def prepare(emitter):
    if (emitter.program.poisoned or emitter.function.debug_metadata.get('security_owned')
            or not getattr(emitter,'native_budget',None)):return
    regions=_regions(emitter)
    if not regions:return
    from .bare_statements import emit
    from .bare_registers import _allocate
    baseline={}
    statistics=emitter.program.optimization.copy()
    promising=[]
    for region in regions:
        text=emit(emitter,tuple(n.assignment.instruction for n in region.nodes),region.block,planned=False)
        cost=_native_cost(text,emitter.local_slots,emitter.program.version)
        candidate=_sequential(emitter,region)
        estimate=_native_cost(candidate,emitter.local_slots,emitter.program.version)
        if (cost is not None and estimate is not None and estimate<=cost and len(candidate)<=len(text)
                and (estimate<cost or len(candidate)<len(text))):
            promising.append(region);baseline[id(region)]=(text,cost)
    emitter.program.optimization.clear();emitter.program.optimization.update(statistics)
    regions=promising
    if not regions:return
    old=(emitter.liveness,emitter.local_releases,emitter.edge_releases,emitter.register_map,emitter.local_slots)
    admitted=False
    for attempt in range(2):
        view,live,releases,edges=_storage(emitter,regions)
        emitter.storage_function=view;emitter.liveness=live
        mapping=_allocate(emitter,emitter.local_count);slots=tuple(sorted(set(mapping.values())))
        if len(slots)>min(len(old[4]),emitter.native_budget):break
        emitter.register_map=mapping;emitter.local_slots=slots
        accepted=[]
        for region in regions:
            text=_sequential(emitter,region);before,cost=baseline[id(region)]
            after=_native_cost(text,slots,emitter.program.version)
            if (cost is not None and after is not None and after<=cost and len(text)<=len(before)
                    and (after<cost or len(text)<len(before))):accepted.append(region)
        if len(accepted)==len(regions):
            emitter.local_releases=releases;emitter.edge_releases=edges;admitted=True;break
        regions=accepted
        if not regions:break
    if not admitted:
        emitter.liveness,emitter.local_releases,emitter.edge_releases,emitter.register_map,emitter.local_slots=old
        if hasattr(emitter,'storage_function'):del emitter.storage_function
        emitter.program.optimization['expression_graph_rejections']+=1
        return
    emitter.expression_plan={n.assignment.instruction.id:n for r in regions for n in r.nodes}
    emitter.program.optimization['native_slots_elided']+=len(old[4])-len(emitter.local_slots)
    emitter.program.optimization['expression_graph_regions']+=len(regions)
    for region in regions:
        emitter.program.optimization.update(region.statistics)
        emitter.program.optimization['expression_fusions']+=region.statistics['graph_expression_fusions']
