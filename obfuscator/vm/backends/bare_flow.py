"""Bounded Bare emission graph reshaping; original guards/instructions stay put."""
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
import random


@dataclass
class Node:
    key: int
    code: str
    successors: tuple[int, ...]
    condition: str | None
    sources: tuple[int, ...]
    blocks: tuple[str, ...]
    units: int
    locked: bool = False
    depth: int = 0
    clears: tuple[str, ...] = ()


def _predecessors(nodes):
    result: dict[int,set[int]]={key:set() for key in nodes}
    for node in nodes.values():
        for target in node.successors:result[target].add(node.key)
    return result


@lru_cache(maxsize=2)
def _branch_forms(version):
    from ...passes.function_costs import measure
    prefix='local _Bcondition,_Bposition\n'
    before=measure(prefix+'if _Bcondition then _Bposition=1 else _Bposition=2 end',version=version)
    variants={
        'and-or':'_Bposition=_Bcondition and 1 or 2',
        'default-right':'_Bposition=2;if _Bcondition then _Bposition=1 end',
        'default-left':'_Bposition=1;if not _Bcondition then _Bposition=2 end'}
    costs={name:measure(prefix+code,version=version) for name,code in variants.items()}
    valid={name:cost['total_instructions'] for name,cost in costs.items()
           if 'error' not in before and 'error' not in cost and cost['total_instructions']<=before['total_instructions']}
    minimum=min(valid.values(),default=-1)
    return tuple(name for name,cost in valid.items() if cost==minimum)


def _chains(nodes, entry, components, statistics):
    predecessors=_predecessors(nodes)
    changed=True
    while changed:
        changed=False
        for key in list(nodes):
            if key not in nodes:continue
            node=nodes[key]
            while len(node.successors)==1:
                target=node.successors[0]
                other=nodes[target]
                if (target in (entry,key) or predecessors[target]!={key} or node.locked or other.locked
                        or key in other.successors or node.units+other.units>64
                        or len(node.code)+len(other.code)>8192):break
                if (node.blocks[-1]!=other.blocks[0]
                        and components[node.blocks[-1]]==components[other.blocks[0]]):break
                node=Node(key,node.code+node.clears[0]+other.code,other.successors,other.condition,
                    node.sources+other.sources,node.blocks+other.blocks,node.units+other.units,
                    depth=max(node.depth,other.depth),clears=other.clears)
                nodes[key]=node;del nodes[target];del predecessors[target]
                for successor in set(other.successors):
                    predecessors[successor].discard(target);predecessors[successor].add(key)
                statistics['chain_links_elided']+=1;changed=True


def _loops(nodes, entry, statistics):
    changed=True
    while changed:
        changed=False
        predecessors=_predecessors(nodes)
        for header in list(nodes.values()):
            if header.locked or len(header.successors)!=2 or len(set(header.successors))!=2:continue
            for arm,start in enumerate(header.successors):
                exit_key=header.successors[1-arm]
                path: list[Node]=[]
                seen={header.key};current=start
                while current!=header.key and current not in seen and len(path)<16:
                    node=nodes[current]
                    if node.locked or len(node.successors)!=1:break
                    seen.add(current);path.append(node);current=node.successors[0]
                if current!=header.key or exit_key in seen:continue
                cycle=[header,*path];members={node.key for node in cycle}
                incoming={node.key for node in cycle if predecessors[node.key]-members}
                if entry in members:incoming.add(entry)
                if len(incoming)!=1:
                    statistics['loop_entry_rejections']+=1;continue
                loop_entry=next(iter(incoming))
                units=sum(node.units for node in cycle)
                if units>192 or sum(len(node.code) for node in cycle)>16384 or max(node.depth for node in cycle)>=2:
                    statistics['loop_budget_rejections']+=1;continue
                position=next(i for i,node in enumerate(cycle) if node.key==loop_entry)
                ordered=cycle[position:]+cycle[:position]
                pieces=['while true do\n']
                for node in ordered:
                    pieces.append(node.code)
                    if node.key==header.key:
                        # Keep the original comparison and its reference clears;
                        # invert only the already computed Boolean, never < to >=.
                        exiting='not ('+header.condition+')' if arm==0 else header.condition
                        pieces.append('if '+exiting+' then break end\n')
                        pieces.append(node.clears[arm])
                    else:pieces.append(node.clears[0])
                pieces.append('end\n')
                replacement=Node(loop_entry,''.join(pieces),(exit_key,),None,
                    tuple(source for node in ordered for source in node.sources),
                    tuple(block for node in ordered for block in node.blocks),units,
                    depth=1+max(node.depth for node in cycle),clears=(header.clears[1-arm],))
                for key in members:del nodes[key]
                nodes[loop_entry]=replacement
                statistics['inner_loops']+=1
                statistics['loop_dispatch_edges_elided']+=len(cycle)
                changed=True;break
            if changed:break


def _render(nodes, entry, tags, state, version, compact=False):
    rng=random.Random();rng.setstate(state)
    variants=random.Random();variants.setstate(state)
    leaves=[];branches=0
    def advance(target):return '_Bposition='+str(tags[target])+'\n'
    for node in nodes.values():
        code=node.code
        if len(node.successors)==2:
            left,right=node.successors
            if compact and not node.locked and left==right:
                code+=node.clears[0]+advance(left);branches+=1
            elif compact and not node.locked and not any(node.clears) and _branch_forms(version):
                # Both tags are strictly positive numbers, hence truthy in Lua.
                form=variants.choice(_branch_forms(version))
                if form=='and-or':
                    code+='_Bposition=('+node.condition+') and '+str(tags[left])+' or '+str(tags[right])+'\n'
                else:
                    default,alternative=(right,left) if form=='default-right' else (left,right)
                    test=node.condition if form=='default-right' else 'not ('+node.condition+')'
                    code+=advance(default)+'if '+test+' then\n'+advance(alternative)+'end\n'
                branches+=1
            else:
                code+='if '+node.condition+' then\n'+node.clears[0]+advance(left)+'else\n'+node.clears[1]+advance(right)+'end\n'
        elif node.successors:code+=node.clears[0]+advance(node.successors[0])
        else:code+='_Bposition=nil\n'
        leaves.append((tags[node.key],code))
    leaves.sort()
    def tree(items):
        if len(items)==1:return items[0][1]
        middle=len(items)//2
        bound=rng.randint(items[middle-1][0]+1,items[middle][0])
        left,right=tree(items[:middle]),tree(items[middle:])
        condition='_Bposition<'+str(bound)
        if rng.getrandbits(1)==0:
            condition=str(bound)+'<=_Bposition';left,right=right,left
        return 'if '+condition+' then\n'+left+'else\n'+right+'end\n'
    source=('--[[VM_DISPATCH_ENTRY]]\nlocal _Bposition='+str(tags[entry])+
            '\nwhile _Bposition do\n'+tree(leaves)+'end\n')
    return source,branches


def transform(nodes, entry, components, statistics):
    _chains(nodes,entry,components,statistics)
    _loops(nodes,entry,statistics)
    _chains(nodes,entry,components,statistics)


def emit(function, emitter, segments, entries, rng):
    nodes={}
    for index,segment in enumerate(segments):
        code=emitter.instructions(segment.instructions,segment.block)
        successors=((segment.following,) if segment.following is not None else
                    tuple(entries[key] for key in segment.block.successors))
        condition=emitter.condition(segment.block) if len(successors)==2 else None
        locked=(bool(function.debug_metadata.get('security_owned') or function.debug_metadata.get('morph_strategies'))
            or any(i.metadata.get('protection_origin') in ('junk','ir_morph') or i.metadata.get('morph_origin')
                   for i in segment.instructions))
        units=sum(not i.metadata.get('bare_call_skip',False) for i in segment.instructions)
        clears=(('',) if segment.following is not None else
                tuple(emitter.edge_clear(segment.block,key) for key in segment.block.successors))
        nodes[index]=Node(index,code,successors,condition,(index,),(segment.block.id,),units,locked,clears=clears)
    tags={index:segment.position for index,segment in enumerate(segments)}
    entry=entries[function.blocks[0].id];state=rng.getstate()
    baseline,_=_render(nodes,entry,tags,state,emitter.program.version)
    if function.debug_metadata.get('security_owned'):return baseline
    statistics: Counter[str]=Counter()
    # Replace nodes, not their code/instruction lists; this leaves the original
    # protected IR and the baseline rendering untouched for admission/diagnostics.
    candidate=dict(nodes)
    transform(candidate,entry,emitter.facts.components,statistics)
    sources=[source for node in candidate.values() for source in node.sources]
    if sorted(sources)!=list(nodes):raise RuntimeError('Bare flow planning lost or duplicated a segment')
    # A default-state write evaluates one extra tag. Do not duplicate expensive
    # literal producers introduced by these optional later output passes.
    compact=not (set(emitter.program.context.output_passes)&{'number_obf','meme_strings'})
    optimized,branches=_render(candidate,entry,tags,state,emitter.program.version,compact=compact)
    statistics['compact_branches']=branches
    if optimized==baseline:
        emitter.program.flow_plans.append({'function':function.id,'admitted':False,'reason':'no-flow-change',
            'segments_before':len(nodes),'segments_after':len(nodes),
            'source_bytes_before':len(baseline),'source_bytes_after':len(baseline),
            'compiler_before':None,'compiler_after':None,
            'groups':tuple({'entry':n.key,'sources':n.sources,'loop_depth':n.depth,'locked':n.locked}
                           for n in nodes.values())})
        return baseline
    from ...passes.function_costs import measure
    names=[*('_Br'+str(i) for i in emitter.local_slots),'_BX','_BS','_BT','_Bcondition']
    prefix='local '+','.join(names)+'\n'
    before=measure(prefix+baseline,version=emitter.program.version)
    after=measure(prefix+optimized,version=emitter.program.version)
    admitted=('error' not in before and 'error' not in after
              and after['total_instructions']<=before['total_instructions'] and len(optimized)<=len(baseline))
    diagnostic={'function':function.id,'admitted':admitted,'segments_before':len(nodes),
        'segments_after':len(candidate),'source_bytes_before':len(baseline),'source_bytes_after':len(optimized),
        'compiler_before':before.get('total_instructions'),'compiler_after':after.get('total_instructions'),
        'groups':tuple({'entry':n.key,'sources':n.sources,'loop_depth':n.depth,'locked':n.locked}
                       for n in candidate.values())}
    emitter.program.flow_plans.append(diagnostic)
    if admitted:
        emitter.program.optimization.update(statistics)
        return optimized
    emitter.program.optimization['flow_cost_rejections']+=1
    return baseline
