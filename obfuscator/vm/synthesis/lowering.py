"""Shared physical ownership and vop allocation; runtime semantics stay backend-owned."""
from dataclasses import dataclass,replace
import hashlib,random,time
from .planner import build_plan,validate_plan,backend_work
from .model import Occurrence,Recipe


@dataclass(frozen=True)
class PhysicalRecipe:
    occurrence: Occurrence
    recipe: Recipe
    start: int
    opcode: int
    original_vops: tuple[int,...]
    destinations: tuple[int,...]


def plan_synthesis(lowered,context):
    if not context.options.get('opcode_synthesis',False):return
    started=time.perf_counter()
    plan=build_plan(lowered.semantic_ir,lua_version=context.target.lua_version if context.target else '5.3',
        enabled=True,policy=context.options.get('synthesis_policy','balanced'),
        seed=int(lowered.semantic_ir.generation,16),
        max_steps=int(context.options.get('synthesis_max_steps',6)),
        max_recipes=int(context.options.get('synthesis_max_recipes',32)),
        max_occurrences=int(context.options.get('synthesis_max_occurrences',512)),
        protection_plan=lowered.protection_plan,backend=lowered.backend)
    lowered.backend_data['synthesis_plan']=plan
    lowered.backend_data['synthesis_handler_budget']=int(context.options.get('synthesis_max_recipes',32))
    context.profile.append({'phase':'opcode_synthesis','elapsed':time.perf_counter()-started,
        'recipes':len(plan.recipes),'regions':len(plan.occurrences),'rejected':dict(plan.rejected),
        'policy':context.options.get('synthesis_policy','balanced'),
        'dispatch_saved_static':sum(o.cost.dispatch_before-o.cost.dispatch_after for o in plan.occurrences),
        'saved_vs_pair_fusion_estimate':sum(o.cost.fusion_dispatch_estimate-o.cost.dispatch_after for o in plan.occurrences),
        'register_reads_saved_static':sum(o.cost.reads_before-o.cost.reads_after for o in plan.occurrences),
        'register_writes_saved_static':sum(o.cost.writes_before-o.cost.writes_after for o in plan.occurrences),
        'logical_events_retained':sum(o.cost.logical_events_after for o in plan.occurrences),
        'operand_slot_bytes':sum(o.cost.operand_slot_bytes for o in plan.occurrences),
        'dispatch_model':'semantic region; MOV microdispatches measured separately' if lowered.backend=='mov' else 'handler',
        'backend_work':[{'sources':o.source_ids,**backend_work(o,lowered.backend)} for o in plan.occurrences],
        'cost_basis':'structural VM bank accesses; helper calls, load and graphs measured separately'})


def prepare_ranges(lowered,targets):
    plan=lowered.backend_data.get('synthesis_plan')
    if plan is None:return
    if plan.backend!=lowered.backend:raise ValueError('synthesis/backend contract mismatch')
    validate_plan(lowered.semantic_ir,plan,protection_plan=lowered.protection_plan)
    occurrences={}
    for o in plan.occurrences:occurrences.setdefault(o.function,[]).append(o)
    groups=set();fallbacks=0;admitted=set();diagnostics=[]
    root=lowered.protection_plan.functions[lowered.semantic_ir.root.id]
    def visit(fn):
        nonlocal fallbacks
        state=targets[id(fn)];ranges={};by_id={i.source_id:n for n,i in enumerate(fn.code) if not i.linker_owned}
        for occurrence in occurrences.get(fn.id,()):
            indexes=[by_id.get(i,-1) for i in occurrence.source_ids]
            if any(i<0 for i in indexes) or indexes!=list(range(indexes[0],indexes[0]+len(indexes))):
                diagnostics.append({'function':fn.id,'sources':occurrence.source_ids,'reason':'non_contiguous_operand_slots'})
                fallbacks+=1
                continue # Exact source fallback, no code mutated.
            start=indexes[0];end=indexes[-1]+1
            vm=state['vm_assignment'];counts=dict(root['alias_requirements'][vm]['operations'])
            signatures=set()
            for variant in range(len(state['instruction_forms'][start])):
                signature=tuple((fn.code[i].operation,'defer' if lowered.backend=='karity' and state['instruction_forms'][i][variant][0]=='defer' else state['alias_variants'][i]%counts[fn.code[i].operation]) for i in indexes)
                signatures.add((vm,occurrence.recipe,signature,occurrence.materialize))
            if len(groups|signatures)>lowered.backend_data['synthesis_handler_budget']:
                diagnostics.append({'function':fn.id,'sources':occurrence.source_ids,'reason':'physical_handler_budget'})
                fallbacks+=1;continue
            groups.update(signatures)
            ranges[start]=(end,occurrence)
            admitted.add((fn.id,occurrence.source_ids))
            for index in indexes:
                # Synthesis owns this area. Split/fuse/defer remains elsewhere.
                state['instruction_forms'][index]=tuple(form if form[0]=='defer' else ('normal',1) for form in state['instruction_forms'][index])
            state['block_variants'][start]=any(state['block_variants'].get(i,False) for i in indexes)
        state['synthesis_ranges']=ranges
        for child in fn.protos:visit(child)
    visit(lowered.program)
    lowered.backend_data['synthesis_pre_lowering_fallbacks']=fallbacks
    lowered.backend_data['synthesis_admitted']=admitted
    lowered.backend_data['synthesis_fallback_diagnostics']=diagnostics


def install_regions(lowered,functions,vm_maps,context):
    plan=lowered.backend_data.get('synthesis_plan')
    if plan is None:return
    recipes={r.id:r for r in plan.recipes}
    heads={(o.function,o.source_ids[0]):o for o in plan.occurrences}
    from ..backends.runtime_layout import iter_functions
    used={v for aliases,splits,fuses,defers in vm_maps for values in aliases.values() for v in values}
    for _,splits,fuses,defers in vm_maps:
        used.update(v for forms in splits.values() for values in forms.values() for v in values)
        used.update(fuses.values());used.update(defers.values())
    seed=int.from_bytes(hashlib.blake2b(plan.dump().encode(),digest_size=8).digest(),'little')
    rng=random.Random(seed);available=[v for v in range(32768) if v not in used];rng.shuffle(available)
    definitions={};slots=0;installed=set()
    for fn in iter_functions(functions):
        code=fn.code;regions=[]
        i=0
        while i<len(code):
            candidate=heads.get((fn.source.id,code[i].instruction.source_id))
            matches=(candidate,) if candidate else ()
            matched=None
            for o in matches:
                n=len(o.source_ids);group=code[i:i+n]
                if tuple(s.instruction.source_id for s in group)!=o.source_ids:continue
                aliases=vm_maps[fn.vm_id][0]
                defers=vm_maps[fn.vm_id][3]
                if any(s.vop not in (*aliases.get(s.instruction.op,()),defers.get(s.instruction.op)) for s in group):continue
                matched=o;break
            if matched is None:i+=1;continue
            group=code[i:i+len(matched.source_ids)];vops=tuple(s.vop for s in group)
            # Original alias transitions are part of recipe specialization.
            key=(fn.vm_id,matched.recipe,vops,matched.materialize)
            if key not in definitions:
                if not available:raise ValueError('synthesis opcode space exhausted after layout admission')
                definitions[key]=available.pop()
            vop=definitions[key]
            entry=PhysicalRecipe(matched,recipes[matched.recipe],i,vop,vops,tuple(s.instruction.a for s in group))
            regions.append(entry);code[i]=replace(code[i],vop=vop);i+=len(group);slots+=1
            installed.add((matched.function,matched.source_ids))
        fn.synthesis=tuple(regions)
    missing=lowered.backend_data['synthesis_admitted']-installed
    if missing:raise ValueError(f'admitted synthesis regions lost by physical layout: {sorted(missing)!r}')
    lowered.backend_data['synthesis_definitions']=definitions
    context.profile.append({'phase':'synthesis_physical','elapsed':0.,'regions':slots,
        'handlers':len(definitions),'fallback_regions':len(plan.occurrences)-len(installed),
        'fallback_diagnostics':lowered.backend_data['synthesis_fallback_diagnostics'],
        'operand_encoding':'retained_48bit_event_slots'})


def first_aliases(lowered,vm_index):
    from ..backends.runtime_layout import iter_functions
    return {e.opcode:e.original_vops[0] for f in iter_functions(lowered.backend_data['layout'].functions)
            if f.vm_id==vm_index for e in f.synthesis}


def dump_plan(lowered):
    import json
    from dataclasses import asdict
    from ..backends.runtime_layout import iter_functions
    plan=lowered.backend_data.get('synthesis_plan')
    if plan is None:return '{"enabled":false}\n'
    data={'enabled':True,**asdict(plan)}
    data['physical']=[{'function':f.source.id,'vm':f.vm_id,'start':e.start,'vop':e.opcode,
        'recipe':e.recipe.id,'sources':e.occurrence.source_ids,'original_vops':e.original_vops,
        'materialize':e.occurrence.materialize} for f in iter_functions(lowered.backend_data['layout'].functions) for e in f.synthesis]
    data['fallback_diagnostics']=lowered.backend_data.get('synthesis_fallback_diagnostics',[])
    data['emission']=list(lowered.backend_data.get('synthesis_emission',{}).values())
    return json.dumps(data,indent=2,sort_keys=True)+'\n'
