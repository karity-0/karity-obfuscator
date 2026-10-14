"""Bounded numeric DAG discovery with explicit proof and event obligations."""
from collections import Counter
from dataclasses import replace
import hashlib
from .model import Ref, Step, Binding, Recipe, Occurrence, Cost, SynthesisPlan
from ..ir.facts import analyze_function

SCALAR=frozenset(('ADD','SUB','MUL','NEGATE'))
POLICIES=('efficiency','balanced','protection')


def _facts(function,version,cache,liveness_cache=None):
    facts=cache.get(function.id)
    if facts is None or facts.function is not function or facts.version!=version:
        facts=analyze_function(function,version,liveness=(liveness_cache or {}).get(function.id))
        cache[function.id]=facts
    return facts


def backend_work(occurrence,backend):
    """Structural work, deliberately not an unverified nanosecond model."""
    cost=occurrence.cost
    saved_dispatch=0 if backend=='mov' else cost.dispatch_before-cost.dispatch_after
    saved_reads=cost.reads_before-cost.reads_after
    saved_writes=cost.writes_before-cost.writes_after
    extra_scope=2 if backend=='mov' else 0
    return {'dispatch_saved':saved_dispatch,'bank_reads_saved':saved_reads,
        'bank_writes_saved':saved_writes,'scope_instructions_added':extra_scope,
        'net_work_estimate':saved_dispatch+saved_reads+saved_writes-extra_scope}


def _signature(recipe):
    return hashlib.sha256(repr((recipe.domain,recipe.input_kinds,recipe.steps,
                                recipe.outputs,recipe.edges)).encode()).hexdigest()[:24]


def _region(function,block,instructions,facts,version,materialize=False):
    """Convert register aliases to ordered value versions, never reassociate."""
    bindings=[];input_indices={};values={};last_write={};steps=[];edges=[];reads=0
    for index,ins in enumerate(instructions):
        args=[]
        for operand in ins.operands:
            if operand.role=='destination':continue
            if operand.kind=='register':reads+=1
            reference=values.get(operand.value) if operand.kind=='register' else None
            if reference is None:
                key=(operand.kind,operand.value)
                if key not in input_indices:
                    input_indices[key]=len(bindings);bindings.append(Binding(*key))
                reference=Ref('input',input_indices[key])
            else:edges.append((reference.index,index))
            args.append(reference)
        steps.append(Step(ins.operation,tuple(args)))
        dst=next(v.value for v in ins.operands if v.role=='destination')
        values[dst]=Ref('temporary',index);last_write[dst]=index
    # A dataflow-connected multi-operation region differs from concatenation.
    connected={x for edge in edges for x in edge}
    if len(steps)<3 or len(connected)!=len(steps):return None,'no_connected_dag'
    live=facts.liveness.after[instructions[-1].id]
    output_pairs=sorted((index,r) for r,index in last_write.items()
                        if f'{function.id}:r{r}' in live)
    if not output_pairs:return None,'no_live_output'
    recipe=Recipe('',version,tuple(v.kind for v in bindings),tuple(steps),
                  tuple(i for i,r in output_pairs),tuple(edges))
    recipe=replace(recipe,id='recipe:'+_signature(recipe))
    output_regs=tuple(r for i,r in output_pairs)
    component=facts.components[block.id]
    hot=facts.component_sizes[component]>1 or block.id in block.successors
    cost=Cost(len(steps),(len(steps)+1)//2,1,reads,
              reads if materialize else sum(v.kind=='register' for v in bindings),len(steps),len(steps) if materialize else len(output_regs),
              # Conservative prototype estimate: tag + up to two uint bytes.
              3*len(bindings)+2*len(output_regs),hot,len(steps),6*len(steps))
    occurrence=Occurrence(function.id,block.id,tuple(i.id for i in instructions),
                          recipe.id,tuple(bindings),output_regs,cost,'shared',materialize,
                          'integer' if version=='5.3' and all(
                              facts.operand(ins,v.role).kind=='integer'
                              for ins in instructions for v in ins.operands if v.role!='destination') else 'number')
    return (recipe,occurrence),None


def build_plan(ir,*,lua_version='5.3',enabled=False,policy='balanced',seed=0,max_steps=8,
               max_recipes=32,max_occurrences=512,protection_plan=None,backend='prototype',analysis_cache=None,liveness_cache=None):
    if policy not in POLICIES:raise ValueError('unknown synthesis policy')
    if lua_version not in ('5.1','5.3'):raise ValueError('unknown Lua target')
    if backend not in ('prototype','classic','karity','mov'):raise ValueError('unknown synthesis backend')
    if not 3<=max_steps<=16 or not 1<=max_recipes<=256 or not 1<=max_occurrences<=4096:
        raise ValueError('invalid synthesis budget')
    if protection_plan is not None and protection_plan.generation!=ir.generation:
        raise ValueError('synthesis/protection generation mismatch')
    if not enabled:return SynthesisPlan(ir.generation,lua_version,(),(),())
    rejected=Counter();candidates=[];analyses={} if analysis_cache is None else analysis_cache
    for function in ir.functions():
        if not any(i.operation in SCALAR for b in function.blocks for i in b.instructions):continue
        facts=_facts(function,lua_version,analyses,liveness_cache)
        if facts.liveness.open_extents:
            rejected['open_register_top']+=1;continue
        # The prototype cannot replay private production dispatch/epoch events.
        # Refuse planned regions rather than drop arbitrary protection fields.
        if protection_plan is not None and backend=='prototype':
            rejected['production_event_lowering_not_implemented']+=1;continue
        for block in function.blocks:
            run=[]
            def flush():
                if len(run)<3:return
                materialize=backend=='karity' or any(i.metadata.get('protection_origin') for i in run)
                found,reason=_region(function,block,run,facts,lua_version,materialize)
                if found:candidates.append(found)
                else:rejected[reason]+=1
            for ins in block.instructions:
                reason=None
                if ins.operation not in SCALAR:reason='non_scalar_boundary'
                elif ins.metadata.get('protection_origin') and backend=='prototype':reason='protection_origin'
                elif ins.id not in facts.effects:reason='unreachable'
                elif facts.effects[ins.id].boundaries:reason='lifetime_or_effect_boundary'
                elif facts.liveness.captured_before[ins.id]:reason='active_capture'
                elif not facts.effects[ins.id].pure:reason='unknown_or_metamethod'
                elif any(facts.operand(ins,v.role).kind not in ('integer','float','number')
                         for v in ins.operands if v.role!='destination'):
                    reason='unproven_numeric'
                if reason:
                    flush();run=[]
                    if ins.operation in SCALAR:rejected[reason]+=1
                    continue
                run.append(ins)
                if len(run)==max_steps:flush();run=[]
            flush()
    definitions={};occurrences=[]
    repetitions=Counter(recipe.id for recipe,_ in candidates)
    regional_count=0
    if policy=='efficiency' and backend!='prototype':
        candidates.sort(key=lambda item:(item[1].cost.loop_region,repetitions[item[0].id],backend_work(item[1],backend)['net_work_estimate']),reverse=True)
    for recipe,occurrence in candidates:
        # No claimed nanosecond speedup: retain structural dispatch/access
        # costs separately from the logical events that must still run.
        if occurrence.cost.dispatch_before<=occurrence.cost.dispatch_after:
            rejected['no_dispatch_saving']+=1;continue
        if occurrence.cost.writes_before<=occurrence.cost.writes_after and backend=='prototype':
            rejected['no_register_local_saving']+=1;continue
        if backend!='prototype' and policy=='efficiency' and not occurrence.cost.loop_region and repetitions[recipe.id]<2:
            rejected['cold_single_use_cost']+=1;continue
        if backend!='prototype' and policy=='efficiency' and backend_work(occurrence,backend)['net_work_estimate']<=0:
            rejected['backend_event_cost']+=1;continue
        # Regional forms are selected later with actual emitted/compiler costs.
        # The standalone prototype keeps the policy's simple regional contract.
        regional=policy=='protection'
        if regional:
            recipe=replace(recipe,id=recipe.id+':region:'+occurrence.source_ids[0])
            occurrence=replace(occurrence,recipe=recipe.id,scope='regional')
        if recipe.id not in definitions and len(definitions)>=max_recipes:
            rejected['recipe_budget']+=1;continue
        if len(occurrences)>=max_occurrences:
            rejected['occurrence_budget']+=1;continue
        definitions[recipe.id]=recipe;occurrences.append(occurrence)
        regional_count+=int(regional)
    plan=SynthesisPlan(ir.generation,lua_version,tuple(definitions.values()),
                       tuple(occurrences),tuple(sorted(rejected.items())),backend,
                       hashlib.sha256(protection_plan.dump().encode()).hexdigest() if protection_plan else '')
    validate_plan(ir,plan,lua_version=lua_version,protection_plan=protection_plan,analysis_cache=analyses)
    return plan


def validate_plan(ir,plan,*,lua_version=None,protection_plan=None,analysis_cache=None):
    if plan.backend not in ('prototype','classic','karity','mov'):
        raise ValueError('unknown synthesis backend contract')
    if ir.generation!=plan.generation or plan.version not in ('5.1','5.3') or lua_version is not None and lua_version!=plan.version:
        raise ValueError('synthesis generation/version mismatch')
    if plan.protection_signature:
        if protection_plan is None or protection_plan.generation!=ir.generation or hashlib.sha256(protection_plan.dump().encode()).hexdigest()!=plan.protection_signature:
            raise ValueError('synthesis protection contract mismatch')
    functions={f.id:f for f in ir.functions()};recipes={r.id:r for r in plan.recipes}
    if len(plan.recipes)>256 or len(plan.occurrences)>4096:raise ValueError('synthesis plan exceeds bounds')
    if len(recipes)!=len(plan.recipes):raise ValueError('duplicate recipe ID')
    consumed=set();used=set();analyses={} if analysis_cache is None else analysis_cache
    for occurrence in plan.occurrences:
        function=functions.get(occurrence.function)
        if function is None:raise ValueError('unknown synthesis function')
        block=next((b for b in function.blocks if b.id==occurrence.block),None)
        if block is None:raise ValueError('unknown synthesis block')
        positions={i.id:n for n,i in enumerate(block.instructions)}
        indices=[positions.get(i,-1) for i in occurrence.source_ids]
        if not 3<=len(indices)<=16 or any(i<0 for i in indices) or indices!=list(range(indices[0],indices[0]+len(indices))):
            raise ValueError('non-contiguous or reordered synthesis region')
        if consumed.intersection(occurrence.source_ids):raise ValueError('overlapping synthesis regions')
        consumed.update(occurrence.source_ids)
        facts=_facts(function,plan.version,analyses)
        original=tuple(block.instructions[n] for n in indices)
        if any(i.operation not in SCALAR or i.metadata.get('protection_origin') and plan.backend=='prototype'
               or i.id not in facts.effects or not facts.effects[i.id].pure
               or facts.effects[i.id].boundaries or facts.liveness.captured_before[i.id]
               for i in original) or facts.liveness.open_extents:
            raise ValueError('unsafe synthesis region')
        materialize=plan.backend=='karity' or any(i.metadata.get('protection_origin') for i in original)
        if plan.backend=='prototype':materialize=False
        expected,reason=_region(function,block,original,facts,plan.version,materialize)
        if expected is None:raise ValueError('invalid synthesis DAG: '+reason)
        expected_recipe,expected_occurrence=expected
        actual=recipes.get(occurrence.recipe)
        if actual is None:raise ValueError('missing recipe')
        if replace(actual,id=expected_recipe.id)!=expected_recipe:
            raise ValueError('recipe semantic definition differs from source')
        if replace(occurrence,recipe=expected_occurrence.recipe,scope='shared')!=expected_occurrence:
            raise ValueError('recipe operand/fallback binding differs from source')
        if occurrence.scope not in ('shared','regional'):raise ValueError('invalid sharing scope')
        expected_id=expected_recipe.id if occurrence.scope=='shared' else expected_recipe.id+':region:'+occurrence.source_ids[0]
        if actual.id!=expected_id:raise ValueError('recipe signature/scope identity mismatch')
        used.add(actual.id)
    if used!=recipes.keys():raise ValueError('unused recipe retained')
