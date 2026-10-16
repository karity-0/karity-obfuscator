"""Bounded ordered DAG discovery with explicit proof and event obligations."""
from collections import Counter
from dataclasses import replace
import hashlib
from .model import Ref, Step, Binding, Recipe, Occurrence, Cost, SynthesisPlan
from ..ir.facts import analyze_function

from .strategies import NUMERIC, INTEGER_BITS, SCALAR, SUPPORTED, TERMINAL, inputs, rejection, ordered, materialized, linear_chains
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
    shape=(recipe.domain,recipe.input_kinds,recipe.steps,recipe.outputs,recipe.edges)
    if recipe.ordered:shape+=('ordered',)
    return hashlib.sha256(repr(shape).encode()).hexdigest()[:24]


def _region(function,block,instructions,facts,version,materialize=False,backend='prototype'):
    """Convert register aliases to ordered value versions, never reassociate."""
    bindings=[];input_indices={};values={};last_write={};steps=[];edges=[];reads=0
    if any(i.operation in TERMINAL for i in instructions[:-1]):
        return None,'nonterminal_control_or_call'
    for index,ins in enumerate(instructions):
        args=[]
        for operand in inputs(ins):
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
        if facts.effects[ins.id].may_call:
            # A metamethod can write an owner's captured locals. Later reads
            # are fresh observations, never edges to a stale value version.
            for name in facts.liveness.captured_before[ins.id]:
                reg=int(name.rsplit(':r',1)[1]);values.pop(reg,None);last_write.pop(reg,None)
                input_indices.pop(('register',reg),None)
            input_indices={key:value for key,value in input_indices.items() if key[0]!='upvalue'}
        if ins.operation not in TERMINAL:
            dst=next(v.value for v in ins.operands if v.role=='destination')
            values[dst]=Ref('temporary',index);last_write[dst]=index
        else:
            # Calls can overwrite several registers (or runtime top). Their
            # results never become local SSA temporaries in a terminal recipe.
            for name in ins.outputs:
                if name.startswith(function.id+':r'):
                    last_write.pop(int(name.rsplit(':r',1)[1]),None)
    # A dataflow-connected multi-operation region differs from concatenation.
    connected={x for edge in edges for x in edge}
    if len(steps)<3 or len(connected)!=len(steps):return None,'no_connected_dag'
    reachable={0};pending=[0];neighbors={n:set() for n in connected}
    for a,b in edges:neighbors[a].add(b);neighbors[b].add(a)
    while pending:
        for n in neighbors[pending.pop()]-reachable:reachable.add(n);pending.append(n)
    if len(reachable)!=len(steps):return None,'disconnected_dags'
    live=facts.liveness.after[instructions[-1].id]
    output_pairs=sorted((index,r) for r,index in last_write.items()
                        if f'{function.id}:r{r}' in live)
    if not output_pairs and instructions[-1].operation not in TERMINAL:return None,'no_live_output'
    recipe=Recipe('',version,tuple(v.kind for v in bindings),tuple(steps),
                  tuple(i for i,r in output_pairs),tuple(edges),ordered(instructions,facts))
    recipe=replace(recipe,id='recipe:'+_signature(recipe))
    output_regs=tuple(r for i,r in output_pairs)
    # Karity keeps every encoded commit. Only proven scalar producers can
    # lend raw intermediate values, guarded by the shared epoch/map state.
    local_values=tuple(n for n,i in enumerate(instructions) if backend=='karity' and not ordered(instructions,facts)
        and i.operation in SCALAR and facts.effects[i.id].pure
        and any(a==n for a,b in edges))
    block_ids={facts.locations[i.id][0] for i in instructions}
    hot=any(facts.component_sizes[facts.components[b]]>1 or
            b in function.blocks[facts.block_indices[b]].successors for b in block_ids)
    writes=sum(len(i.outputs) for i in instructions)
    cost=Cost(len(steps),(len(steps)+1)//2,1,reads,
              reads if materialize else sum(v.kind=='register' for v in bindings),writes,writes if materialize else len(output_regs),
              # Conservative prototype estimate: tag + up to two uint bytes.
              3*len(bindings)+2*len(output_regs),hot,len(steps),6*len(steps))
    occurrence=Occurrence(function.id,facts.locations[instructions[0].id][0],tuple(i.id for i in instructions),
                          recipe.id,tuple(bindings),output_regs,cost,'shared',materialize,
                          'ordered' if ordered(instructions,facts) else 'integer' if version=='5.3' and all(
                              facts.operand(ins,v.role).kind=='integer'
                              for ins in instructions for v in ins.operands if v.role!='destination') else 'number',local_values)
    return (recipe,occurrence),None


def discover_windows(function,block,run,facts,version,backend):
    """Bounded contiguous discovery, also used when a larger candidate falls back."""
    found=[];start=0;failure=None
    while start+3<=len(run):
        for end in range(len(run),start+2,-1):
            window=run[start:end]
            item,reason=_region(function,block,window,facts,version,
                                materialized(window,facts,backend),backend)
            if item:
                found.append(item);start=end;break
            failure=reason
        else:
            start+=1
    return found,failure


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
        if not any(i.operation in SUPPORTED for b in function.blocks for i in b.instructions):continue
        facts=_facts(function,lua_version,analyses,liveness_cache)
        if facts.liveness.open_extents and backend=='prototype':
            rejected['open_register_top']+=1;continue
        # The prototype cannot replay private production dispatch/epoch events.
        # Refuse planned regions rather than drop arbitrary protection fields.
        if protection_plan is not None and backend=='prototype':
            rejected['production_event_lowering_not_implemented']+=1;continue
        for chain in linear_chains(function,facts,backend):
            block=chain[0]
            run=[]
            def flush():
                # Bounded contiguous windows can retain a useful DAG beside
                # an unrelated move/read without moving any effectful step.
                found,failure=discover_windows(function,block,run,facts,lua_version,backend)
                candidates.extend(found)
                if failure:rejected[failure]+=1
            for ins in (i for b in chain for i in b.instructions):
                reason=rejection(ins,facts,lua_version,backend)
                if reason:
                    flush();run=[]
                    if ins.operation in SUPPORTED:rejected[reason]+=1
                    continue
                run.append(ins)
                if len(run)==max_steps or ins.operation in TERMINAL:flush();run=[]
            flush()
    definitions={};occurrences=[]
    repetitions=Counter(recipe.id for recipe,_ in candidates)
    regional_count=0
    if backend!='prototype':
        # A newly supported cold call/branch must not consume a small recipe
        # budget before recurring loop DAGs in child functions are considered.
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
    chain_positions={}
    for occurrence in plan.occurrences:
        function=functions.get(occurrence.function)
        if function is None:raise ValueError('unknown synthesis function')
        block=next((b for b in function.blocks if b.id==occurrence.block),None)
        if block is None:raise ValueError('unknown synthesis block')
        facts=_facts(function,plan.version,analyses)
        if function.id not in chain_positions:
            records={}
            for chain in linear_chains(function,facts,plan.backend):
                instructions=tuple(i for b in chain for i in b.instructions)
                positions={i.id:n for n,i in enumerate(instructions)}
                records.update((b.id,(instructions,positions)) for b in chain)
            chain_positions[function.id]=records
        instructions,positions=chain_positions[function.id][block.id]
        indices=[positions.get(i,-1) for i in occurrence.source_ids]
        if not 3<=len(indices)<=16 or any(i<0 for i in indices) or indices!=list(range(indices[0],indices[0]+len(indices))):
            raise ValueError('non-contiguous or reordered synthesis region')
        if consumed.intersection(occurrence.source_ids):raise ValueError('overlapping synthesis regions')
        consumed.update(occurrence.source_ids)
        original=tuple(instructions[n] for n in indices)
        if any(rejection(i,facts,plan.version,plan.backend) for i in original):
            raise ValueError('unsafe synthesis region')
        materialize=materialized(original,facts,plan.backend)
        expected,reason=_region(function,block,original,facts,plan.version,materialize,plan.backend)
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
