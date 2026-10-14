"""Cost admission before physical ownership; protection diversity is a separate budget.

Compiler counts measure generated code, not helper runtime nanoseconds. Retained
graph, route, epoch and pending events cancel only in the *difference*: they are
reported explicitly and never assumed removable. No benchmark input is executed
during an ordinary build and no source-dependent wall-time prediction is made.
"""
from collections import Counter
from dataclasses import replace
import hashlib
import time

from ...passes.function_costs import measure, MAX_JUMP
from .planner import backend_work, validate_plan


def compiled(body, version):
    started=time.perf_counter()
    report=measure(body,version=version)
    if 'error' in report:return {'bytes':len(body.encode()),'error':report['error']}
    return {'bytes':len(body.encode()),'instructions':report['total_instructions'],'probe_seconds':time.perf_counter()-started,
            'max_jump':max(row['max_jump'] for row in report['functions']),
            'stack':max(row['stack'] for row in report['functions'])}


def kernel_context(lowered,variant,source):
    from ..vm_obfuscation import _inline_fetch_decode
    a=source.index('--<<FETCH>>')+len('--<<FETCH>>')
    b=source.index('--<<ENDFETCH>>',a)
    fetch=source[a:b].strip()
    native='--<<TARGET_CLASSIC_EXEC_NATIVE>>' in source or '--<<TARGET_KARITY_EXEC_STATE>>' in source
    if lowered.backend=='karity':
        prefix='--<<TARGET_KARITY_EXEC_STATE>>' if native else ''
        fetch=_inline_fetch_decode(prefix+'--<<FETCH>>--<<ENDFETCH>>',variant['helper_fetch_variant'])[len(prefix):]
        if native:fetch=fetch.replace('(_S[611] or 0)~(_XF[1] or 0)','_pxor(_S[611] or 0,_XF[1] or 0)')
    return fetch,native


def compile_entry(entry,lowered,variant,source,vm_maps):
    """The same renderer and planned mutation stream as final emission."""
    from .emission import render_kernel
    from ..vm_mutation import mutate_handlers,planned_mutation_seeds,_native_scratch_locals
    import re
    fetch,native=kernel_context(lowered,variant,source)
    body=render_kernel(entry,lowered,variant,fetch,vm_maps[0],vm_maps[3],native)
    if variant['mutate_handlers']:
        body=mutate_handlers({0:body},native_state=native,planned_seeds=planned_mutation_seeds(
            variant['mutation_seed'],{0:'synthesis:'+entry.recipe.id}))[0]
        if len(set(re.findall(r'\blocal\s+([A-Za-z_]\w*)',body)))>200//4:
            body=_native_scratch_locals(body,0,0,scratch_name='_SYN_TEMPS',rewrite_helpers=False)
    return compiled(body,'5.1' if native else '5.3')


def choose_regions(lowered,targets,vm_maps,context):
    """Measure both execution forms and admit within per-VM code/compiler budgets.

Balanced regional sharing consumes actual remaining code capacity, rather than
an RNG probability or an arbitrary fraction of the recipe count. Protection can
pay for distinct forms even without a performance saving. Efficiency never does.
"""
    plan=lowered.backend_data['synthesis_plan']
    if not plan.occurrences:return
    growth=float(context.options.get('synthesis_max_code_growth',.1))
    if growth==0:
        rejected=Counter(dict(plan.rejected));rejected['emitted_code_budget']+=len(plan.occurrences)
        decisions=tuple({'sources':o.source_ids,'fallback':'emitted_code_budget','code_budget_bytes':0} for o in plan.occurrences)
        lowered.backend_data['synthesis_plan']=replace(plan,recipes=(),occurrences=(),rejected=tuple(sorted(rejected.items())),decisions=decisions)
        context.profile.append({'phase':'synthesis_cost_selection','elapsed':0.,'recipes':0,'regions':0,'decisions':decisions})
        return
    from .lowering import PhysicalRecipe
    from ..backends.runtime_variants import resolve_runtime_variants
    from ..backends.handler_ir import OPERATION_IDS
    from ..backends.runtime_templates import classic_executor
    from pathlib import Path
    started=time.perf_counter()
    variants=resolve_runtime_variants(lowered)
    target=context.target
    loader=target.runtime_template('vm.lua') if target else (Path(__file__).parents[1]/'vm.lua').read_text(encoding='utf-8')
    source=loader if lowered.backend=='karity' else target.runtime_template('classic_exec.lua') if target else classic_executor()
    policy=context.options.get('synthesis_policy','balanced')
    # Growth is an explicit cost allowance, independent of hard compiler safety.
    multiplier={'efficiency':.5,'balanced':1.,'protection':2.}[policy]
    byte_budget=int(len(loader.encode())*growth*multiplier)
    fn_by_id={};indexes_by_function={}
    def visit(fn):
        fn_by_id[fn.id]=fn
        indexes_by_function[fn.id]={ins.source_id:n for n,ins in enumerate(fn.code) if not ins.linker_owned}
        for child in fn.protos:visit(child)
    visit(lowered.program)
    helper_costs={}
    if lowered.backend=='classic':
        for name in ('RGET','RSET'):
            body=source.split('--<<'+name+'>>',1)[1].split('--<<END'+name+'>>',1)[0]
            report=measure(body,version=plan.version)
            helper_costs[name.lower()]=report['functions'][1]['instructions']
    definitions={};occurrences=[];decisions=[];rejected=Counter(dict(plan.rejected))
    spent=Counter();compiler_spent=Counter();measured={};forms={};repeats=Counter(o.recipe for o in plan.occurrences)
    mov_runtime_costs={};mov_shared_reserved=Counter()
    recipes={r.id:r for r in plan.recipes}
    dispatch=compiled('while true do if op==selector then work() else break end end',plan.version)['instructions']
    for occurrence in plan.occurrences:
        fn=fn_by_id[occurrence.function];state=targets[id(fn)];vm=state['vm_assignment']
        indexes=indexes_by_function[fn.id]
        raw=[fn.code[indexes[s]] for s in occurrence.source_ids]
        original=[]
        for ins in raw:
            n=indexes[ins.source_id];op=OPERATION_IDS[ins.operation]
            original.append(vm_maps[vm][3][op] if lowered.backend=='karity' and state['instruction_forms'][n][0][0]=='defer'
                            else vm_maps[vm][0][op][state['alias_variants'][n]%len(vm_maps[vm][0][op])])
        recipe=recipes[occurrence.recipe]
        entry=PhysicalRecipe(occurrence,recipe,0,0,tuple(original),tuple(i.a for i in raw))
        reports={}
        if lowered.backend=='mov':
            from types import SimpleNamespace
            from ..mov.adapter import MovHostSlot
            from ..mov.lower import lower
            from .mov_lowering import lower_regions,wire_runtime,recipe_spec
            plain=lower(tuple(MovHostSlot(i.operation,None,0,i.source_id,'source') for i in raw))
            specialized=lower_regions(plain,SimpleNamespace(synthesis=(entry,)))
            def tape_bytes(program):
                return sum(2+sum(max(1,(value.bit_length()+6)//7) for value in (i.a,i.b,i.c,i.d,i.mode)) for i in program.code)
            if occurrence.numeric_domain not in mov_runtime_costs:
                template=target.runtime_template('mov_exec.lua')
                preview=SimpleNamespace(backend_data={'layout':SimpleNamespace(functions=SimpleNamespace(synthesis=(entry,),children=()))})
                normal=compiled(template,plan.version);wired=compiled(wire_runtime(template,preview),plan.version)
                mov_runtime_costs[occurrence.numeric_domain]={'bytes':max(0,wired['bytes']-normal['bytes']-len(recipe_spec(entry).encode())-24),
                    'instructions':wired['instructions']-normal['instructions'],'probe_seconds':wired['probe_seconds']+normal['probe_seconds']}
            mov_runtime_cost=mov_runtime_costs[occurrence.numeric_domain]
            # Cost the actual target fragment and ULEB-serialized microcode.
            # Proven integer DAGs keep LOOKUP arithmetic, eliminating two
            # representation-boundary records per step. 5.1 keeps its guards.
            saved=2*len(recipe.steps) if occurrence.numeric_domain=='integer' else 0
            reports['locals']={'bytes':len(recipe_spec(entry).encode())+max(0,tape_bytes(specialized)-tape_bytes(plain)),
                'micro_blob_delta':tape_bytes(specialized)-tape_bytes(plain),
                'instructions':2-saved,'max_jump':0,'stack':0,'runtime_shared':mov_runtime_cost}
            baseline={'bytes':0,'instructions':0,'max_jump':0,'stack':0}
        else:
            for form in ('locals','cells'):
                key=(vm,recipe.id,tuple(original),occurrence.materialize,form)
                if key not in measured:measured[key]=compile_entry(replace(entry,execution_form=form),lowered,variants[vm],source,vm_maps[vm])
                reports[form]=measured[key]
            # Same event replay with every value materialized is the reference
            # kernel. Ordinary dispatch is charged separately for every step.
            reference_key=(vm,recipe.id,tuple(original),True,'locals')
            if reference_key not in measured:
                measured[reference_key]=compile_entry(replace(entry,occurrence=replace(occurrence,materialize=True)),lowered,variants[vm],source,vm_maps[vm])
            baseline=measured[reference_key]
        available={k:v for k,v in reports.items() if 'error' not in v and v['max_jump']<=MAX_JUMP//4}
        decision={'sources':occurrence.source_ids,'vm':vm,'policy':policy,'domain':occurrence.numeric_domain,
            'forms':reports,'reference_replay':baseline,'code_budget_bytes':byte_budget,
            'retained_events':{'logical':len(recipe.steps),'encoded_writes':len(recipe.steps) if lowered.backend=='karity' else 0,
                'graph_candidates':sum(bool(targets[id(fn)]['graph_families'].get(indexes[s],0)) for s in occurrence.source_ids),
                'pending_producers':sum(v in vm_maps[vm][3].values() for v in original)},
            'work':backend_work(occurrence,lowered.backend)}
        # A table adds binding bytes while all original words must still feed
        # routing, key/state and graph events. It cannot replace those words.
        # This dominated representation is rejected, rather than pretending
        # the prototype's compact, event-free encoding is production-safe.
        from .prototype import encode_bindings
        binding_bytes=len(encode_bindings(occurrence))
        decision['operand_encodings']={'event_slots':{'bytes':occurrence.cost.operand_slot_bytes,'binding_reads_added':0},
            'recipe_table_with_event_slots':{'bytes':occurrence.cost.operand_slot_bytes+binding_bytes,'binding_reads_added':len(occurrence.inputs)+len(occurrence.output_registers),
                'reason':'adds_bindings_without_removing_required_event_words'}}
        decision['operand_encoding']='event_slots'
        if not available:
            decision['fallback']='compiler_cost';rejected['compiler_cost']+=1;decisions.append(decision);continue
        cheapest=min(available,key=lambda k:(available[k]['instructions'],available[k]['bytes']))
        form=cheapest
        if policy!='efficiency':
            ordered=sorted(available)
            selector=int.from_bytes(hashlib.blake2b((plan.generation+plan.protection_signature+occurrence.source_ids[0]).encode(),digest_size=8).digest(),'little')
            proposed=ordered[selector%len(ordered)]
            if spent[vm]+available[proposed]['bytes']<=byte_budget:form=proposed
        report=available[form]
        key=(vm,recipe.id,tuple(original),occurrence.materialize,form,occurrence.numeric_domain if lowered.backend=='mov' else None)
        regional=policy=='balanced' and any(k[:2]==key[:2] and k[4]!=form for k in forms)
        if regional and lowered.backend!='mov':
            regional_recipe=replace(recipe,id=recipe.id+':region:'+occurrence.source_ids[0])
            report=compile_entry(replace(entry,recipe=regional_recipe,execution_form=form),lowered,variants[vm],source,vm_maps[vm])
            if 'error' in report or report['max_jump']>MAX_JUMP//4:
                decision['fallback']='regional_compiler_cost';rejected['regional_compiler_cost']+=1;decisions.append(decision);continue
            decision['regional_form']=report
            key=(vm,regional_recipe.id,tuple(original),occurrence.materialize,form,None)
        specializations=len({tuple('defer' if state['instruction_forms'][indexes[s]][variant_index][0]=='defer' else 'normal'
            for s in occurrence.source_ids) for variant_index in range(len(state['instruction_forms'][indexes[occurrence.source_ids[0]]]))})
        extra=0 if key in forms else (report['bytes']+24)*specializations
        if lowered.backend=='mov':extra+=max(0,mov_runtime_cost['bytes']-mov_shared_reserved[vm])
        saved_helper_work=sum(decision['work'][key]*helper_costs.get(helper,0) for key,helper in
            (('bank_reads_saved','rget'),('bank_writes_saved','rset')))
        before=baseline.get('instructions',0)+len(recipe.steps)*dispatch+saved_helper_work
        after=report['instructions']+dispatch
        decision.update(form=form,compiled_work_before=before,compiled_work_after=after,
            compiler_work_delta=before-after,incremental_bytes=extra,helper_instruction_costs=helper_costs,event_specializations=specializations,
            amortization={'loop':occurrence.cost.loop_region,'static_uses':repeats[occurrence.recipe],
                'minimum_replays_for_extra_bytecode':max(1,(max(0,report['instructions']-baseline.get('instructions',0))+max(1,before-after)-1)//max(1,before-after))})
        reason=None
        if (regional_recipe.id if regional and lowered.backend!='mov' else recipe.id) not in definitions and len(definitions)>=int(context.options.get('synthesis_max_recipes',32)):
            reason='recipe_budget'
        if policy=='efficiency' and (before<=after or decision['work']['net_work_estimate']<=0):reason='measured_kernel_work'
        if spent[vm]+extra>byte_budget:reason='emitted_code_budget'
        reserved_instructions=0 if not extra else max(0,report['instructions'])*specializations
        decision['dispatcher_storage']='closure_bank' if compiler_spent[vm]+reserved_instructions>MAX_JUMP//4 else 'inline'
        if reason:
            decision['fallback']=reason;rejected[reason]+=1;decisions.append(decision);continue
        # Share a form when its semantic/event identity is already represented.
        # A new regional form is allowed only when its measured marginal cost
        # fits. There is no fixed .25 chance and no fixed quarter-budget cap.
        if regional:
            recipe=replace(recipe,id=recipe.id+':region:'+occurrence.source_ids[0])
            occurrence=replace(occurrence,recipe=recipe.id,scope='regional')
        definitions[recipe.id]=recipe;occurrences.append(occurrence)
        forms[key]=form;spent[vm]+=extra;compiler_spent[vm]+=reserved_instructions
        if lowered.backend=='mov':mov_shared_reserved[vm]=max(mov_shared_reserved[vm],mov_runtime_cost['bytes'])
        lowered.backend_data.setdefault('synthesis_execution_forms',{})[occurrence.source_ids]=form
        decision['accepted_for']='work_saving' if policy=='efficiency' else 'bounded_structure_diversity'
        decisions.append(decision)
    plan=replace(plan,recipes=tuple(definitions.values()),occurrences=tuple(occurrences),
                 rejected=tuple(sorted(rejected.items())),decisions=tuple(decisions))
    validate_plan(lowered.semantic_ir,plan,protection_plan=lowered.protection_plan,analysis_cache=lowered.backend_data.get('synthesis_analysis'))
    lowered.backend_data['synthesis_plan']=plan
    context.profile.append({'phase':'synthesis_cost_selection','elapsed':time.perf_counter()-started,
        'recipes':len(plan.recipes),'regions':len(plan.occurrences),'code_bytes_reserved':dict(spent),
        'compiler_instructions_reserved':dict(compiler_spent),'cost_model':'compiler-measured representative kernels; estimated alias/defer group costs; retained helper events; independent diversity budget',
        'decisions':decisions})
