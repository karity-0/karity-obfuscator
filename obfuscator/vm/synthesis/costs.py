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
    from .kernels import prepare_kernel
    fetch,native=kernel_context(lowered,variant,source)
    body,_,report,elapsed=prepare_kernel(entry,lowered,variant,fetch,vm_maps[0],vm_maps[3],native)
    if 'error' in report:return {'bytes':len(body.encode()),'error':report['error']}
    return {'bytes':len(body.encode()),'instructions':report['total_instructions'],'probe_seconds':elapsed,
        'max_jump':max(r['max_jump'] for r in report['functions']),'stack':max(r['stack'] for r in report['functions'])}


def preserve_terminal_variants(lowered,plan,targets,functions,indexes,options):
    """Retain prefix DAGs when a terminal would swallow selected block clones."""
    if options.get('block_variant_rate',0)<=0:return plan
    from .strategies import TERMINAL
    from .planner import _facts,discover_windows
    from ..backends.handler_layout import _block_chunks
    semantic={f.id:f for f in lowered.semantic_ir.functions()}
    recipes={r.id:r for r in plan.recipes};chunks={};candidates=[]
    rejected=Counter(dict(plan.rejected));decisions=list(plan.decisions)
    for o in plan.occurrences:
        if recipes[o.recipe].steps[-1].operation not in TERMINAL:
            candidates.append((recipes[o.recipe],o));continue
        fn=functions[o.function];state=targets[id(fn)];owned={indexes[fn.id][s] for s in o.source_ids}
        if fn.id not in chunks:
            chunks[fn.id]=_block_chunks(fn.code,int(options.get('block_variant_max_instructions',6)))
        if not any(eligible and state['block_variants'].get(a,False) and owned.intersection(range(a,b))
                   for a,b,eligible in chunks[fn.id]):
            candidates.append((recipes[o.recipe],o));continue
        function=semantic[o.function]
        facts=_facts(function,plan.version,lowered.backend_data['synthesis_analysis'])
        run=[facts.producers[s] for s in o.source_ids[:-1]]
        block=function.blocks[facts.block_indices[o.block]]
        prefixes,_=discover_windows(function,block,run,facts,plan.version,plan.backend)
        for recipe,prefix in prefixes:
            if o.scope=='regional':
                recipe=replace(recipe,id=recipe.id+':region:'+prefix.source_ids[0])
                prefix=replace(prefix,recipe=recipe.id,scope='regional')
            candidates.append((recipe,prefix))
        rejected['terminal_block_variants']+=1
        decisions.append({'sources':o.source_ids,'vm':state['vm_assignment'],
            'fallback':'terminal_block_variants','recovered_prefix_candidates':len(prefixes)})
    definitions={};occurrences=[]
    for recipe,o in candidates:
        if (recipe.id not in definitions and len(definitions)>=int(options.get('synthesis_max_recipes',32))
                or len(occurrences)>=int(options.get('synthesis_max_occurrences',512))):
            rejected['terminal_prefix_budget']+=1
            decisions.append({'sources':o.source_ids,'fallback':'terminal_prefix_budget'});continue
        definitions[recipe.id]=recipe;occurrences.append(o)
    result=replace(plan,recipes=tuple(definitions.values()),occurrences=tuple(occurrences),
                   rejected=tuple(sorted(rejected.items())),decisions=tuple(decisions))
    validate_plan(lowered.semantic_ir,result,protection_plan=lowered.protection_plan,
                  analysis_cache=lowered.backend_data['synthesis_analysis'])
    return result


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
    lowered.backend_data['synthesis_template']=source
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
    plan=preserve_terminal_variants(lowered,plan,targets,fn_by_id,indexes_by_function,context.options)
    helper_costs={}
    if lowered.backend=='classic':
        for name in ('RGET','RSET'):
            body=source.split('--<<'+name+'>>',1)[1].split('--<<END'+name+'>>',1)[0]
            report=measure(body,version=plan.version,minimum_paths=True)
            helper_costs[name.lower()]=report['functions'][1]['minimum_path_instructions']
    definitions={};occurrences=[];decisions=list(plan.decisions);rejected=Counter(dict(plan.rejected))
    spent=Counter();compiler_spent=Counter();measured={};forms={};repeats=Counter(o.recipe for o in plan.occurrences)
    reservations={};reservation_owner={}
    mov_runtime_costs={};mov_shared_reserved=Counter()
    recipes={r.id:r for r in plan.recipes}
    dispatch=compiled('while true do if op==selector then work() else break end end',plan.version)['instructions']
    alternatives={};probe_cache={};probed_signatures=set();frame_costs={}
    def probe(body):
        if body not in probe_cache:probe_cache[body]=compiled(body,plan.version)
        return probe_cache[body]
    frames={};frame_keys={}
    semantic_functions={f.id:f for f in lowered.semantic_ir.functions()}
    semantic_instructions={i.id:i for f in semantic_functions.values() for b in f.blocks for i in b.instructions}
    if lowered.backend!='mov':
        from .planner import _facts
        for o in plan.occurrences:
            semantic=semantic_functions[o.function]
            if o.function not in frame_costs:
                frame_costs[o.function]=_facts(semantic,plan.version,lowered.backend_data['synthesis_analysis'])
            facts=frame_costs[o.function];component=facts.components[o.block] if o.cost.loop_region else None
            key=(o.function,component);frame_keys[o.source_ids]=key
            if key not in frames:
                frames[key]={'sites':sum(len(b.instructions) for b in semantic.blocks if component is None or
                    facts.components[b.id]==component),'candidates':0,'covered':set()}
            frames[key]['candidates']+=1;frames[key]['covered'].update(o.source_ids)
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
        signatures=set()
        for block_variant in range(len(state['instruction_forms'][indexes[occurrence.source_ids[0]]])):
            event_aliases=tuple(vm_maps[vm][3][i.op] if lowered.backend=='karity' and
                state['instruction_forms'][indexes[i.source_id]][block_variant][0]=='defer' else
                vm_maps[vm][0][i.op][state['alias_variants'][indexes[i.source_id]]%len(vm_maps[vm][0][i.op])] for i in raw)
            signatures.add((vm,recipe.id,event_aliases,occurrence.materialize))
        # Bound explored physical event contracts by the existing handler limit.
        # Failed kernels consume exploration capacity too; shared signatures
        # can reuse probes. Every budget fallback remains explicit in diagnostics.
        if len(probed_signatures|signatures)>int(context.options.get('synthesis_max_recipes',32)):
            rejected['cost_probe_handler_budget']+=1
            decisions.append({'sources':occurrence.source_ids,'vm':vm,'fallback':'cost_probe_handler_budget'})
            continue
        probed_signatures.update(signatures)
        entry=PhysicalRecipe(occurrence,recipe,0,0,tuple(original),tuple(i.a for i in raw))
        reports={}
        if lowered.backend=='mov':
            from types import SimpleNamespace
            from ..mov.adapter import MovHostSlot
            from ..mov.lower import lower
            from .mov_lowering import lower_regions,wire_runtime,recipe_spec,scope_cost
            plain=lower(tuple(MovHostSlot(i.operation,None,0,i.source_id,'source') for i in raw))
            specialized=lower_regions(plain,SimpleNamespace(synthesis=(entry,)))
            def tape_bytes(program):
                return sum(2+sum(max(1,(value.bit_length()+6)//7) for value in (i.a,i.b,i.c,i.d,i.mode)) for i in program.code)
            if occurrence.numeric_domain not in mov_runtime_costs:
                template=target.runtime_template('mov_exec.lua')
                preview=SimpleNamespace(backend_data={'layout':SimpleNamespace(functions=SimpleNamespace(synthesis=(entry,),children=()))})
                wired_source=wire_runtime(template,preview)
                normal=compiled(template,plan.version);wired=compiled(wired_source,plan.version)
                mov_runtime_costs[occurrence.numeric_domain]={'bytes':max(0,wired['bytes']-normal['bytes']-len(recipe_spec(entry).encode())-24),
                    'instructions':wired['instructions']-normal['instructions'],'probe_seconds':wired['probe_seconds']+normal['probe_seconds'],
                    **scope_cost(wired_source,probe)}
            mov_runtime_cost=mov_runtime_costs[occurrence.numeric_domain]
            # Cost the actual target fragment and ULEB-serialized microcode.
            # Proven integer DAGs keep LOOKUP arithmetic, eliminating two
            # representation-boundary records per step. 5.1 keeps its guards.
            saved=2*len(recipe.steps) if occurrence.numeric_domain=='integer' else 0
            reports['locals']={'bytes':len(recipe_spec(entry).encode())+max(0,tape_bytes(specialized)-tape_bytes(plain)),
                'micro_blob_delta':tape_bytes(specialized)-tape_bytes(plain),
                'instructions':2-saved,'max_jump':0,'stack':0,'runtime_shared':mov_runtime_cost}
        else:
            for form in (('locals','cells','materialized') if occurrence.local_values else ('locals','cells')):
                key=(vm,recipe.id,tuple(original),occurrence.materialize,form)
                if key not in measured:measured[key]=compile_entry(replace(entry,execution_form=form),lowered,variants[vm],source,vm_maps[vm])
                reports[form]=measured[key]
            # Actual fallback handlers below replace the old materialized
            # synthesis proxy. Do not generate a third unused kernel to cost it.
        available={k:v for k,v in reports.items() if 'error' not in v and v['max_jump']<=MAX_JUMP//4}
        decision={'sources':occurrence.source_ids,'vm':vm,'policy':policy,'domain':occurrence.numeric_domain,
            'forms':reports,'code_budget_bytes':byte_budget,
            'retained_events':{'logical':len(recipe.steps),'encoded_writes':occurrence.cost.writes_before if lowered.backend=='karity' else 0,
                'open_result_top':any(v.role=='results' and v.count is None
                                      for source_id in occurrence.source_ids for v in semantic_instructions[source_id].operands),
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
        if lowered.backend!='mov':
            from .alternatives import Alternatives
            if vm not in alternatives:
                alternatives[vm]=Alternatives(source,variants[vm],vm_maps[vm],
                    probe,kernel_context(lowered,variants[vm],source)[0],lowered.policy)
            comparison=alternatives[vm].compare(fn,state,[indexes[s] for s in occurrence.source_ids],dispatch)
        else:
            comparison={'ordinary':{'work':len(plain.code)},'fusion':{'unavailable':'MOV_has_no_pair_fusion'},
                'planned':{'work':len(plain.code)},'baseline':'planned'}
        decision['alternatives']=comparison
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
        if occurrence.local_values and form!='materialized':
            from .register_local import helper_source,helper_arities
            arities=set().union(*(helper_arities(replace(entry,original_vops=signature[2]),vm_maps[vm][3])
                for signature in signatures))
            shared=helper_source(source,arities)
            # Charge the complete helper set per new physical kernel. Final
            # emission shares it per VM; this conservative reservation also
            # survives later Efficiency removals without an uncharged owner.
            decision['guarded_local_helpers']={'bytes':len(shared.encode()),'arities':sorted(arities),
                'candidate_edges':sum(a in occurrence.local_values for a,b in recipe.edges),
                'bank_commits_elided':0,'reads_saved':'runtime epoch/pending guards decide'}
            if key not in forms:extra+=len(shared.encode())
        if lowered.backend=='mov':extra+=max(0,mov_runtime_cost['bytes']-mov_shared_reserved[vm])
        saved_helper_work=sum(decision['work'][key]*helper_costs.get(helper,0) for key,helper in
            (('bank_reads_saved','rget'),('bank_writes_saved','rset')))
        before=comparison['planned']['work']+saved_helper_work
        if lowered.backend=='mov':
            host_work=mov_runtime_cost['scope_instructions']
            if occurrence.numeric_domain=='integer':host_work+=len(recipe.steps)*mov_runtime_cost['integer_proof_per_step']
            after=len(specialized.code)+host_work
            decision['mov_host_work_added']=host_work
        else:
            # The outer fetch and head restoration are outside render_kernel.
            fetch=kernel_context(lowered,variants[vm],source)[0]
            outer=probe(fetch+'; local _syn_dispatch=op; if _SYN_HEAD[op] then op=_SYN_HEAD[op] end; op=_syn_dispatch')
            after=report['instructions']+outer['instructions']-2*probe('')['instructions']+dispatch
            # Head remapping also runs on ordinary instructions in this frame.
            # Charge remaining sites in the same loop SCC (or the whole cold
            # function); do not assume they vanish with the numeric region.
            frame=frames[frame_keys[occurrence.source_ids]]
            other_sites=frame['sites']-len(frame['covered'])
            remap=probe('local saved=op; if _SYN_HEAD[op] then op=_SYN_HEAD[op] end; op=saved')['instructions']-probe('')['instructions']
            surcharge=(max(0,other_sites)*remap+frame['candidates']-1)//frame['candidates']
            decision['compiled_work_after_without_frame_remapping']=after
            after+=surcharge
            decision['frame_head_remapping']={'other_sites':max(0,other_sites),'work_per_site':remap,
                'work_added':surcharge,'shared_regions':frame['candidates'],
                'frequency_basis':'same_loop_SCC' if occurrence.cost.loop_region else 'cold_function'}
        decision['alternatives']['synthesis']={'work':after,'form':form}
        decision.update(form=form,compiled_work_before=before,compiled_work_after=after,
            compiler_work_delta=before-after,incremental_bytes=extra,helper_instruction_costs=helper_costs,event_specializations=specializations,
            amortization={'loop':occurrence.cost.loop_region,'static_uses':repeats[occurrence.recipe],
                'work_saving_proxy_per_replay':before-after,'extra_kernel_bytes':extra,
                'dynamic_execution_count':'unknown'})
        reason=None
        if (regional_recipe.id if regional and lowered.backend!='mov' else recipe.id) not in definitions and len(definitions)>=int(context.options.get('synthesis_max_recipes',32)):
            reason='recipe_budget'
        if policy=='efficiency' and (before<=after or decision['work']['net_work_estimate']<=0):reason='measured_kernel_work'
        if policy=='efficiency' and comparison.get('cross_region_unit'):reason='planned_unit_boundary'
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
        reservation_owner[occurrence.source_ids]=key
        if key not in reservations:reservations[key]=(vm,extra,reserved_instructions)
        forms[key]=form;spent[vm]+=extra;compiler_spent[vm]+=reserved_instructions
        if lowered.backend=='mov':mov_shared_reserved[vm]=max(mov_shared_reserved[vm],mov_runtime_cost['bytes'])
        lowered.backend_data.setdefault('synthesis_execution_forms',{})[occurrence.source_ids]=form
        decision['accepted_for']='work_saving' if policy=='efficiency' else 'bounded_structure_diversity'
        decisions.append(decision)
    # Reprice the shared frame overhead using *admitted* regions. Each failed
    # budget/compiler candidate remains an ordinary site. Efficiency removals
    # can only increase that overhead: this fixed point terminates in <=N rounds
    # and never retries generation or relaxes a protection/compile constraint.
    frame_rounds=0
    if lowered.backend!='mov':
        decision_by_source={d['sources']:d for d in decisions}
        while occurrences:
            frame_rounds+=1;active=Counter();covered={}
            for o in occurrences:
                key=frame_keys[o.source_ids];active[key]+=1
                covered.setdefault(key,set()).update(o.source_ids)
            kept=[]
            for o in occurrences:
                d=decision_by_source[o.source_ids];key=frame_keys[o.source_ids];head=d['frame_head_remapping']
                sites=max(0,frames[key]['sites']-len(covered[key]))
                charge=(sites*head['work_per_site']+active[key]-1)//active[key]
                head.update(other_sites=sites,shared_regions=active[key],work_added=charge)
                after=d['compiled_work_after_without_frame_remapping']+charge
                d.update(compiled_work_after=after,compiler_work_delta=d['compiled_work_before']-after)
                d['alternatives']['synthesis']['work']=after
                d['amortization']['work_saving_proxy_per_replay']=d['compiler_work_delta']
                if policy=='efficiency' and d['compiler_work_delta']<=0:
                    d.pop('accepted_for',None);d['fallback']='frame_head_work';rejected['frame_head_work']+=1
                else:kept.append(o)
            if len(kept)==len(occurrences):break
            occurrences=kept
        used={o.recipe for o in occurrences}
        definitions={key:value for key,value in definitions.items() if key in used}
    plan=replace(plan,recipes=tuple(definitions.values()),occurrences=tuple(occurrences),
                 rejected=tuple(sorted(rejected.items())),decisions=tuple(decisions))
    validate_plan(lowered.semantic_ir,plan,protection_plan=lowered.protection_plan,analysis_cache=lowered.backend_data.get('synthesis_analysis'))
    lowered.backend_data['synthesis_plan']=plan
    live_bytes=Counter();live_instructions=Counter()
    for key in {reservation_owner[o.source_ids] for o in occurrences}:
        vm,size,count=reservations[key];live_bytes[vm]+=size;live_instructions[vm]+=count
    context.profile.append({'phase':'synthesis_cost_selection','elapsed':time.perf_counter()-started,
        'recipes':len(plan.recipes),'regions':len(plan.occurrences),'code_bytes_reserved':dict(live_bytes),
        'compiler_instructions_reserved':dict(live_instructions),'probe_code_bytes_reserved':dict(spent),'fallback_probes':len(probe_cache),
        'physical_signatures_probed':len(probed_signatures),
        'frame_admission_rounds':frame_rounds,
        'cost_model':'compiler-measured planned alias/split/fuse/defer bodies and synthesis; retained helper events; independent diversity budget',
        'decisions':decisions})
