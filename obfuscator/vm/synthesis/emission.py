"""Backend-owned recipe bodies with original logical dispatch/alias events."""
from ..backends.runtime_layout import iter_functions
from .lowering import first_aliases

SLOTS={'ADD':'ADD','SUB':'SUB','MUL':'MUL','NEGATE':'UNM'}


def inject_handlers(source,lowered,variant,vm_index):
    entries={e.opcode:e for f in iter_functions(lowered.backend_data['layout'].functions)
             if f.vm_id==vm_index for e in f.synthesis}
    if not entries:return source
    from ..vm_obfuscation import (_find_chain,_parse_handler_blocks,_rebuild_chain,
        _ST_TRANSITIONS,_ST_TRANSITIONS_NATIVE)
    a=source.index('--<<FETCH>>')+len('--<<FETCH>>');b=source.index('--<<ENDFETCH>>',a)
    fetch=source[a:b].strip()
    if lowered.backend=='karity':
        from ..vm_obfuscation import _inline_fetch_decode
        prefix='--<<TARGET_KARITY_EXEC_STATE>>' if '--<<TARGET_KARITY_EXEC_STATE>>' in source else ''
        # Reuse the planned fetch variant for interior events as well as the
        # outer dispatch. A generic decode call here would undo that existing
        # optimization and erase fetch-layout diversity inside new kernels.
        fetch=_inline_fetch_decode(prefix+'--<<FETCH>>--<<ENDFETCH>>',variant['helper_fetch_variant'])[len(prefix):]
    if lowered.backend=='karity' and '--<<TARGET_KARITY_EXEC_STATE>>' in source:
        fetch=fetch.replace('(_S[611] or 0)~(_XF[1] or 0)','_pxor(_S[611] or 0,_XF[1] or 0)')
    heads=first_aliases(lowered,vm_index)
    restore='local _syn_dispatch=op; if _SYN_HEAD[op] then op=_SYN_HEAD[op] end; '
    patched=fetch.replace('_route_step(_ip,op,A,B,C)',restore+'_route_step(_ip,op,A,B,C)',1)+'; op=_syn_dispatch'
    declaration='local _SYN_HEAD={'+','.join(f'[{k}]={v}' for k,v in sorted(heads.items()))+'}\n'
    source=source[:a]+'\n'+patched+'\n'+source[b:]
    import re
    source,count=re.subn(r'(local _st\s*=)',lambda m:declaration+m.group(),source,count=1)
    if count!=1:raise ValueError('synthesis frame declaration boundary missing')
    native='--<<TARGET_CLASSIC_EXEC_NATIVE>>' in source or '--<<TARGET_KARITY_EXEC_STATE>>' in source
    transitions=_ST_TRANSITIONS_NATIVE if native else _ST_TRANSITIONS
    aliases=lowered.backend_data['layout'].vm_maps[vm_index][0]
    defers=lowered.backend_data['layout'].vm_maps[vm_index][3]
    blocks={}
    for opcode,entry in entries.items():
        recipe=entry.recipe;lines=[]
        if not entry.occurrence.materialize:
            lines.append('local '+','.join(f'_si{i}' for i in range(len(recipe.input_kinds))))
            lines.append('local '+','.join(f'_sv{i}' for i in range(len(recipe.steps))))
        for index,step in enumerate(recipe.steps):
            lines.append('do')
            fetch_names=('_ip','_dk','_dw','_lo','_hi','ins','op','A','B','C','Bx','sBx','_av')
            rename={name:f'_syn_{name.lstrip("_")}{index}' for name in fetch_names} if index else {}
            def fields(value):
                return re.sub(r'\b(?:_ip|_dk|_dw|_lo|_hi|ins|op|A|B|C|Bx|sBx|_av)\b',lambda m:rename.get(m.group(),m.group()),value)
            if index:
                event_fetch=fetch
                if lowered.backend=='karity' and not lowered.policy.get('semantic_state_threading',False):
                    event_fetch=event_fetch.replace('; _ss_step(_ip,op,A,B,C)','')
                lines.append(fields(event_fetch))
            original=entry.original_vops[index]
            from ..backends.handler_ir import OPERATION_IDS
            op=OPERATION_IDS[step.operation];deferred=defers.get(op)==original
            ordinal=0 if deferred else aliases[op].index(original)
            transition='' if deferred else transitions[variant['alias_transition_indices'][op][ordinal]]
            pre=ordinal%2==0
            if pre:lines.append(fields(transition))
            slot='__VM_SLOT_'+SLOTS[step.operation]+'__'
            if entry.occurrence.materialize:
                if deferred:
                    token='__VM_PENDING_'+('UNM' if step.operation=='NEGATE' else step.operation)+'__'
                    body=f'_defer1r(A,B,_av,{slot},{token})' if step.operation=='NEGATE' else f'_defer2r(A,B,C,_av,{slot},{token})'
                    lines.append(fields(body))
                elif step.operation=='NEGATE':
                    extra=',-1' if lowered.backend=='karity' else ''
                    lines.append(fields(f'_arith1r(A,B,_av,{slot}{extra})'))
                else:
                    extra=(',1' if step.operation=='ADD' else ',-1' if step.operation=='SUB' else ',nil') if lowered.backend=='karity' else ''
                    lines.append(fields(f'_arith2r(A,B,C,_av,{slot}{extra})'))
            else:
                values=[]
                for arg,ref in enumerate(step.inputs):
                    if ref.kind=='temporary':values.append(f'_sv{ref.index}')
                    else:
                        field='B' if arg==0 else 'C';name=f'_si{ref.index}'
                        lines.append(fields(f'if {name}==nil then {name}=rget({field}) end'))
                        values.append(name)
                expr=f'_arith1({values[0]},_av,{slot})' if step.operation=='NEGATE' else f'_arith2({values[0]},{values[1]},_av,{slot})'
                lines.append(fields(f'_sv{index}={expr}'))
                if index in recipe.outputs:lines.append(fields(f'rset(A,_sv{index})'))
            if not pre:lines.append(fields(transition))
            lines.append('end')
        blocks[opcode]='\n'+'\n'.join(lines)+'\n'
    scratch_handlers=0
    if variant['mutate_handlers']:
        from ..vm_mutation import mutate_handlers,planned_mutation_seeds
        blocks=mutate_handlers(blocks,native_state=native,planned_seeds=planned_mutation_seeds(
            variant['mutation_seed'],{op:'synthesis:'+e.recipe.id for op,e in entries.items()}))
        # Both Lua targets cap simultaneous locals at 200. Keep three quarters
        # for the enclosing executor. Reuse its existing mutation compactor,
        # but isolate recipe temporaries from ordinary handler scratch.
        from ..vm_mutation import _native_scratch_locals
        for opcode,body in blocks.items():
            if len(set(re.findall(r'\blocal\s+([A-Za-z_]\w*)',body)))>200//4:
                blocks[opcode]=_native_scratch_locals(body,0,0,scratch_name='_SYN_TEMPS',rewrite_helpers=False)
                scratch_handlers+=1
        if scratch_handlers:
            source=source.replace(declaration,declaration+'local _SYN_TEMPS={}\n',1)
    from ...passes.function_costs import measure,MAX_JUMP
    version='5.1' if native else '5.3'
    measurements={opcode:measure(body,version=version) for opcode,body in blocks.items()}
    failures={opcode:report['error'] for opcode,report in measurements.items() if 'error' in report}
    if failures:raise ValueError(f'synthesized handler cannot compile: vm={vm_index} errors={failures!r}')
    instructions=sum(report['total_instructions'] for report in measurements.values())
    bank=instructions>MAX_JUMP//4;kernel_bytes=sum(len(body.encode()) for body in blocks.values());bank_bytes=0
    if bank:
        # Bound the enclosing dispatch jump even at large explicit budgets.
        # Each body becomes a private per-frame closure with the same events,
        # mutations and PC/register banks. Dispatcher selection stays intact.
        definitions='local _SYN_HANDLERS={'+','.join(f'[{opcode}]=function(op,A,B,C,Bx,sBx,_av)\n{body}\nend' for opcode,body in blocks.items())+'}\n'
        bank_bytes=len(definitions.encode())
        anchor='--[[VM_DISPATCH_ENTRY]]'
        if anchor not in source:raise ValueError('synthesis closure bank boundary missing')
        source=source.replace(anchor,definitions+anchor,1)
        blocks={opcode:f'\n_SYN_HANDLERS[{opcode}](op,A,B,C,Bx,sBx,_av)\n' for opcode in blocks}
    lowered.backend_data.setdefault('synthesis_emission',{})[vm_index]={
        'vm':vm_index,'handlers':len(blocks),'handler_bytes':kernel_bytes,'closure_bank_bytes':bank_bytes,
        'dispatch_stub_bytes':sum(len(body.encode()) for body in blocks.values()) if bank else 0,
        'head_table_bytes':len(declaration.encode()),
        'scratch_handlers':scratch_handlers,
        'kernel_instructions':instructions,'storage':'closure_bank' if bank else 'inline',
        'register_local_handlers':sum(not e.occurrence.materialize for e in entries.values()),
        'materialized_handlers':sum(e.occurrence.materialize for e in entries.values()),
        'logical_events':sum(len(e.recipe.steps) for e in entries.values())}
    start,end=_find_chain(source);original=_parse_handler_blocks(source[start:end]);original.update(blocks)
    return source[:start]+_rebuild_chain(original)+source[end:]
