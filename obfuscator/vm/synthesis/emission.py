"""Backend-owned recipe bodies with original logical dispatch/alias events."""
from ..backends.runtime_layout import iter_functions
from .lowering import first_aliases

SLOTS={'ADD':'ADD','SUB':'SUB','MUL':'MUL','NEGATE':'UNM','BIT_NOT':'BNOT',
       'BIT_AND':'BAND','BIT_OR':'BOR','BIT_XOR':'BXOR','SHIFT_LEFT':'SHL','SHIFT_RIGHT':'SHR'}
UNARY=frozenset(('NEGATE','BIT_NOT'))


def render_kernel(entry,lowered,variant,fetch,aliases,defers,native,ordinary=None):
    import re
    from ..vm_obfuscation import _ST_TRANSITIONS,_ST_TRANSITIONS_NATIVE
    transitions=_ST_TRANSITIONS_NATIVE if native else _ST_TRANSITIONS
    recipe=entry.recipe;lines=[]
    cells=entry.execution_form=='cells'
    def temporary(index):return f'_sv[{index+1}]' if cells else f'_sv{index}'
    def input_value(index):return f'_si[{index+1}]' if cells else f'_si{index}'
    if not entry.occurrence.materialize:
        if cells:lines.append('local _si,_sv={},{}')
        else:
            lines.append('local '+','.join(f'_si{i}' for i in range(len(recipe.input_kinds))))
            lines.append('local '+','.join(f'_sv{i}' for i in range(len(recipe.steps))))
    elif cells:lines.append('local _sx={}')
    from .register_local import active_values,guarded_read
    local_values=active_values(entry,defers) if entry.execution_form!='materialized' else set()
    if local_values:
        if cells:lines.append('local _sl,_se,_sg,_sp={},{},{},{}')
        else:
            # One four-field cache per initializer: the all-cache parallel
            # assignment exceeds Lua 5.1's expression stack after banking,
            # while one statement per field needlessly multiplies CFF states.
            lines.extend('local '+','.join(f'_{prefix}{n}' for prefix in ('sl','se','sg','sp'))
                         for n in sorted(local_values))
    def cached(prefix,n):return f'_{prefix}[{n+1}]' if cells else f'_{prefix}{n}'
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
        if ordinary is not None and not deferred:
            # Reuse the actual planned alias, including its semantic route and
            # before/after state transition. No cached reads across calls.
            lines.append(fields(ordinary[original]));lines.append('end');continue
        ordinal=0 if deferred else aliases[op].index(original)
        transition='' if deferred else transitions[variant['alias_transition_indices'][op][ordinal]]
        pre=ordinal%2==0
        if pre:lines.append(fields(transition))
        slot='__VM_SLOT_'+SLOTS[step.operation]+'__'
        if entry.occurrence.materialize:
            arguments=[]
            if local_values and not deferred:
                for arg,ref in enumerate(step.inputs):
                    if ref.kind!='temporary' or ref.index not in local_values:
                        arguments.append('nil');continue
                    n=ref.index;field='B' if arg==0 else 'C';name=f'_slv{arg}'
                    value,epoch,generation,position=(cached(prefix,n) for prefix in ('sl','se','sg','sp'))
                    lines.append(fields(guarded_read(value,epoch,generation,position,field,name)))
                    arguments.append(name)
            use_local=bool(local_values) and not deferred
            def emit_commit(body):
                if use_local:
                    body=body.replace('_arith','_syn_arith',1)
                    body=body[:-1]+','+','.join(arguments)+')'
                    if index in local_values:body=cached('sl',index)+'='+body
                lines.append(fields(body))
                if use_local and index in local_values:
                    value,epoch,generation,position=(cached(prefix,index) for prefix in ('sl','se','sg','sp'))
                    lines.append(fields(f'if {value}~=nil then {position}=_rpos(3,A); '
                        f'{epoch}=_RE[{position}]; {generation}=_MG[1] end'))
            if cells:lines.append(fields('_sx[1],_sx[2],_sx[3]=A,B,C'))
            if deferred:
                token='__VM_PENDING_'+('UNM' if step.operation=='NEGATE' else step.operation)+'__'
                body=f'_defer1r(A,B,_av,{slot},{token})' if step.operation=='NEGATE' else f'_defer2r(A,B,C,_av,{slot},{token})'
                lines.append(fields(body.replace('A,B,C','_sx[1],_sx[2],_sx[3]').replace('A,B','_sx[1],_sx[2]') if cells else body))
            elif step.operation in UNARY:
                extra=(',-1' if step.operation=='NEGATE' else ',nil') if lowered.backend=='karity' else ''
                body=f'_arith1r(A,B,_av,{slot}{extra})'
                emit_commit(body.replace('A,B','_sx[1],_sx[2]') if cells else body)
            else:
                extra=(',1' if step.operation=='ADD' else ',-1' if step.operation=='SUB' else ',nil') if lowered.backend=='karity' else ''
                body=f'_arith2r(A,B,C,_av,{slot}{extra})'
                emit_commit(body.replace('A,B,C','_sx[1],_sx[2],_sx[3]') if cells else body)
        else:
            values=[]
            for arg,ref in enumerate(step.inputs):
                if ref.kind=='temporary':values.append(temporary(ref.index))
                else:
                    field='B' if arg==0 else 'C';name=input_value(ref.index)
                    lines.append(fields(f'if {name}==nil then {name}=rget({field}) end'))
                    values.append(name)
            expr=f'_arith1({values[0]},_av,{slot})' if step.operation in UNARY else f'_arith2({values[0]},{values[1]},_av,{slot})'
            lines.append(fields(f'{temporary(index)}={expr}'))
            if index in recipe.outputs:lines.append(fields(f'rset(A,{temporary(index)})'))
        if not pre:lines.append(fields(transition))
        lines.append('end')
    return '\n'+'\n'.join(lines)+'\n'


def inject_handlers(source,lowered,variant,vm_index):
    entries={e.opcode:e for f in iter_functions(lowered.backend_data['layout'].functions)
             if f.vm_id==vm_index for e in f.synthesis}
    if not entries:return source
    from ..vm_obfuscation import _find_chain,_parse_handler_blocks,_rebuild_chain
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
    aliases=lowered.backend_data['layout'].vm_maps[vm_index][0]
    defers=lowered.backend_data['layout'].vm_maps[vm_index][3]
    from .kernels import prepare_kernel
    from .register_local import helper_source,helper_arities,active_values
    from .kernels import generated_names
    local_entries=[e for e in entries.values() if active_values(e,defers) and e.execution_form!='materialized']
    arities=set().union(*(helper_arities(e,defers) for e in local_entries)) if local_entries else set()
    helpers=helper_source(lowered.backend_data['synthesis_template'],arities) if arities else ''
    if helpers:
        helpers=generated_names(helpers,lowered.backend_data.get('vm_key_renames',{}))
        anchor='local function _arith2s('
        if anchor not in source:raise ValueError('register-local helper boundary missing')
        source=source.replace(anchor,helpers+'\n    '+anchor,1)
    from ...passes.function_costs import MAX_JUMP
    blocks={};measurements={};scratch_handlers=0
    for opcode,entry in entries.items():
        body,scratch,report,_=prepare_kernel(entry,lowered,variant,fetch,aliases,defers,native)
        blocks[opcode]=body;measurements[opcode]=report;scratch_handlers+=scratch
    if scratch_handlers:
        source=source.replace(declaration,declaration+'local _SYN_TEMPS={}\n',1)
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
        'guarded_register_local_handlers':len(local_entries),'guarded_local_helper_bytes':len(helpers.encode()),
        'guarded_local_edges':sum(sum(a in active_values(e,defers) for a,b in e.recipe.edges) for e in local_entries),
        'materialized_handlers':sum(e.occurrence.materialize for e in entries.values()),
        'logical_events':sum(len(e.recipe.steps) for e in entries.values())}
    start,end=_find_chain(source);original=_parse_handler_blocks(source[start:end]);original.update(blocks)
    return source[:start]+_rebuild_chain(original)+source[end:]
