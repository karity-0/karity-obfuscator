"""Lower common regions to MOV microcode scopes and local representation banks."""
from ..mov.ir import Host,Op,Instruction,Program


def recipe_spec(entry):
    from ..backends.handler_ir import OPERATION_IDS
    outputs=','.join(str(i+1) for i in (range(len(entry.recipe.steps)) if entry.occurrence.materialize else entry.recipe.outputs))
    nodes='false'
    if entry.occurrence.numeric_domain=='integer':
        rows=[]
        for step in entry.recipe.steps:
            refs=[str(ref.index+1 if ref.kind=='input' else -ref.index-1) for ref in step.inputs]
            if len(refs)==1:refs.append('false')
            rows.append('{'+','.join(refs+[str(OPERATION_IDS[step.operation])])+'}')
        nodes='{'+','.join(rows)+'}'
    return '{'+str(len(entry.recipe.steps))+',{'+outputs+'},'+nodes+'}'


def lower_regions(program,function):
    if not function.synthesis:return program
    from dataclasses import replace
    prefixes={};specialized={};removed=set()
    for e in function.synthesis:
        start=e.start+1;end=start+len(e.occurrence.source_ids)
        prefixes.setdefault(program.entries[start-1],[]).append(Instruction(Op.HOST,Host.SYNTH_BEGIN,start))
        prefixes.setdefault(program.entries[end-1],[]).insert(0,Instruction(Op.HOST,Host.SYNTH_END))
        if e.occurrence.numeric_domain=='integer':
            for ip in range(start,end):
                address=program.entries[ip-1];prepare=program.code[address-1]
                guard,fallback=program.code[address:address+2]
                if (prepare.op!=Op.HOST or prepare.a!=Host.PREPARE or prepare.b!=ip
                    or guard.op!=Op.SELECT or guard.a!=11 or fallback.a!=Host.EXEC or fallback.b!=ip):
                    raise ValueError('integer DAG differs from MOV representation boundary')
                specialized[address]=replace(prepare,a=Host.SYNTH_PREPARE,c=guard.b)
                removed.update((address+1,address+2))
    code=[];addresses={}
    for index,ins in enumerate(program.code,1):
        addresses[index]=len(code)+1;code.extend(prefixes.get(index,()))
        if index not in removed:code.append(specialized.get(index,ins))
    from ..mov.optimizer import _relocate
    return Program([addresses[x] for x in program.entries],_relocate(code,addresses.__getitem__),
        program.lowered_sites,program.vm_id,{k:addresses[v] for k,v in program.recipe_offsets.items()})


def wire_runtime(source,lowered,vm_index=None):
    from ..backends.runtime_layout import iter_functions
    entries={e.opcode:e for f in iter_functions(lowered.backend_data['layout'].functions)
             if vm_index is None or f.vm_id==vm_index for e in f.synthesis}
    if not entries:return source
    original_bytes=len(source.encode())
    integer_enabled=any(e.occurrence.numeric_domain=='integer' for e in entries.values())
    import re
    heads='{'+','.join(f'[{v}]={e.original_vops[0]}' for v,e in sorted(entries.items()))+'}'
    specs='{'+','.join(f'[{v}]={recipe_spec(e)}' for v,e in sorted(entries.items()))+'}'
    # All generated vops are disjoint across VMs; each frame owns its temp banks.
    source=source.replace('decode(code[','_syn_decode(code[')
    declaration=f'''local _syn_heads={heads}
    local _syn_specs={specs}
    local _syn_tmp,_syn_live,_syn_step
    local _syn_nodes,_syn_values,_syn_inputs,_syn_start
    local _syn_raw_decode=decode
    local function _syn_decode(...)
        local op,A,B,C,Bx,sBx=_syn_raw_decode(...)
        return _syn_heads[op] or op,A,B,C,Bx,sBx
    end
'''
    source=source.replace('local _mdigits={}',declaration+'local _mdigits={}')
    # Copy the target's existing exact digit conversion, including Lua 5.1 ABI.
    a=source.index('--<<TARGET_INTEGER_DIGITS>>');b=source.index('--<<ENDTARGET_INTEGER_DIGITS>>',a)+len('--<<ENDTARGET_INTEGER_DIGITS>>')
    conversion=source[a:b]
    helper='local function _syn_native(d)\n'+conversion+'\nreturn v end\n'
    source=source.replace('local function rget(i)',helper+'''local function rget(i)
        if _syn_tmp and _syn_tmp[i]~=nil then
            local t=_syn_tmp[i]
            if type(t)=="table" then return _syn_native(t) end
            return t
        end''')
    source=source.replace('_mdigits[i]=nil; _mstrings[i]=nil; regs[i]=v',
        'if _syn_tmp then if not _syn_live[_syn_step] then _syn_tmp[i]=v; return end; _syn_tmp[i]=nil end\n        _mdigits[i]=nil; _mstrings[i]=nil; regs[i]=v')
    source=source.replace('local function _mov_digits(i)',
        'local function _mov_digits(i)\n        if _syn_tmp and type(_syn_tmp[i])=="table" then return _syn_tmp[i] end')
    operand='''local function _syn_operand(field,reference)
        if reference<0 then return _syn_values[-reference] end
        local value=_syn_inputs[reference]
        if value==nil then value=_mov_digits(field); _syn_inputs[reference]=value end
        return value
    end
    '''
    if integer_enabled:source=source.replace('local function _mov_copy(',operand+'local function _mov_copy(',1)
    # A reused register's ordinary cache may name an older value version.
    # Convert native local values with the original target's conversion path
    # and cache the result locally; Lua 5.1's number-only guard stays native.
    source=source.replace('local d=_mdigits[i]','local d=_mdigits[i]; if _syn_tmp and _syn_tmp[i]~=nil then d=nil end')
    source=source.replace('local v=regs[i]','local v=regs[i]; if _syn_tmp and _syn_tmp[i]~=nil then v=_syn_tmp[i] end')
    source=source.replace('_mdigits[i]=d','if _syn_tmp and _syn_tmp[i]~=nil then _syn_tmp[i]=d else _mdigits[i]=d end')
    source=source.replace('return _mdigits[i]','if _syn_tmp and _syn_tmp[i]~=nil then return nil end; return _mdigits[i]')
    source=source.replace('_mdigits[_ma]=d; _mstrings[_ma]=nil; regs[_ma]=nil',
        'if _syn_nodes then _syn_values[_syn_step-_syn_start+1]=d end\n'
        '            if _syn_tmp and not _syn_live[_syn_step] then _syn_tmp[_ma]=d else if _syn_tmp then _syn_tmp[_ma]=nil end; _mdigits[_ma]=d; _mstrings[_ma]=nil; regs[_ma]=nil end')
    source=source.replace('local ip=q[3]','local ip=q[3]; _syn_step=ip')
    source=source.replace('pc=q[3]','pc=q[3]; _syn_step=pc')
    if integer_enabled:
        source=source.replace('q[2]==1 then','(q[2]==1 or q[2]==12) then',1)
        source=source.replace('local x,y\n            if op==28 then',
        'local x,y\n            if q[2]==12 then\n'
        '                local node=_syn_nodes[ip-_syn_start+1]\n'
        '                assert(node and op==node[3],"invalid integer DAG binding")\n'
        '                if op==25 then x=_mzero; y=_syn_operand(B,node[1])\n'
        '                else x=_syn_operand(B,node[1]); y=_syn_operand(C,node[2]) end\n'
            '            elseif op==28 then',1)
        source=source.replace('elseif kind==__MOV_HOST__ and q[2]==2 then',
            'if q[2]==12 then assert(_ms[11],"invalid integer synthesis proof"); _mp=q[4] end\n'
            '        elseif kind==__MOV_HOST__ and q[2]==2 then',1)
    begin='''elseif kind==__MOV_HOST__ and q[2]==10 then
            local ip=q[3]
            local vop=_syn_raw_decode(code[ip],_ksm(ip))
            local spec=_syn_specs[vop]
            assert(spec and not _syn_tmp,"invalid synthesized MOV scope")
            _syn_tmp={};_syn_live={}
            _syn_start=ip;_syn_nodes=spec[3]
            if _syn_nodes then _syn_inputs={};_syn_values={} end
            for _,offset in ipairs(spec[2]) do
                _syn_live[ip+offset-1]=true
            end
        elseif kind==__MOV_HOST__ and q[2]==11 then
            _syn_tmp=nil;_syn_live=nil
            _syn_nodes=nil;_syn_inputs=nil;_syn_values=nil;_syn_start=nil
        elseif kind==__MOV_HOST__ and q[2]==0 then'''
    source=source.replace('elseif kind==__MOV_HOST__ and q[2]==0 then',begin)
    if not integer_enabled:
        source=source.replace('    local _syn_nodes,_syn_values,_syn_inputs,_syn_start\n','')
        source=source.replace('if _syn_nodes then _syn_values[_syn_step-_syn_start+1]=d end\n','')
        source=source.replace('_syn_start=ip;_syn_nodes=spec[3]\n            if _syn_nodes then _syn_inputs={};_syn_values={} end','')
        source=source.replace('_syn_nodes=nil;_syn_inputs=nil;_syn_values=nil;_syn_start=nil','')
    if hasattr(lowered,'backend'):
        lowered.backend_data.setdefault('synthesis_emission',{})['mov'+str(vm_index)]={
            'backend':'mov','vm':vm_index,'handlers':len(entries),'runtime_bytes_added':len(source.encode())-original_bytes,
            'integer_dag_kernels':sum(e.occurrence.numeric_domain=='integer' for e in entries.values()),
            'dag_edges':sum(len(e.recipe.edges) for e in entries.values() if e.occurrence.numeric_domain=='integer'),
            'logical_events':sum(len(e.recipe.steps) for e in entries.values()),'storage':'shared_micro_dag_nodes'}
    return source
