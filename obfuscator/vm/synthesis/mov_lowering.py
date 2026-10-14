"""Lower common regions to MOV microcode scopes and local representation banks."""
from ..mov.ir import Host,Op,Instruction,Program


def lower_regions(program,function):
    if not function.synthesis:return program
    prefixes={}
    for e in function.synthesis:
        start=e.start+1;end=start+len(e.occurrence.source_ids)
        prefixes.setdefault(program.entries[start-1],[]).append(Instruction(Op.HOST,Host.SYNTH_BEGIN,start))
        prefixes.setdefault(program.entries[end-1],[]).insert(0,Instruction(Op.HOST,Host.SYNTH_END))
    code=[];addresses={}
    for index,ins in enumerate(program.code,1):
        addresses[index]=len(code)+1;code.extend(prefixes.get(index,()));code.append(ins)
    from ..mov.optimizer import _relocate
    return Program([addresses[x] for x in program.entries],_relocate(code,addresses.__getitem__),
        program.lowered_sites,program.vm_id,{k:addresses[v] for k,v in program.recipe_offsets.items()})


def wire_runtime(source,lowered):
    from ..backends.runtime_layout import iter_functions
    entries={e.opcode:e for f in iter_functions(lowered.backend_data['layout'].functions) for e in f.synthesis}
    if not entries:return source
    import re
    heads='{'+','.join(f'[{v}]={e.original_vops[0]}' for v,e in sorted(entries.items()))+'}'
    specs='{'+','.join(f'[{v}]={{{len(e.occurrence.source_ids)},{{'+','.join(str(i+1) for i in (range(len(e.recipe.steps)) if e.occurrence.materialize else e.recipe.outputs))+'}}' for v,e in sorted(entries.items()))+'}'
    # All generated vops are disjoint across VMs; each frame owns its temp banks.
    source=source.replace('decode(code[','_syn_decode(code[')
    declaration=f'''local _syn_heads={heads}
    local _syn_specs={specs}
    local _syn_tmp,_syn_live,_syn_step
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
    # A reused register's ordinary cache may name an older value version.
    # Convert native local values with the original target's conversion path
    # and cache the result locally; Lua 5.1's number-only guard stays native.
    source=source.replace('local d=_mdigits[i]','local d=_mdigits[i]; if _syn_tmp and _syn_tmp[i]~=nil then d=nil end')
    source=source.replace('local v=regs[i]','local v=regs[i]; if _syn_tmp and _syn_tmp[i]~=nil then v=_syn_tmp[i] end')
    source=source.replace('_mdigits[i]=d','if _syn_tmp and _syn_tmp[i]~=nil then _syn_tmp[i]=d else _mdigits[i]=d end')
    source=source.replace('return _mdigits[i]','if _syn_tmp and _syn_tmp[i]~=nil then return nil end; return _mdigits[i]')
    # A reused register's ordinary cache may name an older value version.
    # Convert native local values with the original target's conversion path
    # and cache the result locally; Lua 5.1's number-only guard stays native.
    source=source.replace('local d=_mdigits[i]','local d=_mdigits[i]; if _syn_tmp and _syn_tmp[i]~=nil then d=nil end')
    source=source.replace('local v=regs[i]','local v=regs[i]; if _syn_tmp and _syn_tmp[i]~=nil then v=_syn_tmp[i] end')
    source=source.replace('_mdigits[i]=d','if _syn_tmp and _syn_tmp[i]~=nil then _syn_tmp[i]=d else _mdigits[i]=d end')
    source=source.replace('return _mdigits[i]','if _syn_tmp and _syn_tmp[i]~=nil then return nil end; return _mdigits[i]')
    source=source.replace('_mdigits[_ma]=d; _mstrings[_ma]=nil; regs[_ma]=nil',
        'if _syn_tmp and not _syn_live[_syn_step] then _syn_tmp[_ma]=d else if _syn_tmp then _syn_tmp[_ma]=nil end; _mdigits[_ma]=d; _mstrings[_ma]=nil; regs[_ma]=nil end')
    source=source.replace('local ip=q[3]','local ip=q[3]; _syn_step=ip')
    source=source.replace('pc=q[3]','pc=q[3]; _syn_step=pc')
    begin='''elseif kind==__MOV_HOST__ and q[2]==10 then
            local ip=q[3]
            local vop=_syn_raw_decode(code[ip],_ksm(ip))
            local spec=_syn_specs[vop]
            assert(spec and not _syn_tmp,"invalid synthesized MOV scope")
            _syn_tmp={};_syn_live={}
            for _,offset in ipairs(spec[2]) do
                _syn_live[ip+offset-1]=true
            end
        elseif kind==__MOV_HOST__ and q[2]==11 then
            _syn_tmp=nil;_syn_live=nil
        elseif kind==__MOV_HOST__ and q[2]==0 then'''
    source=source.replace('elseif kind==__MOV_HOST__ and q[2]==0 then',begin)
    return source
