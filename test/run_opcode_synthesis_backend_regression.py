"""Real backend recipe execution, protected event replay and safe fallback."""
from pathlib import Path
from dataclasses import replace
import sys
import argparse
import random
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools'),str(ROOT/'test')]
from profile_opcode_synthesis import build,BASE,PROTECTED,SOURCE,REPEATED,FUNCTIONS,LONG_DAG
from profile_vm_runtime import execute
from run_opcode_synthesis_regression import must_fail
from obfuscator.vm.synthesis.planner import validate_plan
from obfuscator.vm.backends.handler_layout import validate_layout
from obfuscator.vm.backends.runtime_layout import iter_functions
from obfuscator.vm.mov.validate import validate_host_bindings
from obfuscator.vm.mov.ir import Host,Op

SEMANTICS="""local fs={};for i=1,3 do local n=i;fs[i]=function(...) n=n+1;return n,... end end;
for i=1,3 do local a,b,c,d=fs[i](nil,9,nil);print(a,b,c,d) end;
local co=coroutine.create(function()coroutine.yield('yield',nil);return 'done',nil end);
print(coroutine.resume(co));print(coroutine.resume(co));
print(pcall(function()error('expected',0)end));
local mt={__add=function(a,b)return a.x+b.x end};local a=setmetatable({x=3},mt);local b=setmetatable({x=7},mt);print(a+b)
"""
LONG_BODY='local a=i+3;'+''.join('a=a*2;a=a-3;' for _ in range(8))+'sum=sum+a;'
LONG='local sum=0;for i=1,10 do '+LONG_BODY+' end;print(sum)'
STORAGE='local s=0;for i=1,3 do local a;'+('a=i*3;a=a+7;a=a*5;s=s+a;'*256)+'end;print(s)'

def storage_checks(backends,versions):
    count=0
    for version in versions:
        for backend in backends:
            output,data,p=build(STORAGE,backend,version,{**BASE,'opcode_synthesis':True,'synthesis_policy':'efficiency',
                'synthesis_max_steps':4,'synthesis_max_recipes':64,'synthesis_max_occurrences':1024,'synthesis_max_code_growth':64})
            assert execute(output,version)[0]==execute(STORAGE,version)[0]
            storage=next(row for row in p.last_profile if row['phase']=='serialize_blob')
            assert storage['format_version']==3 and storage['synthesis_storage_saved_bytes']>0
            if backend!='mov':
                assert p.last_lowered_ir.backend_data['synthesis_kernel_reuse']['hits']>0
                retired=p.last_lowered_ir.backend_data['synthesis_pruning'][0]['retired_aliases']
                assert retired and set(retired)<=p.last_lowered_ir.backend_data['layout'].used_ops[0]
            assert 'synthesis_kernel_cache' not in p.last_lowered_ir.backend_data
            count+=1
            print('synthesis-storage-ok',backend,version,storage['synthesis_storage_saved_bytes'],flush=True)
            if backend=='karity':
                from obfuscator.vm.backends import handler_codec
                settings={**BASE,**PROTECTED,'opcode_synthesis':True,'synthesis_policy':'efficiency',
                    'synthesis_max_steps':4,'synthesis_max_recipes':64,'synthesis_max_occurrences':1024,
                    'synthesis_max_code_growth':64,'block_variant_rate':0,'physical_block_permutation_rate':0}
                source=STORAGE.replace('1,3','1,1')
                compact,_,protected=build(source,backend,version,settings,event_trace=True)
                assert next(row for row in protected.last_profile if row['phase']=='serialize_blob')['format_version']==3
                serialize=handler_codec.serialize
                with patch.object(handler_codec,'serialize',lambda *args,**kwargs:serialize(*args,**kwargs,compact_synthesis=False)):
                    legacy,_,_=build(source,backend,version,settings,event_trace=True)
                assert execute(compact,version)[0]==execute(legacy,version)[0]
                count+=2
            if backend=='mov':continue
            # An ordinary numeric site outside the region must retain all its
            # planned aliases, even when that operation is also synthesized.
            source='local n=tonumber("3");'+SOURCE+';print(n*2)'
            output,data,p=build(source,backend,version,{**BASE,'opcode_synthesis':True})
            assert data['handlers'] and execute(output,version)[0]==execute(source,version)[0]
            from obfuscator.vm.backends.handler_ir import OPERATION_IDS
            kept=p.last_lowered_ir.backend_data['layout'].vm_maps[0][0][OPERATION_IDS['MUL']]
            retired=p.last_lowered_ir.backend_data['synthesis_pruning'][0]['retired_aliases']
            assert not set(kept).intersection(retired)
            count+=1
    return count

def hidden_dispatch_checks(backends,versions):
    from obfuscator.presets import user_preset
    count=0
    for version in versions:
        for backend in backends:
            if backend=='mov':continue
            for shape in ('ifelseif','bsearch','split4','bsplit6','tailcall','mixed'):
                options={**user_preset('strong')['vm_options'],'blob_form':'string',
                    'dispatcher_type':shape,'synthesis_max_code_growth':64}
                output,data,_=build(SOURCE,backend,version,options)
                assert data['handlers'],(backend,version,shape,'fixture must reach synthesized dispatch')
                assert execute(output,version)[0]==execute(SOURCE,version)[0],(backend,version,shape)
                count+=1
                print('synthesis-hidden-dispatch-ok',backend,version,shape,flush=True)
            options={**BASE,**PROTECTED,'semantic_state_threading':False,
                'opcode_synthesis':True,'dispatcher_type':'bsplit6','synthesis_max_code_growth':64}
            output,data,_=build(SOURCE,backend,version,options)
            assert data['handlers'] and execute(output,version)[0]==execute(SOURCE,version)[0]
            count+=1
    return count

def maximum_checks(backends,versions):
    from obfuscator.presets import user_preset
    count=0
    for version in versions:
        for backend in backends:
            if backend=='mov':continue
            output,data,_=build(LONG_DAG,backend,version,{**user_preset('maximum')['vm_options'],'blob_form':'string'})
            assert data['handlers'] and data['regions'],(backend,version,'maximum must exercise real kernels')
            assert execute(output,version)[0]==execute(LONG_DAG,version)[0],(backend,version,'maximum')
            print('synthesis-maximum-ok',backend,version,data['regions'],data['handlers'],flush=True)
            count+=1
    return count
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backends',nargs='+',choices=('classic','karity','mov'),default=('classic','karity','mov'))
    parser.add_argument('--lua',nargs='+',choices=('5.1','5.3'),default=('5.1','5.3'))
    parser.add_argument('--dispatch-only',action='store_true')
    parser.add_argument('--maximum-only',action='store_true')
    parser.add_argument('--storage-only',action='store_true')
    arguments=parser.parse_args()
    if arguments.storage_only:
        print('opcode-synthesis-storage-regression-ok',storage_checks(arguments.backends,arguments.lua))
        return
    if arguments.maximum_only:
        print('opcode-synthesis-maximum-regression-ok',maximum_checks(arguments.backends,arguments.lua))
        return
    count=hidden_dispatch_checks(arguments.backends,arguments.lua)
    if arguments.dispatch_only:
        print('opcode-synthesis-hidden-dispatch-regression-ok',count)
        return
    count+=maximum_checks(arguments.backends,arguments.lua)
    count+=storage_checks(arguments.backends,arguments.lua)
    for version in arguments.lua:
        for backend in arguments.backends:
            off,data,_=build(SOURCE,backend,version,BASE)
            explicit,other,_=build(SOURCE,backend,version,{**BASE,'opcode_synthesis':False})
            assert off==explicit and data['blob_hash']==other['blob_hash']
            fixtures=(('dag',SOURCE,{}),('shared',REPEATED,{}),('multivm',FUNCTIONS,{'vm_count':3}),
                ('protected',SOURCE,PROTECTED),('composed',SOURCE,{**PROTECTED,'junk_instructions':True,'junk_rate':.08,'ir_mba_rate':.5}),('semantics',SEMANTICS,{}),
                ('overwrite',SOURCE.replace('local a=i*3;local b=a+7;local c=b*5;sum=sum+c','local a=i*3;a=a+7;a=a*5;sum=sum+a'),{}),
                ('pending_head',SOURCE.replace('i*3','i+3'),PROTECTED),
                ('float',SOURCE.replace('i*3','i*1.5').replace('b*5','-b'),{}))
            mixed=SOURCE.replace(';print(sum)','')+';'+SOURCE.replace('i*3','i*1.5').replace('local sum=0;','').replace('1,40','1,8')
            fixtures+=(('mixed_domains',mixed,{}),)
            fixtures+= (
                ('max_region',LONG,{**PROTECTED,'synthesis_max_steps':16}),
                ('signed_zero',SOURCE.replace('i*3','i*0.0').replace('a+7','-a').replace('b*5','-b'),{}),
                ('nan',SOURCE.replace('i*3','i*1e309').replace('a+7','a-a').replace('b*5','-b').replace('print(sum)','print(sum~=sum)'),{}),
            )
            if version=='5.3':fixtures+=(('overflow',SOURCE.replace('i*3','i*0x7fffffffffffffff').replace('a+7','a+0x7fffffffffffffff').replace('b*5','-b'),{}),)
            for name,source,options in fixtures:
                expected=execute(source,version)[0]
                policies=('efficiency','protection') if name=='shared' else ('balanced',)
                for policy in policies:
                    output,data,p=build(source,backend,version,{**BASE,**options,'opcode_synthesis':True,'synthesis_policy':policy})
                    actual,_=execute(output,version)
                    assert actual==expected,(backend,version,name,actual,expected)
                    if data['regions']:
                        plan=p.last_lowered_ir.backend_data['synthesis_plan']
                        assert plan.decisions and all(d.get('accepted_for') or d.get('fallback') for d in plan.decisions)
                        for decision in plan.decisions:
                            if decision.get('accepted_for'):
                                assert decision['incremental_bytes']<=decision['code_budget_bytes']
                                assert decision['operand_encodings']['event_slots']['bytes']<decision['operand_encodings']['recipe_table_with_event_slots']['bytes']
                    if name in ('dag','shared','overwrite','float','pending_head'):assert data['regions']>0 and data['handlers']>0,(backend,version,name,data)
                    if name=='semantics':assert not data['regions']
                    if name=='multivm':
                        assert data['regions']==2 and data['handlers']>=2
                        assert p.last_lowered_ir.backend_data['layout'].vm_count==3
                    if name=='dag':
                        plan=p.last_lowered_ir.backend_data['synthesis_plan']
                        must_fail(lambda:validate_plan(p.last_semantic_ir,replace(plan,protection_signature='stale'),protection_plan=p.last_protection_plan))
                        layout=p.last_lowered_ir.backend_data['layout'];function=next(f for f in iter_functions(layout.functions) if f.synthesis)
                        original=function.synthesis
                        function.synthesis=(replace(original[0],start=original[0].start+1),)
                        must_fail(lambda:validate_layout(function,layout.vm_maps));function.synthesis=original
                        entry=original[0];first=function.code[entry.start]
                        old_vop=entry.original_vops[0]
                        function.synthesis=(replace(entry,opcode=old_vop),)
                        function.code[entry.start]=replace(first,vop=old_vop)
                        must_fail(lambda:validate_layout(function,layout.vm_maps))
                        function.synthesis=original;function.code[entry.start]=first
                        jump=next(i for i,s in enumerate(function.code) if s.instruction.operation=='FOR_PREP')
                        saved=function.code[jump]
                        function.code[jump]=replace(saved,instruction=saved.instruction.with_bx(entry.start-jump+131071))
                        must_fail(lambda:validate_layout(function,layout.vm_maps));function.code[jump]=saved
                        if backend=='mov':
                            lowered=p.last_lowered_ir
                            must_fail(lambda:validate_host_bindings(lowered.backend_data['programs'][0],lowered.backend_data['mov_slots'][0].slots))
                            micro=lowered.backend_data['programs'][0]
                            direct=[(n,i) for n,i in enumerate(micro.code) if i.op==Op.HOST and i.a==Host.SYNTH_PREPARE]
                            if version=='5.3':
                                assert len(direct)==4,'integer proof must remove four representation guards'
                                n,ins=direct[0];micro.code[n]=replace(ins,c=micro.entries[0])
                                must_fail(lambda:validate_host_bindings(micro,lowered.backend_data['mov_slots'][0].slots,synthesis=function.synthesis))
                                micro.code[n]=ins
                            else:assert not direct,'number-only ABI must retain native guards'
                    if name=='protected' and backend=='karity':
                        layout=p.last_lowered_ir.backend_data['layout']
                        functions=list(iter_functions(layout.functions))
                        assert sum(len(f.synthesis) for f in functions)>data['regions'],'block variants must retain atomic recipe clones'
                        assert any(v in layout.vm_maps[f.vm_id][3].values() for f in functions for e in f.synthesis for v in e.original_vops),'pending arithmetic must remain deferred'
                        assert p.last_lowered_ir.backend_data['karity_state'].occurrence_inventory()[0]
                    count+=1
                    print('synthesis-backend-ok',backend,version,name,policy,data['regions'],data['handlers'],flush=True)
            # Independent VMs necessarily require independent physical handlers;
            # two repeats in one VM may legitimately share the sole handler.
            output,data,_=build(FUNCTIONS,backend,version,{**BASE,'vm_count':3,'opcode_fusion':True,'opcode_splitting':True,'opcode_synthesis':True,'synthesis_policy':'efficiency','synthesis_max_recipes':1})
            assert execute(output,version)[0]==execute(FUNCTIONS,version)[0]
            assert data['handlers']<=1
            assert data['fallbacks']>0
            count+=1
            baseline,base_data,base_pass=build(SOURCE,backend,version,BASE)
            output,data,p=build(SOURCE,backend,version,{**BASE,'opcode_synthesis':True,'synthesis_max_code_growth':0})
            assert not data['regions'] and not data['handlers']
            # The enabled request is part of existing runtime-layout entropy,
            # so source frame keys may differ even without an admitted region.
            assert data['blob_hash']==base_data['blob_hash'],'zero cost budget must leave original operand storage intact'
            assert p.last_lowered_ir.backend_data['layout'].functions.code==base_pass.last_lowered_ir.backend_data['layout'].functions.code
            assert execute(output,version)[0]==execute(baseline,version)[0]
            assert dict(p.last_lowered_ir.backend_data['synthesis_plan'].rejected)['emitted_code_budget']
            count+=1
            # Exercise suspension/error after a region that really is synthesized.
            source='local co=coroutine.create(function() '+SOURCE.replace('print(sum)','coroutine.yield(sum,nil);error("expected",0)')+' end);print(coroutine.resume(co));print(coroutine.resume(co))'
            output,data,p=build(source,backend,version,{**BASE,'opcode_synthesis':True,'synthesis_policy':'protection'})
            assert data['regions'] and execute(output,version)[0]==execute(source,version)[0]
            count+=1
    for version in arguments.lua:
        if 'karity' in arguments.backends:
            settings={**BASE,**PROTECTED,'block_variant_rate':0,'physical_block_permutation_rate':0}
            ordinary,_,_=build(SOURCE,'karity',version,settings,event_trace=True)
            synthesized,data,_=build(SOURCE,'karity',version,{**settings,'opcode_synthesis':True,'synthesis_policy':'protection'},event_trace=True)
            before=execute(ordinary,version)[0];after=execute(synthesized,version)[0]
            assert data['handlers'] and before==after and b'_route_step' in after and b'_ss_step' in after
            count+=1
        if 'classic' not in arguments.backends:continue
        source='local sum=0;for i=1,2 do '+LONG_BODY*32+' end;print(sum)'
        output,data,p=build(source,'classic',version,{**BASE,'mutate_handlers':True,'opcode_synthesis':True,'synthesis_policy':'protection','synthesis_max_steps':16,'synthesis_max_recipes':32,'synthesis_max_code_growth':64})
        assert execute(output,version)[0]==execute(source,version)[0]
        assert p.last_lowered_ir.backend_data['synthesis_emission'][0]['storage']=='closure_bank'
        count+=1
    print('opcode-synthesis-backend-regression-ok',count,'VM builds + six byte-identical disabled paths')
if __name__=='__main__':
    from obfuscator.vm.synthesis import costs
    choose=costs.choose_regions
    def checked(*args,**kwargs):
        before=random.getstate()
        result=choose(*args,**kwargs)
        assert random.getstate()==before,'cost probes must not consume runtime/protection RNG'
        return result
    with patch.object(costs,'choose_regions',checked):main()
