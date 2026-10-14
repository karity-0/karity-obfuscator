"""Real backend recipe execution, protected event replay and safe fallback."""
from pathlib import Path
from dataclasses import replace
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools'),str(ROOT/'test')]
from profile_opcode_synthesis import build,BASE,PROTECTED,SOURCE,REPEATED,FUNCTIONS
from profile_vm_runtime import execute
from run_opcode_synthesis_regression import must_fail
from obfuscator.vm.synthesis.planner import validate_plan
from obfuscator.vm.backends.handler_layout import validate_layout
from obfuscator.vm.backends.runtime_layout import iter_functions
from obfuscator.vm.mov.validate import validate_host_bindings

SEMANTICS="""local fs={};for i=1,3 do local n=i;fs[i]=function(...) n=n+1;return n,... end end;
for i=1,3 do local a,b,c,d=fs[i](nil,9,nil);print(a,b,c,d) end;
local co=coroutine.create(function()coroutine.yield('yield',nil);return 'done',nil end);
print(coroutine.resume(co));print(coroutine.resume(co));
print(pcall(function()error('expected',0)end));
local mt={__add=function(a,b)return a.x+b.x end};local a=setmetatable({x=3},mt);local b=setmetatable({x=7},mt);print(a+b)
"""
LONG_BODY='local a=i+3;'+''.join('a=a*2;a=a-3;' for _ in range(8))+'sum=sum+a;'
LONG='local sum=0;for i=1,10 do '+LONG_BODY+' end;print(sum)'
def main():
    count=0
    for version in ('5.1','5.3'):
        for backend in ('classic','karity','mov'):
            off,data,_=build(SOURCE,backend,version,BASE)
            explicit,other,_=build(SOURCE,backend,version,{**BASE,'opcode_synthesis':False})
            assert off==explicit and data['blob_hash']==other['blob_hash']
            fixtures=(('dag',SOURCE,{}),('shared',REPEATED,{}),('multivm',FUNCTIONS,{'vm_count':3}),
                ('protected',SOURCE,PROTECTED),('composed',SOURCE,{**PROTECTED,'junk_instructions':True,'junk_rate':.08,'ir_mba_rate':.5}),('semantics',SEMANTICS,{}),
                ('overwrite',SOURCE.replace('local a=i*3;local b=a+7;local c=b*5;sum=sum+c','local a=i*3;a=a+7;a=a*5;sum=sum+a'),{}),
                ('pending_head',SOURCE.replace('i*3','i+3'),PROTECTED),
                ('float',SOURCE.replace('i*3','i*1.5').replace('b*5','-b'),{}))
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
                    if name=='protected' and backend=='karity':
                        layout=p.last_lowered_ir.backend_data['layout']
                        functions=list(iter_functions(layout.functions))
                        assert sum(len(f.synthesis) for f in functions)>data['regions'],'block variants must retain atomic recipe clones'
                        assert any(v in layout.vm_maps[f.vm_id][3].values() for f in functions for e in f.synthesis for v in e.original_vops),'pending arithmetic must remain deferred'
                        assert p.last_lowered_ir.backend_data['karity_state'].occurrence_inventory()[0]
                    count+=1
                    print('synthesis-backend-ok',backend,version,name,policy,data['regions'],data['handlers'],flush=True)
            output,data,_=build(REPEATED,backend,version,{**BASE,'opcode_fusion':True,'opcode_splitting':True,'opcode_synthesis':True,'synthesis_policy':'efficiency','synthesis_max_recipes':1})
            assert execute(output,version)[0]==execute(REPEATED,version)[0]
            assert data['handlers']<=1
            if backend!='mov':assert data['fallbacks']>0
            count+=1
    for version in ('5.1','5.3'):
        source='local sum=0;for i=1,2 do '+LONG_BODY*32+' end;print(sum)'
        output,data,p=build(source,'classic',version,{**BASE,'mutate_handlers':True,'opcode_synthesis':True,'synthesis_policy':'protection','synthesis_max_steps':16,'synthesis_max_recipes':32})
        assert execute(output,version)[0]==execute(source,version)[0]
        assert p.last_lowered_ir.backend_data['synthesis_emission'][0]['storage']=='closure_bank'
        count+=1
    print('opcode-synthesis-backend-regression-ok',count,'VM builds + six byte-identical disabled paths')
if __name__=='__main__':main()
