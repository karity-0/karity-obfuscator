"""Ordered mixed DAGs, captured owners and guarded Karity intermediates."""
from pathlib import Path
from dataclasses import replace
from unittest.mock import patch
import argparse
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools'),str(ROOT/'test')]
from profile_opcode_synthesis import build,BASE,PROTECTED
from profile_vm_runtime import execute
from obfuscator.vm.synthesis import planner
from obfuscator.vm.synthesis.lowering import dump_plan
from run_opcode_synthesis_regression import must_fail


def guard_contract(version):
    from obfuscator.vm.synthesis.register_local import guarded_read
    guard=guarded_read('v','epoch','generation','position','slot','candidate')
    source='''local _MG,_RE,_PD={1},{[7]=10},{};local slot=3
local function _rpos(_,r)return r end
local function read(v,epoch,generation,position)
'''+guard+'''
return candidate end
assert(read(19,10,1,7)==19)
_RE[7]=11;assert(read(19,10,1,7)==nil,'stale epoch')
_RE[7]=10;_MG[1]=2;assert(read(19,10,1,nil)==nil,'stale mapping before address lookup')
_MG[1]=1;_PD[slot]={};assert(read(19,10,1,7)==nil,'pending value must finish through original helper')
_PD[slot]=nil;assert(read(false,10,1,7)==false)
assert(read(nil,10,1,7)==nil)
print('guard-contract-ok')'''
    assert execute(source,version)[0]==b'guard-contract-ok'


def force_local_form(form):
    from obfuscator.vm.synthesis import costs
    choose=costs.choose_regions
    def force(lowered,*args,**kwargs):
        result=choose(lowered,*args,**kwargs)
        for o in lowered.backend_data['synthesis_plan'].occurrences:
            if o.local_values:
                lowered.backend_data['synthesis_execution_forms'][o.source_ids]=form
        return result
    return patch.object(costs,'choose_regions',force)


def stress_checks(version):
    source='local s=0;for i=1,3 do local a=i*1.5;'+('a=a*1.25;'*16)+'s=s+a end;print(s)'
    for mutate in (False,True):
        for form in ('locals','cells'):
            with force_local_form(form):
                output,data,p=build(source,'karity',version,{**BASE,**PROTECTED,'mutate_handlers':mutate,
                    'opcode_synthesis':True,'synthesis_policy':'protection','synthesis_max_steps':16,
                    'synthesis_max_code_growth':64,'block_variant_rate':0,'physical_block_permutation_rate':0})
            assert data['handlers'] and execute(output,version)[0]==execute(source,version)[0]
            stats=p.last_lowered_ir.backend_data['synthesis_emission'].values()
            assert any(r['guarded_register_local_handlers'] and r['guarded_local_edges']>=15 for r in stats)
            print('guarded-local-stress',version,form,mutate,flush=True)
    return 4

FIXTURES={
    'captured_owner': '''local sum=0;local function get()return sum end
for i=1,12 do local a=i*3;local b=a+7;local c=b*5;sum=sum+c end
print(sum,get())''',
    'unrelated_capture': '''local x=9;local function get()return x end;local sum=0
for i=1,12 do local a=i*3;local b=a+7;local c=b*5;sum=sum+c end
print(sum,get())''',
    'open_tail': '''local function f(...)local s=0
for i=1,8 do local a=i*3;local b=a+7;local c=b*5;s=s+c end
return s,... end;print(f(nil,9,nil))''',
    'table_numeric': '''local t={4,7,9};local s=0
for i=1,3 do local a=t[i];local b=a*3;local c=b+7;s=s+c end;print(s)''',
    'table_bit': '''local t={4,7,9};local s=0
for i=1,3 do local a=t[i];local b=a~3;local c=b&15;s=s+c end;print(s)''',
    'table_false_nil': '''local t={false};local s
for i=1,2 do local a=t[i];local b=not a;local c=not b;s=c end;print(s)''',
    'more_arithmetic': '''local t={1,2,3,4};local s=0
for i=1,3 do local a=#t;local b=a%3;local c=b/2;local d=c^2;s=s+d end;print(s)''',
    'floor_division': '''local t={41};local s=0
for i=1,3 do local a=t[1];local b=a//3;local c=b%4;s=s+c end;print(s)''',
    'metamethod_order': '''local log={};local mt={}
mt.__mul=function(a,b)log[#log+1]='mul';return setmetatable({n=a.n*b},mt)end
mt.__add=function(a,b)log[#log+1]='add';return a.n+b end
local t=setmetatable({},{__index=function()log[#log+1]='get';return setmetatable({n=7},mt)end})
local a=t[1];local b=a*2;local c=b+3;print(c,table.concat(log,','))''',
    'captured_callback': '''local x=2;local function read()return x end
local t=setmetatable({},{__index=function()x=13;return 3 end})
local a=t[1];local b=a*read();local c=b+2;local d=c*3;print(d,x)''',
    'captured_clobber_in_region': '''local x=2;local function read()return x end
local t=setmetatable({},{__index=function()x=13;return 3 end})
local a=x*3;local b=t[1];local c=x*b;local d=c+a;print(d,read())''',
    'captured_write_before_error': '''local get
local function run()local x=2;get=function()return x end
x=x*3;x=x+7;x=x*5;local a={}*3;return a end
local ok=pcall(run);print(ok,get())''',
    'metamethod_error': '''local log={};local t=setmetatable({},{__index=function()
log[#log+1]='get';return setmetatable({},{__mul=function()error('stop',0)end})end})
local function f()local a=t[1];local b=a*3;local c=b+2;return c*5 end
local ok,err=pcall(f);print(ok,err,table.concat(log,','))''',
    'metamethod_yield': '''local t=setmetatable({},{__index=function()
coroutine.yield('get',nil);return 7 end})
local co=coroutine.create(function()local a=t[1];local b=a*3;local c=b+2;return c*5,nil end)
print(coroutine.resume(co));print(coroutine.resume(co))''',
    'local_float': '''local s=0;for i=1,24 do local a=i*1.5;local b=a*2;local c=b*3;s=s+c end;print(s)''',
    'pending_fanout': '''local s=0;for i=1,24 do local a=i+3;local b=a*2;local c=b+a;s=s+c end;print(s)''',
    'mixed_proofs': '''local s=0;for i=1,3 do local a=i*3;local b=a+7;local c=b*5;s=s+c end
local function f(i,s)local a=i*3;local b=a+7;local c=b*5;s=s+c;return s end
local t=setmetatable({n=2},{__mul=function(a,b)return a.n*b end});print(s,f(t,0))''',
}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backends',nargs='+',default=['classic','karity','mov'])
    parser.add_argument('--lua',nargs='+',default=['5.1','5.3'])
    parser.add_argument('--stress-only',action='store_true')
    args=parser.parse_args();count=0
    if args.stress_only:
        for version in args.lua:stress_checks(version)
        return
    for version in args.lua:
        guard_contract(version)
        for backend in args.backends:
            for name,source in FIXTURES.items():
                if version=='5.1' and name in ('table_bit','floor_division','metamethod_yield'):continue
                # Native 5.1 cannot yield across metamethod C-call boundaries.
                for protected in (False,True):
                    settings={**BASE,**(PROTECTED if protected else {}),'opcode_synthesis':True,
                        'synthesis_policy':'protection','synthesis_max_steps':8,'synthesis_max_recipes':64,
                        'synthesis_max_code_growth':64,'table_virtualization':protected,
                        'upvalue_virtualization':protected,'vm_count':2 if protected else 1}
                    output,data,p=build(source,backend,version,settings)
                    assert execute(output,version)[0]==execute(source,version)[0],(backend,version,name,protected)
                    assert data['regions'] and data['handlers'],(backend,version,name,protected,data['rejected'])
                    plan=p.last_lowered_ir.backend_data['synthesis_plan']
                    assert all(s.operation not in ('TAIL_CALL','RETURN','CLOSURE','VARARG')
                               for r in plan.recipes for s in r.steps)
                    if name=='mixed_proofs':
                        assert {r.ordered for r in plan.recipes}=={False,True},(backend,version,protected)
                    assert not {'active_capture','open_register_top'} & data['rejected'].keys()
                    if name in ('table_numeric','table_false_nil','table_bit','metamethod_order','metamethod_yield'):
                        recipes={r.id:r for r in plan.recipes}
                        assert any(recipes[o.recipe].ordered and any(s.operation in ('GET_TABLE','GET_UPVALUE_TABLE') for s in recipes[o.recipe].steps)
                                   for o in plan.occurrences),(backend,version,name)
                        assert all(o.materialize and not o.local_values for o in plan.occurrences if recipes[o.recipe].ordered)
                    if backend=='karity' and name=='local_float':
                        assert any(o.local_values for o in plan.occurrences)
                        o=next(o for o in plan.occurrences if o.local_values)
                        bad=replace(o,local_values=())
                        must_fail(lambda:planner.validate_plan(p.last_semantic_ir,replace(plan,
                            occurrences=tuple(bad if x is o else x for x in plan.occurrences)),
                            protection_plan=p.last_protection_plan))
                        assert 'local_values' in dump_plan(p.last_lowered_ir)
                    count+=1
                    print('synthesis-dag-ok',backend,version,name,protected,data['regions'],flush=True)
            if backend!='karity':continue
            for name in ('table_numeric','metamethod_order'):
                settings={**BASE,**PROTECTED,'block_variant_rate':0,'physical_block_permutation_rate':0}
                ordinary,_,_=build(FIXTURES[name],backend,version,settings,event_trace=True)
                synthesized,data,_=build(FIXTURES[name],backend,version,{**settings,'opcode_synthesis':True,
                    'synthesis_policy':'protection','synthesis_max_code_growth':64},event_trace=True)
                assert data['regions'] and execute(ordinary,version)[0]==execute(synthesized,version)[0],(version,name)
                count+=2
            # Prove actual bank reads are bypassed, while writes/route/state
            # traces stay identical. Disabling only the new raw temporaries
            # retains exactly the same regions, aliases and opcode layout.
            original=planner._region
            def no_local(*a,**kw):
                found,reason=original(*a,**kw)
                if found:
                    recipe,o=found;found=recipe,replace(o,local_values=())
                return found,reason
            for protected in (False,True):
                settings={**BASE,**(PROTECTED if protected else {}),'opcode_synthesis':True,
                    'synthesis_policy':'protection','synthesis_max_code_growth':64,
                    'block_variant_rate':0,'physical_block_permutation_rate':0}
                with patch.object(planner,'_region',no_local):
                    before,_,_=build(FIXTURES['local_float'],backend,version,settings,instrument=True,event_trace=True)
                def counters(s):return tuple(int(x) for x in s.split(b'SYN-COUNTERS\t')[1].splitlines()[0].split(b'\t'))
                a=execute(before,version)[0];ac=counters(a)
                for form in ('locals','cells'):
                    # Exercise both compiler-admissible forms independently of
                    # the seeded production diversity selection. Budgets are
                    # deliberately ample; no protection plan is modified.
                    with force_local_form(form):
                        after,_,_=build(FIXTURES['local_float'],backend,version,settings,instrument=True,event_trace=True)
                    b=execute(after,version)[0];bc=counters(b)
                    assert ac[0]==bc[0] and ac[2:]==bc[2:],(version,protected,form,ac,bc)
                    assert bc[1]<ac[1],(version,protected,form,ac,bc)
                    assert a.split(b'SYN-EVENTS')[1]==b.split(b'SYN-EVENTS')[1],(version,protected,form)
                    print('guarded-local-reads',version,protected,form,ac,bc,flush=True)
                    count+=1
                count+=1
            count+=stress_checks(version)
    print('synthesis-dag-regression-ok',count,flush=True)


if __name__=='__main__':main()
