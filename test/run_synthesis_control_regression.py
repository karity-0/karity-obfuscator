"""Terminal call/branch recipes preserve continuations and scope cleanup."""
from pathlib import Path
from dataclasses import replace
from unittest.mock import patch
import argparse
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools'),str(ROOT/'test')]
from profile_opcode_synthesis import build,BASE,PROTECTED
from profile_vm_runtime import execute
from obfuscator.vm.synthesis.strategies import TERMINAL
from obfuscator.vm.synthesis import kernels,planner
from run_opcode_synthesis_regression import must_fail,frontend

FIXTURES={
    'zero_args': ('''local t={function()return 7,nil end};local f=t[1];local g=f
local p,q=g();print(p,q)''','CALL'),
    'vm_call': ('''local function f(x)return x,nil,false,nil end
local function run(f,x)local a=x*3;local b=a+7;local c=b*5
local p,q,r,s=f(c);print(p,q,r,s);return p end
print(run(f,2))''','CALL'),
    'native_call': ('''local function run(f,x)local a=x*3;local b=a+7;local c=b*5
local p=f(c);return p end;print(run(math.sqrt,2))''','CALL'),
    'open_results': ('''local function f(x)return x,nil,false,nil end
local function run(f,x)local a=x*3;local b=a+7;local c=b*5
return (function(...)print(select('#',...),...);return ... end)(f(c)) end
print(run(f,2))''','CALL'),
    'capture_write': ('''local x=2;local function get()return x end
local function f(a)x={a};return nil,false,nil end
local function run(fn,n)local a=n*3;local b=a+7;local c=b*5
local p,q,r=fn(c);print(get()[1],p,q,r)end;run(f,2)''','CALL'),
    'call_error': ('''local x=2;local function get()return x end
local function f(a)x=a;error('stop',0)end
local function run(f,n)local a=n*3;local b=a+7;local c=b*5
local y=f(c);return y end;local ok,e=pcall(run,f,2);print(ok,e,get())''','CALL'),
    'call_yield': ('''local function f(a)coroutine.yield(a,nil,false);return a+1,nil end
local function run(f,x)local a=x*3;local b=a+7;local c=b*5
local p,q=f(c);return p,q end
local co=coroutine.create(function()return run(f,2)end)
print(coroutine.resume(co));print(coroutine.resume(co))''','CALL'),
    'less': ('''local function f(x)local a=x*3;local b=a+7
if b<20 then return 'less' else return 'more' end end;print(f(2),f(8))''','LESS_THAN'),
    'equal': ('''local function f(x)local a=x*3;local b=a+7
if b==13 then return 'yes' else return 'no' end end;print(f(2),f(8))''','EQUAL'),
    'less_equal': ('''local function f(x)local a=x*3;local b=a+7
if b<=13 then return 'yes' else return 'no' end end;print(f(2),f(8))''','LESS_EQUAL'),
    'truth': ('''local function f(x)local a=not x;local b=not a
if b then return 'yes' else return 'no' end end;print(f(false),f(nil),f(0))''','TEST'),
    'compare_callback': ('''local log={};local mt={}
mt.__add=function(a,b)log[#log+1]='add';return setmetatable({n=a.n+b},mt)end
mt.__mul=function(a,b)log[#log+1]='mul';return setmetatable({n=a.n*b},mt)end
mt.__lt=function(a,b)log[#log+1]='lt';return a.n<b.n end
local function f(x,y)local a=x*3;local b=a+7
if b<y then return 'yes' else return 'no' end end
print(f(setmetatable({n=2},mt),setmetatable({n=20},mt)),table.concat(log,','))''','LESS_THAN'),
}


def banked():
    prepare=kernels.prepare_kernel
    def forced(entry,*args,**kwargs):
        body,scratch,report,elapsed=prepare(entry,*args,**kwargs)
        if entry.opcode and 'error' not in report:
            report={**report,'total_instructions':131072}
        return body,scratch,report,elapsed
    return patch.object(kernels,'prepare_kernel',forced)


CHAIN_SOURCE='local s=0;for i=1,4 do local a=i*3;local b=a+7;local c=b*5;s=s+c end;print(s)'


def split_blocks(ir):
    """Exercise preserved morph-style blocks, which normalization often merges."""
    from obfuscator.vm.ir.model import IRBlock
    from obfuscator.vm.ir.validate import validate_semantic_ir
    def split(fn):
        blocks=[]
        for b in fn.blocks:
            run=next((n for n in range(len(b.instructions)-2)
                      if all(i.operation in planner.SCALAR for i in b.instructions[n:n+3])),None)
            if run is None:
                blocks.append(b);continue
            cuts=(run+1,run+2,len(b.instructions));offset=0
            ids=(b.id,b.id+':linear1',b.id+':linear2')
            for n,end in enumerate(cuts):
                instructions=b.instructions[offset:end];targets=(ids[n+1],) if n<2 else b.successors
                instructions=(*instructions[:-1],replace(instructions[-1],targets=targets))
                blocks.append(IRBlock(ids[n],instructions,targets));offset=end
        return replace(fn,blocks=tuple(blocks),children=tuple(split(c) for c in fn.children),
                       debug_metadata={**fn.debug_metadata,'morph_strategies':('test-linear-split',)})
    result=replace(ir,root=split(ir.root));validate_semantic_ir(result);return result


def chains(backend,version):
    from obfuscator.vm.ir import morphing
    original=morphing.morph_semantic_ir
    def split(*args,**kw):
        ir,profile=original(*args,**kw)
        return split_blocks(ir),profile
    with patch.object(morphing,'morph_semantic_ir',split):
        output,data,p=build(CHAIN_SOURCE,backend,version,{**BASE,**PROTECTED,
            'opcode_synthesis':True,'synthesis_policy':'protection',
            'synthesis_max_code_growth':64,'block_variant_rate':0})
    assert execute(output,version)[0]==execute(CHAIN_SOURCE,version)[0]
    plan=p.last_lowered_ir.backend_data['synthesis_plan']
    locations={i.id:b.id for f in p.last_lowered_ir.semantic_ir.functions() for b in f.blocks for i in b.instructions}
    cross=[o for o in plan.occurrences if len({locations[s] for s in o.source_ids})>=3]
    assert cross and data['handlers'],(backend,version,plan.dump())
    o=cross[0]
    must_fail(lambda:planner.validate_plan(p.last_lowered_ir.semantic_ir,replace(plan,
        occurrences=tuple(replace(x,block=locations[x.source_ids[-1]]) if x is o else x for x in plan.occurrences)),
        protection_plan=p.last_protection_plan))
    print('synthesis-linear-chain-ok',backend,version,flush=True)


def proofs(version):
    from obfuscator.vm.synthesis.strategies import linear_chains
    from obfuscator.vm.ir.facts import analyze_function
    ir=split_blocks(frontend(CHAIN_SOURCE,version));fn=ir.root;facts=analyze_function(fn,version)
    groups=linear_chains(fn,facts,'karity');chain=next(c for c in groups if len(c)>=3)
    # Even an otherwise identical adjacent block must remain separate if it
    # has an extra predecessor. No speculation through joins or loop headers.
    target=chain[1].id;facts.predecessors[target].add('external-entry')
    assert not any(chain[0] in c and chain[1] in c for c in linear_chains(fn,facts,'karity'))
    open_ir=frontend('local function f(g,x,...)local a=x*3;local b=a+7;local c=b*5;local y=g(c,...);return y end;return f',version)
    plan=planner.build_plan(open_ir,lua_version=version,backend='karity',enabled=True,policy='protection')
    assert dict(plan.rejected).get('open_call_arguments')
    assert not any(s.operation=='CALL' for r in plan.recipes for s in r.steps)
    print('synthesis-control-proofs-ok',version,flush=True)


def variant_fallback(backend,version):
    source='''local function f(x)local a=x*3;local b=a+7;local c=b*5
if c<100 then return 'less' else return 'more' end end;print(f(2),f(8))'''
    output,data,p=build(source,backend,version,{**BASE,**PROTECTED,'opcode_synthesis':True,
        'synthesis_policy':'protection','synthesis_max_code_growth':64,'block_variant_rate':1})
    assert execute(output,version)[0]==execute(source,version)[0]
    plan=p.last_lowered_ir.backend_data['synthesis_plan']
    assert dict(plan.rejected).get('terminal_block_variants')
    assert any(d.get('fallback')=='terminal_block_variants' for d in plan.decisions)
    assert data['handlers'] and any(d.get('recovered_prefix_candidates',0)>0 for d in plan.decisions)
    assert any(all(s.operation in planner.SCALAR for s in r.steps) for r in plan.recipes)
    print('synthesis-control-variants-retained',backend,version,flush=True)


def traces(version):
    # Uniform physical forms make original logical route/state traces directly
    # comparable. Graph/alias/state protections remain enabled on both sides.
    for name in ('vm_call','compare_callback'):
        source,operation=FIXTURES[name]
        settings={**BASE,**PROTECTED,'mutate_handlers':False,'cross_instruction_rate':0,
            'opcode_fusion':False,'block_variant_rate':0,'physical_block_permutation_rate':0}
        before,_,_=build(source,'karity',version,settings,event_trace=True)
        after,_,_=build(source,'karity',version,{**settings,'opcode_synthesis':True,
            'synthesis_policy':'protection','synthesis_max_steps':10,'synthesis_max_code_growth':64},event_trace=True)
        assert execute(before,version)[0]==execute(after,version)[0],(version,name)
        print('synthesis-control-events-retained',version,name,flush=True)


def check(source,operation,backend,version,protected,bank=False,dispatcher=None):
    settings={**BASE,**(PROTECTED if protected else {}),'opcode_synthesis':True,
        'synthesis_policy':'protection','synthesis_max_steps':10,'synthesis_max_recipes':64,
        'synthesis_max_code_growth':64,'vm_count':2 if protected else 1,
        'block_variant_rate':0,'physical_block_permutation_rate':1 if protected else 0}
    if dispatcher is not None:settings['dispatcher_type']=dispatcher
    output,data,p=build(source,backend,version,settings)
    assert execute(output,version)[0]==execute(source,version)[0],(backend,version,operation,protected)
    plan=p.last_lowered_ir.backend_data['synthesis_plan'];recipes={r.id:r for r in plan.recipes}
    matched=[o for o in plan.occurrences if recipes[o.recipe].steps[-1].operation==operation]
    assert matched and data['handlers'],(backend,version,operation,data['rejected'],plan.decisions)
    if operation=='CALL' and source not in (FIXTURES['zero_args'][0],FIXTURES['open_results'][0]):
        assert any(sum(s.operation in planner.SCALAR for s in recipes[o.recipe].steps)>=2 for o in matched),source
    if source==FIXTURES['open_results'][0]:
        instructions={i.id:i for f in p.last_lowered_ir.semantic_ir.functions() for b in f.blocks for i in b.instructions}
        assert any(any(v.role=='results' and v.count is None for v in instructions[o.source_ids[-1]].operands)
                   for o in matched),'the actual open-result call must be synthesized'
    assert all(not any(s.operation in TERMINAL for s in r.steps[:-1]) for r in plan.recipes)
    assert all(o.materialize and not o.local_values for o in matched)
    if bank:
        assert any(r['storage']=='closure_bank' for r in p.last_lowered_ir.backend_data['synthesis_emission'].values())
    print('synthesis-control-ok',backend,version,operation,protected,bank,flush=True)
    return p


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backends',nargs='+',default=['classic','karity','mov'])
    parser.add_argument('--lua',nargs='+',default=['5.1','5.3'])
    parser.add_argument('--dispatch-only',action='store_true')
    args=parser.parse_args();count=0
    if args.dispatch_only:
        for version in args.lua:
            for backend in args.backends:
                if backend=='mov':continue
                for dispatcher in ('ifelseif','bsearch','split4','bsplit6','tailcall','mixed'):
                    check(*FIXTURES['vm_call'],backend,version,True,dispatcher=dispatcher);count+=1
        print('synthesis-control-dispatch-ok',count,flush=True);return
    for version in args.lua:
        proofs(version)
        for backend in args.backends:
            chains(backend,version);count+=1
            variant_fallback(backend,version);count+=1
            for name,(source,operation) in FIXTURES.items():
                for protected in (False,True):
                    check(source,operation,backend,version,protected);count+=1
            if backend!='mov':
                with banked():
                    check(*FIXTURES['vm_call'],backend,version,True,bank=True);count+=1
            if backend=='karity':
                for dispatcher in ('ifelseif','bsearch','split4','bsplit6','tailcall','mixed'):
                    check(*FIXTURES['vm_call'],backend,version,True,dispatcher=dispatcher);count+=1
        if 'karity' in args.backends:traces(version);count+=4
    print('synthesis-control-regression-ok',count,flush=True)


if __name__=='__main__':main()
