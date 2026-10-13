"""Independent structural proofs and native/VM differential morphing coverage."""
from pathlib import Path
from dataclasses import replace
import sys
import random
import math

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tools'))
from profile_vm_runtime import execute,FIXTURES,SETTINGS
from obfuscator.vm import VMPass
from obfuscator.vm.targets.profile import TargetProfile
from obfuscator.vm.ir.morphing import morph_semantic_ir,RATES
from obfuscator.vm.ir.optimize import optimize_semantic_ir
from obfuscator.vm.ir.validate import validate_semantic_ir
from obfuscator.vm.ir.morph_mba import PATTERNS
from obfuscator.toolchain import LuaToolchain
from lupa.lua53 import LuaRuntime

CASES={
 'ir_mba_rate':'local x=9223372036854775807;for i=1,9 do x=(x+i)~i;x=x-(-i);x=x&i;x=x|i end;local k=math.type(x);print(x,k)',
 'ir_test_set_rate':"local function f(a,b)return a or b,a and b end;for _,v in ipairs({false,0,'',{},true})do local a,b=f(v,9);print(type(a),a==v,b==v)end;local a,b=f(nil,5);print(a,b)",
 'ir_tail_duplication_rate':"local trace={};local function f(n)local x;if n>1 then x=7 else x=9 end;return x end;local a,b=f(2),f(0);trace[#trace+1]=a;trace[#trace+1]=b;print(a,b,table.concat(trace,','))",
 'ir_rematerialization_rate':'local x=1;for i=1,20 do local s=i~x;local a=s&255;local b=s>>1;x=a+b end;print(x)',
}
POLICY={**dict.fromkeys(RATES,1.0),'ir_morph_max_growth':3.0,'ir_morph_max_new_operations':12,
        'ir_morph_max_depth':3,'physical_block_permutation_rate':1.0}


def pattern_checks():
    lua=LuaRuntime()
    operators={'ADD':'+','SUB':'-','BIT_XOR':'~','BIT_AND':'&','BIT_OR':'|','BIT_NOT':'~'}
    values=(0,1,-1,2,-2,127,-128,(1<<63)-1,-(1<<63),-987654321)
    for original,patterns in PATTERNS.items():
        expected=lua.eval(f'function(x,y)return x {operators[original]} y end')
        for pattern in patterns:
            statements=['local a,b,d']
            for op,dst,*args in pattern:
                expression='~'+args[0] if len(args)==1 else args[0]+operators[op]+args[1]
                statements.append(dst+'='+expression)
            compiled=lua.eval('function(x,y)'+';'.join(statements)+';return d end')
            for x in values:
                for y in values:assert compiled(x,y)==expected(x,y),(original,pattern,x,y)


def structural_checks():
    target=TargetProfile('5.3','karity').adapter()
    for key,source in CASES.items():
        ir=optimize_semantic_ir(target.build_ir(target.compile(source,LuaToolchain())))
        out,stats=morph_semantic_ir(ir,{key:1,'ir_morph_max_growth':4,'ir_morph_max_new_operations':12},'5.3')
        validate_semantic_ir(out)
        assert out.generation!=ir.generation,(key,stats)
        assert any(r.get('applied',0)>0 for r in stats),key
        if key=='ir_test_set_rate':
            assert not any(i.operation=='TEST_SET' for f in out.functions() for b in f.blocks for i in b.instructions)
        if key=='ir_mba_rate':
            assert optimize_semantic_ir(out).dump()==out.dump()
        disabled,_=morph_semantic_ir(ir,{},'5.3')
        assert disabled is ir
        bounded,records=morph_semantic_ir(ir,{**POLICY,'ir_morph_max_added_instructions':0},'5.3')
        assert bounded.dump()==ir.dump() and not any(r.get('applied',0) for r in records)
        ids=[i.id for f in out.functions() for b in f.blocks for i in b.instructions]
        assert len(ids)==len(set(ids))
    # An uncertain bit operation can invoke a metamethod returning any value.
    source='local function f(x)local a=x&1;return a~2 end;return f'
    ir=target.build_ir(target.compile(source,LuaToolchain()))
    out,stats=morph_semantic_ir(ir,{'ir_mba_rate':1},'5.3')
    assert out.dump()==ir.dump()
    assert any(r.get('skipped',{}).get('unproven_integer') for r in stats)


def build_case(source,options,version,backend,seed):
    random.seed(seed)
    p=VMPass(target=TargetProfile(version,backend),vm_options=options)
    output=p.run(source)
    assert execute(output,version)[0]==execute(source,version)[0],(version,backend,seed,source)
    validate_semantic_ir(p.last_morphed_ir)
    assert p.last_protection_plan.generation==p.last_semantic_ir.generation
    return p


def main():
    pattern_checks();structural_checks();builds=0
    for backend in ('classic','karity','mov'):
        for key,source in CASES.items():
            p=build_case(source,{key:1,'ir_morph_max_growth':4,'ir_morph_max_new_operations':12},'5.3',backend,801)
            assert any(r.get('applied',0) for r in p.last_profile),key
            builds+=1;print('ir-morph-strategy-ok',backend,key,flush=True)
    # Full supported integration, including two seed variants and six target/backend pairs.
    for version in ('5.1','5.3'):
        for backend in ('classic','karity','mov'):
            options={**POLICY,'physical_block_permutation_rate':0 if backend=='mov' else 1}
            if backend=='karity':options.update(SETTINGS['protected'])
            for seed in (1283,6011):
                source=FIXTURES['closures']+";local function f(a,b)return a or b end;print(f(false,9),f(7,nil));local s=0;for i=1,7 do if i%2==0 then s=s+i else s=s-i end end;print(s)"
                build_case(source,options,version,backend,seed)
                builds+=1;print('ir-morph-combined-ok',version,backend,seed,flush=True)
    # Non-integer/metamethod effects must execute exactly once at their original point.
    source="local count=0;local t=setmetatable({},{__add=function()count=count+1;return 3.5 end});local a=t+1;local z=-0.0;print(a,count,1/z,0/0==0/0);local ok=pcall(function()error('expected',0)end);print(ok)"
    for backend in ('classic','karity','mov'):
        build_case(source,POLICY if backend!='mov' else {**POLICY,'physical_block_permutation_rate':0},'5.3',backend,9911)
        builds+=1
    print('ir-morphing-regression-ok',builds,'builds, all identities, structure, optimizer provenance, effects and budgets')


if __name__=='__main__':main()
