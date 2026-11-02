"""Proofs must not survive uncertain arithmetic, captured writes or CFG joins."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from obfuscator.vm.ir.facts import analyze_function,literal_fact,merge_facts,cfg_components,INTEGER,UNKNOWN
from obfuscator.vm.targets.profile import TargetProfile
from obfuscator.toolchain import LuaToolchain


def analyze(source,version='5.3'):
    target=TargetProfile(version,'karity').adapter()
    ir=target.build_ir(target.compile(source,LuaToolchain(lua_version=version)))
    return ir,{f.id:analyze_function(f,version) for f in ir.functions()}


def main():
    from types import SimpleNamespace
    graph=SimpleNamespace(blocks=tuple(SimpleNamespace(id=n,successors=s) for n,s in
        (('entry',('left','right')),('left',('join',)),('right',('join',)),
         ('join',('loop',)),('loop',('join','exit')),('exit',()))))
    predecessors,components=cfg_components(graph)
    assert predecessors['join']=={'left','right','loop'}
    assert components['join']==components['loop']
    assert len({components[n] for n in ('entry','left','right','join','exit')})==5
    ir,facts=analyze('local x=1;for i=1,20 do x=x~i end;print(x)')
    integer_ops=[i for b in ir.root.blocks for i in b.instructions if i.operation=='BIT_XOR']
    assert integer_ops and all(facts[ir.root.id].operand(i,r).kind=='integer' for i in integer_ops for r in ('left','right'))
    ir,table=analyze('local a,b=17,3;local q=a//b;local r=a%b;print(q+r)')
    info=table[ir.root.id]
    instructions=[i for b in ir.root.blocks for i in b.instructions]
    divisions=[i for i in instructions if i.operation in {'MOD','FLOOR_DIV'}]
    assert len(divisions)==2 and all(not info.effects[i.id].pure for i in divisions)
    addition=next(i for i in instructions if i.operation=='ADD')
    assert all(info.operand(addition,role).kind=='integer' for role in ('left','right'))
    for source in (
        "local x=1;local function f()x='changed'end;f();print(x+1)",
        "local x=1;local a=setmetatable({},{__add=function()x='changed';return 1 end});local z=a+1;print(x+1)",
    ):
        ir,table=analyze(source);info=table[ir.root.id]
        adds=[i for b in ir.root.blocks for i in b.instructions if i.operation=='ADD']
        assert adds and info.operand(adds[-1],'left')==UNKNOWN
    ir,table=analyze('local function f(v)local a=v&1;return a~2 end;return f')
    child=ir.root.children[0]
    assert all(table[child.id].operand(i,'left')==UNKNOWN for b in child.blocks for i in b.instructions if i.operation=='BIT_XOR')
    ir,_=analyze("local x=1;local function f()x='changed';return 7 end;local n=f();print(n,x+1)")
    instructions=[i for b in ir.root.blocks for i in b.instructions]
    call=next(i for i in instructions if i.operation=='CALL')
    typed=analyze_function(ir.root,'5.3',result_hints={call.id:INTEGER})
    assert typed.effects[call.id].may_call and not typed.effects[call.id].pure
    addition=next(i for i in instructions if i.operation=='ADD')
    assert typed.operand(addition,'left')==UNKNOWN, 'return type hint hid a captured write'
    assert literal_fact(-0.0,'5.3')!=literal_fact(0.0,'5.3')
    assert merge_facts([literal_fact(-0.0,'5.3'),literal_fact(0.0,'5.3')]).known is False
    assert literal_fact(True,'5.3').kind=='boolean'
    assert literal_fact(1,'5.1').kind=='float'
    assert merge_facts([INTEGER,UNKNOWN])==UNKNOWN
    ir,table=analyze('local n=0;for i=1,9 do local a=i*3;n=n+a end;print(n)','5.1')
    muls=[i for b in ir.root.blocks for i in b.instructions if i.operation=='MUL']
    assert muls and all(table[ir.root.id].operand(i,'left').kind=='float' for i in muls)
    for version in ('5.1','5.3'):
        ir,table=analyze('local function f(...)return ... end;return f(1,nil,3,nil)',version)
        assert any(info.liveness.open_extents for info in table.values())
    print('ir-facts-regression-ok integer loops, effects, captures, unknown results, float bits, open top')


if __name__=='__main__':main()
