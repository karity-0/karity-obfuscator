"""Phase A/B proofs: real semantic DAGs, local writes and explicit barriers."""
from pathlib import Path
from dataclasses import replace
import random
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools')]
from obfuscator.toolchain import LuaToolchain
from obfuscator.vm.targets.profile import TargetProfile
from obfuscator.vm.ir.optimize import optimize_semantic_ir
from obfuscator.vm.protection import ProtectionPlanner
from obfuscator.vm.synthesis.planner import build_plan,validate_plan
from obfuscator.vm.synthesis.model import Ref,Binding
from obfuscator.vm.synthesis.prototype import emit_region_benchmark,emit_kernel,allocate_opcodes,encode_occurrence
from profile_vm_runtime import execute

SOURCE='local sum=0;for i=1,20 do local a=i*3;local b=a+7;local c=b*5;sum=sum+c end;print(sum)'
def frontend(source,version):
    target=TargetProfile(version,'classic').adapter()
    return optimize_semantic_ir(target.build_ir(target.compile(source,LuaToolchain(lua_version=version))))
def must_fail(fn):
    try:fn()
    except ValueError:return
    raise AssertionError('invalid synthesis accepted')

def main():
    for version in ('5.1','5.3'):
        ir=frontend(SOURCE,version);original=ir.dump()
        before=random.getstate()
        plan=build_plan(ir,lua_version=version,enabled=True,policy='efficiency',seed=19)
        assert random.getstate()==before and ir.dump()==original
        assert len(plan.recipes)==1 and len(plan.occurrences)==1
        occurrence=plan.occurrences[0];recipe=plan.recipes[0]
        assert len(recipe.steps)==4 and recipe.edges==((0,1),(1,2),(2,3))
        assert occurrence.cost.dispatch_before==4 and occurrence.cost.dispatch_after==1
        assert occurrence.cost.reads_before==5 and occurrence.cost.reads_after==2
        assert occurrence.cost.writes_before==4 and occurrence.cost.writes_after==1
        assert not build_plan(ir,lua_version=version).occurrences
        assert build_plan(ir,lua_version=version,enabled=True,policy='efficiency',seed=19).dump()==plan.dump()
        for mode,expected in (('ordinary',(4000,5000,4000)),('fusion',(2000,5000,4000)),('synthesis',(1000,2000,1000))):
            actual,_=execute(emit_region_benchmark(ir,plan,occurrence,mode=mode,iterations=1000,instrument=True),version)
            values=actual.split(b'\t');assert int(float(values[0]))==7542500
            assert tuple(int(float(x)) for x in values[1:])==expected,(version,mode,actual)
        codes=allocate_opcodes(plan.recipes,19,reserved=range(64))
        assert set(codes.values()).isdisjoint(range(64))
        assert codes==allocate_opcodes(plan.recipes,19,reserved=range(64))
        must_fail(lambda:allocate_opcodes(plan.recipes,reserved=range(32768)))
        word,bindings=encode_occurrence(occurrence,codes[recipe.id])
        assert len(word)==6 and len(bindings)==13
        from obfuscator.vm.backends.handler_codec import DEFAULT_INSTR_LAYOUT
        packed=int.from_bytes(word,'little')
        assert ((packed&127)|(((packed>>DEFAULT_INSTR_LAYOUT['V'])&255)<<7))==codes[recipe.id]
        assert 'local t0=' in emit_kernel(recipe) and emit_kernel(recipe).count('rset(')==1
        # Safety/performance policy never silently strips real protection events.
        protection=ProtectionPlanner({'junk_instructions':True,'graph_execution_rate':1,
            'integrity_constants':True,'semantic_state_threading':True}).build(ir)
        guarded=build_plan(ir,lua_version=version,enabled=True,protection_plan=protection)
        assert not guarded.occurrences and dict(guarded.rejected)['production_event_lowering_not_implemented']
        bad=replace(occurrence,inputs=(Binding('register',254),*occurrence.inputs[1:]))
        must_fail(lambda:validate_plan(ir,replace(plan,occurrences=(bad,))))
        bad=replace(occurrence,source_ids=tuple(reversed(occurrence.source_ids)))
        must_fail(lambda:validate_plan(ir,replace(plan,occurrences=(bad,))))
        bad_recipe=replace(recipe,steps=(replace(recipe.steps[0],inputs=(Ref('temporary',99),)),*recipe.steps[1:]))
        must_fail(lambda:validate_plan(ir,replace(plan,recipes=(bad_recipe,))))
        must_fail(lambda:validate_plan(ir,replace(plan,occurrences=(occurrence,occurrence))))
        must_fail(lambda:validate_plan(ir,replace(plan,generation='stale')))
        must_fail(lambda:validate_plan(ir,plan,lua_version='5.1' if version=='5.3' else '5.3'))
        # Temporary writes with protection provenance cannot become local temps.
        first=occurrence.source_ids[0]
        from dataclasses import replace as edit
        root=edit(ir.root,blocks=tuple(edit(b,instructions=tuple(edit(i,metadata={**i.metadata,'protection_origin':'ir_morph'}) if i.id==first else i for i in b.instructions)) for b in ir.root.blocks))
        marked=build_plan(edit(ir,root=root),lua_version=version,enabled=True)
        assert all(first not in o.source_ids for o in marked.occurrences)
        for source,reason in (
            ('local function f(a,b)local x=a*b;local y=x+7;return y*5 end;return f','unknown_or_metamethod'),
            ('local sum=0;local function f()return sum end;for i=1,20 do local a=i*3;local b=a+7;local c=b*5;sum=sum+c end;local result=f();print(result)','active_capture'),
            ('local function f(...)local sum=0;for i=1,20 do local a=i*3;local b=a+7;sum=sum+b*5 end;return sum,... end;return f','open_register_top'),
        ):
            rejected=build_plan(frontend(source,version),lua_version=version,enabled=True)
            assert not rejected.occurrences and dict(rejected.rejected).get(reason),(version,reason,rejected.dump())
        # Two structurally equal occurrences have distinct bindings/provenance.
        repeated=frontend('local sum=0;for i=1,20 do local a=i*3;local b=a+7;local c=b*5;sum=sum+c end;for j=1,20 do local a=j*3;local b=a+9;local c=b*5;sum=sum+c end;print(sum)',version)
        shared=build_plan(repeated,lua_version=version,enabled=True,policy='efficiency')
        regional=build_plan(repeated,lua_version=version,enabled=True,policy='protection')
        assert len(shared.occurrences)==2 and len(shared.recipes)==1
        assert len(regional.recipes)==2 and all(o.scope=='regional' for o in regional.occurrences)
        capped=build_plan(repeated,lua_version=version,enabled=True,policy='efficiency',max_occurrences=1)
        assert len(capped.occurrences)==1 and dict(capped.rejected)['occurrence_budget']==1
        capped=build_plan(repeated,lua_version=version,enabled=True,policy='protection',max_recipes=1)
        assert len(capped.recipes)==1 and dict(capped.rejected)['recipe_budget']==1
        for body in (
            'local a=i*3;a=a+7;a=a*5;sum=sum+a',
            'local a=i*1.5;local b=a-3.0;local c=-b;sum=sum+c',
            'local a=i*(-3);local b=a+7;local c=b*(-5);sum=sum+c',
            'local a=i*0.0;local b=a-0.0;local c=-b;sum=sum+c',
            'local a=i*3;local b=a+7;local c=b*5;sum=sum+c;local extra=sum-c',
            'local a=i*3;local b=i*7;local c=a+b;sum=sum+c',
        ):
            source='local sum=0;for i=1,1000 do '+body+' end;print(sum)'
            variant=frontend(source,version)
            selected=build_plan(variant,lua_version=version,enabled=True,policy='efficiency')
            assert selected.occurrences,(version,body,selected.dump())
            expected=execute(source,version)[0]
            for mode in ('ordinary','synthesis'):
                actual=execute(emit_region_benchmark(variant,selected,selected.occurrences[0],mode=mode,iterations=1000),version)[0]
                assert float(actual.split(b'\t')[0])==float(expected),(version,body,mode,actual,expected)
        print('opcode-prototype-ok',version,'DAG, dispatch/rget/rset, bindings, sharing, guards',flush=True)
    print('opcode-synthesis-regression-ok decoded prototype; production checked by backend regression')

if __name__=='__main__':main()
