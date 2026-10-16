"""Mechanism benchmark, not production backend/VM performance claims."""
from pathlib import Path
import argparse,json,random,statistics,sys,time
from dataclasses import asdict
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools')]
from obfuscator.toolchain import LuaToolchain
from obfuscator.vm.targets.profile import TargetProfile
from obfuscator.vm.ir.optimize import optimize_semantic_ir
from obfuscator.vm.protection import ProtectionPlanner
from obfuscator.vm.synthesis.planner import build_plan
from obfuscator.vm.synthesis.prototype import emit_region_benchmark,emit_kernel,encode_occurrence,allocate_opcodes
from profile_vm_runtime import execute

SOURCE='local sum=0;for i=1,COUNT do local a=i*3;local b=a+7;local c=b*5;sum=sum+c end;print(sum)'
def main():
    args=argparse.ArgumentParser(description=__doc__)
    args.add_argument('--output',type=Path,required=True)
    args.add_argument('--iterations',type=int,default=100000)
    args.add_argument('--repeats',type=int,default=7)
    opts=args.parse_args()
    if not 1<=opts.repeats<=100:raise ValueError('repeat budget')
    rows=[];report={'scope':'isolated decoded-region prototype; production backends untouched',
        'python':sys.version,'iterations':opts.iterations,'repeats':opts.repeats,'records':rows}
    for version in ('5.1','5.3'):
        source=SOURCE.replace('COUNT',str(opts.iterations))
        adapter=TargetProfile(version,'classic').adapter()
        ir=optimize_semantic_ir(adapter.build_ir(adapter.compile(source,LuaToolchain(lua_version=version))))
        t=time.perf_counter();plan=build_plan(ir,lua_version=version,enabled=True,policy='efficiency',seed=14000)
        planning=time.perf_counter()-t;assert len(plan.occurrences)==1
        occurrence=plan.occurrences[0];recipe=plan.recipes[0]
        native,_=execute(source,version)
        modes={};generated={}
        for mode in ('ordinary','fusion','synthesis'):
            generated[mode]=emit_region_benchmark(ir,plan,occurrence,mode=mode,iterations=opts.iterations,seed=14000)
            instrumented=emit_region_benchmark(ir,plan,occurrence,mode=mode,iterations=opts.iterations,instrument=True,seed=14000)
            result,_=execute(instrumented,version)
            parts=result.split(b'\t');assert float(parts[0])==float(native)
            modes[mode]={'scope':'fusion-shaped pair execution' if mode=='fusion' else 'isolated scalar dispatch' if mode=='ordinary' else 'generated recipe dispatch',
                         'source_bytes':len(generated[mode].encode()),'dispatches':int(float(parts[1])),
                         'register_reads':int(float(parts[2])),'register_writes':int(float(parts[3])),
                         'cpu_samples':[]}
        for repeat in range(opts.repeats):
            # Rotate order to reduce a consistent warmup/order advantage.
            order=list(modes);order=order[repeat%3:]+order[:repeat%3]
            for mode in order:
                actual,cpu=execute(generated[mode],version)
                assert float(actual.split(b'\t')[0])==float(native)
                modes[mode]['cpu_samples'].append(cpu)
        for data in modes.values():data['cpu_median']=statistics.median(data['cpu_samples'])
        code=allocate_opcodes(plan.recipes,14000,reserved=range(64))[recipe.id]
        word,binding=encode_occurrence(occurrence,code)
        row={'lua_version':version,'planning_seconds':planning,'modes':modes,
             'recipe':asdict(recipe),'occurrence':asdict(occurrence),'dynamic_vop':code,
             'kernel_source':emit_kernel(recipe),'encoding':{'ordinary_record_bytes':len(recipe.steps)*6,
                 'fusion_record_bytes':len(recipe.steps)*6,'synth_record_bytes':len(word),
                 'synth_binding_bytes':len(binding),'synth_binding_hex':binding.hex()},
             'matched_native':True}
        # Real backend plans must be refused until event-preserving lowering is
        # available. Report this limitation rather than a synthetic speedup.
        row['backend_preservation_gates']={}
        for backend in ('classic','karity','mov'):
            options={'semantic_state_threading':True,'runtime_polymorphism_rate':1,
                     'integrity_constants':True,'junk_instructions':True,'graph_execution_rate':1}
            random.seed(14000);protection=ProtectionPlanner(options).build(ir)
            gated=build_plan(ir,lua_version=version,enabled=True,protection_plan=protection)
            assert not gated.occurrences
            row['backend_preservation_gates'][backend]={'prototype_applied':0,'reason':dict(gated.rejected)}
        rows.append(row);opts.output.parent.mkdir(parents=True,exist_ok=True)
        opts.output.write_text(json.dumps(report,indent=2),encoding='utf-8')
        print('prototype-benchmark',version,{m:round(v['cpu_median'],6) for m,v in modes.items()},flush=True)

if __name__=='__main__':main()
