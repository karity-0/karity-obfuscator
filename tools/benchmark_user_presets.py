"""Serial preset benchmarks; ordinary builds and diagnostics are separate.

Windows memory is builder/Lua child peak working set, excluding compiler
grandchildren. Runtime wall time includes startup and process creation.
Every output is checked against the original fixture; report saves are incremental.
"""
from pathlib import Path
import argparse
import hashlib
import json
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT/'tools'))
FIXTURES = {
    'small': 'local x=7; print("hello",x*6)',
    'strings': 'local t={"hello world","한글 🍤","dependency reconstruction",string.rep("long text",16)}; for i=1,#t do print(i,#t[i],t[i]:sub(1,4)) end',
    'loops': 'local x=0; for i=1,40 do for j=1,4 do if i%2==0 then x=x+i*j else x=x-j end end end; print(x)',
    'closures': 'local fs={}; for i=1,4 do local n=i; fs[i]=function(...) n=n+1; return n,... end end; for i=1,4 do local a,b,c=fs[i](nil,9); print(a,b,c) end; local co=coroutine.create(function() coroutine.yield("yield"); return "done" end); print(coroutine.resume(co)); print(coroutine.resume(co)); print(pcall(function() error("expected",0) end))',
    'release': (ROOT/'test/fixtures/backend_escape_boundaries.lua').read_text(encoding='utf-8'),
    'records': (ROOT/'test/fixtures/workload_records.lua').read_text(encoding='utf-8'),
    'callbacks': (ROOT/'test/fixtures/workload_callbacks.lua').read_text(encoding='utf-8'),
}


def worker(args):
    from obfuscator.registry import resolve_config_profile, build_pipeline_from_config
    from obfuscator.pipeline import Pipeline
    from obfuscator.profiling import Profiler
    from obfuscator.toolchain import LuaToolchain
    import random
    root=json.loads((ROOT/'config.example.json').read_text(encoding='utf-8'))
    config=resolve_config_profile(root,args.worker_profile)
    config['signature']={'mode':'none'}
    config['vm_options']['backend']=args.worker_backend
    if args.ablation=='notation':
        config['literal_mosaic']['output_cost'].update(hot_operations=0,cold_operations=0,hot_meme_rate=0,cold_meme_rate=0)
    elif args.ablation=='no-unroll':
        config['function_obf_options']['loop_unroll']=False
    elif args.ablation=='no-pack':
        config['passes']=[p for p in config['passes'] if p!='pack']
    elif args.ablation=='full-output':
        config['literal_mosaic'].pop('output_cost',None)
    elif args.ablation=='no-cff-budget':
        config['function_obf_options'].pop('max_pass_expansion_ratio',None)
    random.seed(args.seed)
    pipeline=build_pipeline_from_config(config,Pipeline,show_header=False)
    profiler=Profiler() if args.diagnostic else None
    start,cpu=time.perf_counter(),time.process_time()
    output=pipeline.run(FIXTURES[args.worker_fixture],profiler=profiler)
    row={'build_seconds':time.perf_counter()-start,'build_cpu_seconds':time.process_time()-cpu,
         'output_bytes':len(output.encode()),'config':config,'lua':LuaToolchain.from_config(config).lua(),
         'source_sha256':hashlib.sha256(FIXTURES[args.worker_fixture].encode()).hexdigest(),
         'output_sha256':hashlib.sha256(output.encode()).hexdigest()}
    args.artifact.with_suffix('.lua').write_text(output,encoding='utf-8',newline='\n')
    if profiler: row['profile']=profiler.as_dict()
    args.artifact.with_suffix('.json').write_text(json.dumps(row,ensure_ascii=False),encoding='utf-8')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,default=ROOT/'local/performance/user-presets.json')
    p.add_argument('--profiles',nargs='+',choices=['fast','balanced','strong','maximum'],default=['fast','balanced','strong','maximum'])
    p.add_argument('--backends',nargs='+',choices=['karity','classic','mov'],default=['karity','classic','mov'])
    p.add_argument('--fixtures',nargs='+',choices=list(FIXTURES),default=list(FIXTURES))
    p.add_argument('--repeats',type=int,default=3)
    p.add_argument('--seed',type=int,default=9300)
    p.add_argument('--ablation',choices=['none','notation','no-unroll','no-pack','full-output','no-cff-budget'],default='none')
    p.add_argument('--diagnostic',action='store_true')
    p.add_argument('--worker-profile');p.add_argument('--worker-backend');p.add_argument('--worker-fixture')
    p.add_argument('--artifact',type=Path)
    args=p.parse_args()
    args.output=args.output.resolve()
    if args.worker_profile: return worker(args)
    if args.repeats < 1: p.error('--repeats must be positive')
    from compare_literal_mosaic import run
    artifact_parent=args.output.parent if args.output.is_relative_to(ROOT) else ROOT/'local/performance'
    work=artifact_parent/(args.output.stem+'-artifacts')
    work.mkdir(parents=True,exist_ok=True);args.output.parent.mkdir(parents=True,exist_ok=True)
    report={'python':sys.version,'seed':args.seed,'diagnostic':args.diagnostic,'ablation':args.ablation,
            'memory':'Windows child peak working set; excludes compiler grandchildren',
            'runtime':'external Lua wall time includes startup and process creation','records':[]}
    for fixture in args.fixtures:
        original=work/(fixture+'-original.lua');original.write_text(FIXTURES[fixture],encoding='utf-8',newline='\n')
        for backend in args.backends:
            for profile in args.profiles:
                samples=[]
                for repeat in range(args.repeats):
                    tag=f'{args.output.stem.replace(".","_")}-{fixture}-{backend}-{profile}-{args.ablation}-{int(args.diagnostic)}-{repeat}'
                    artifact=work/tag
                    cmd=[sys.executable,__file__,'--worker-profile',profile,'--worker-backend',backend,
                         '--worker-fixture',fixture,'--seed',str(args.seed+repeat),'--artifact',str(artifact),'--ablation',args.ablation]
                    if args.diagnostic: cmd.append('--diagnostic')
                    measured=run(cmd,ROOT,artifact.with_suffix('.build.log'))
                    row=json.loads(artifact.with_suffix('.json').read_text(encoding='utf-8'))
                    row['artifact']=artifact.with_suffix('.lua').relative_to(ROOT).as_posix()
                    expected=subprocess.run([row['lua'],str(original)],capture_output=True,check=True,timeout=120).stdout
                    runtime=run([row['lua'],str(artifact.with_suffix('.lua'))],ROOT,artifact.with_suffix('.run.log'),timeout=120)
                    actual=artifact.with_suffix('.run.log').read_bytes().replace(b'\r\n',b'\n')
                    assert actual==expected.replace(b'\r\n',b'\n'),(tag,actual,expected)
                    samples.append({**row,'build_memory_bytes':measured['peak_working_set_bytes'],
                                    'runtime_seconds':runtime['wall_seconds'],'runtime_memory_bytes':runtime['peak_working_set_bytes'],'stdout_matches':True})
                summary={'fixture':fixture,'backend':backend,'preset':profile,'samples':samples}
                for metric in ('build_seconds','output_bytes','runtime_seconds','build_memory_bytes','runtime_memory_bytes'):
                    values=[s[metric] for s in samples if s[metric] is not None]
                    summary[metric+'_median']=statistics.median(values) if values else None
                report['records'].append(summary)
                args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
                print('preset-benchmark',fixture,backend,profile,round(summary['build_seconds_median'],3),
                      summary['output_bytes_median'],round(summary['runtime_seconds_median'],3),flush=True)


if __name__=='__main__': main()
