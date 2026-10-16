"""Bounded KES frontend and VM cost comparison; serial, correctness checked."""
from pathlib import Path
import argparse
import hashlib
import json
import platform
import random
import re
import statistics
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'tools'))
from obfuscator.kes import lower_source
from obfuscator.vm.vm_pass import VMPass
from tools.explore_vm_semantics import execute,settings


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=ROOT/'local/performance/kes.json')
    parser.add_argument('--repeats',type=int,default=2)
    parser.add_argument('--samples',type=int,default=3)
    parser.add_argument('--iterations',type=int,default=500)
    args=parser.parse_args()
    if min(args.repeats,args.samples,args.iterations)<1:parser.error('counts must be positive')
    args.output=args.output.resolve();args.output.parent.mkdir(parents=True,exist_ok=True)
    artifacts=args.output.parent/(args.output.stem+'-artifacts');artifacts.mkdir(exist_ok=True)
    report={'platform':platform.platform(),'python':platform.python_version(),'lua':'5.3',
            'vm_mode':'minimal, no output passes','iterations':args.iterations,
            'runtime':'Lua CPU includes loading and initialization, excludes process startup',
            'frontend':{},'records':[]}
    for label,source in (
        ('standard','local n=0\n'+('do local x=4; n=n+x end\n'*128)+'print(n)'),
        ('opaque','local n=0\n'+('do local s=[=[?? += continue 0b1_0 KARITY_PANIC]=]; n=n+1 end\n'*128)+'print(n)'),
        ('kes','local n=0\n'+('do local x=nil ?? 4; n+=x end\n'*128)+'print(n)')):
        samples=[]
        for _ in range(5):
            start=time.perf_counter()
            for _ in range(10):result=lower_source(source)
            samples.append((time.perf_counter()-start)/10)
        if label!='kes':assert result.source is source
        report['frontend'][label]={'source_bytes':len(source.encode()),'lowered_bytes':len(result.source.encode()),
                                   'seconds_median':statistics.median(samples),'seconds_samples':samples,
                                   'batches':5,'calls_per_batch':10}
    harness=artifacts/'cpu.lua'
    harness.write_text('local started=os.clock();dofile(arg[1]);io.stderr:write("kes-cpu:",string.format("%.9f",os.clock()-started),"\\n")',encoding='utf-8')
    n=args.iterations
    sources={
        'syntax-standard':f'local n=0;for i=1,{n} do local x=nil;if x==nil then x=4 end;n=n+x end;print(n)',
        'syntax-kes':f'local n=0;for i=1,{n} do local x=nil ?? 4;n+=x end;print(n)',
        'getter-standard':f'local n=0;for i=1,{n} do n=n+1 end;print(n)',
        'getter-intrinsic':f'local n=0;for i=1,{n} do n=n+KARITY_GET_VM_COUNT() end;print(n)',
    }
    for backend in ('classic','karity','mov'):
        for label,source in sources.items():
            expected=str(n*(4 if label.startswith('syntax') else 1))+'\n'
            samples=[]
            for repeat in range(args.repeats):
                seed=9300+repeat;random.seed(seed);options=settings(backend,'minimal',seed)
                start=time.perf_counter();output=VMPass(vm_options=options).run(source)
                build=time.perf_counter()-start
                artifact=artifacts/f'{backend}-{label}-{seed}.lua';artifact.write_text(output,encoding='utf-8',newline='\n')
                cpu=[]
                for _ in range(args.samples):
                    result=execute(artifact,'5.3',harness=harness)
                    assert result['returncode']==0 and result['stdout']==expected,(backend,label,result)
                    match=re.search(r'kes-cpu:([\d.]+)',result['stderr']);assert match,result
                    cpu.append(float(match[1]))
                samples.append({'seed':seed,'options':options,'build_seconds':build,'output_bytes':len(output.encode()),
                                'source_sha256':hashlib.sha256(source.encode()).hexdigest(),
                                'output_sha256':hashlib.sha256(artifact.read_bytes()).hexdigest(),
                                'artifact':str(artifact.relative_to(args.output.parent)),
                                'runtime_cpu_samples':cpu,'stdout_matches':True})
            record={'backend':backend,'case':label,'samples':samples,
                    'build_seconds_median':statistics.median(s['build_seconds'] for s in samples),
                    'output_bytes_median':statistics.median(s['output_bytes'] for s in samples),
                    'runtime_cpu_seconds_median':statistics.median(v for s in samples for v in s['runtime_cpu_samples'])}
            report['records'].append(record)
            args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
            print('kes-benchmark',backend,label,round(record['build_seconds_median'],3),record['output_bytes_median'],round(record['runtime_cpu_seconds_median'],6),flush=True)
    return 0


if __name__=='__main__':raise SystemExit(main())
