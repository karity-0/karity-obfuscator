"""Serial before/after VM lifetime costs, with unchanged protection settings.

Each compiled output gets repeated executions. Build measurements are single
samples. Run without other builds; these VM-only cases are not GUI preset costs.
"""
from pathlib import Path
import argparse
import hashlib
import json
import random
import statistics
import subprocess
import sys
import time
from itertools import product

ROOT = Path(__file__).resolve().parents[1]
SOURCES = {
    'arithmetic': '''local sum=0
for i=1,4000 do local x=(i*17+3)%997;sum=(sum+x*x-i)%1000003 end
print('arithmetic',sum)''',
    'calls': '''local value=7
local function bump(n) value=(value+n)%997;return value,nil,false end
local function relay(n) local x,b,c=bump(n);assert(b==nil and c==false);return x end
local sum=0
for i=1,500 do sum=sum+relay(i) end
print('calls',sum,value)''',
}


def source_for(fixture, version):
    source=SOURCES[fixture]
    if version=='5.1':
        source=source.replace('for i=1,4000', 'for i=1,200').replace('for i=1,500', 'for i=1,100')
    return source


def lua_command(version, executable, script, argument=None):
    arguments=[str(script)] + ([str(argument)] if argument else [])
    if version=='5.3':
        return [executable,*arguments]
    # The same Lupa ABI used by the Lua 5.1 compiler; a fresh process per sample.
    code=('from pathlib import Path;from lupa.lua51 import LuaRuntime;import sys;'
          'r=LuaRuntime(encoding=None);'
          'r.globals().arg=r.table_from({1:sys.argv[2].encode()}) if len(sys.argv)>2 else r.table();'
          'r.execute(Path(sys.argv[1]).read_bytes())')
    return [sys.executable,'-c',code,*arguments]


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--before', type=Path)
    p.add_argument('--output', type=Path, default=ROOT/'local/performance/vm-lifetimes.json')
    p.add_argument('--samples', type=int, default=5)
    p.add_argument('--versions', nargs='+', choices=['5.1','5.3'], default=['5.1','5.3'])
    p.add_argument('--version', choices=['5.1','5.3'], default='5.3')
    p.add_argument('--worker-root', type=Path)
    p.add_argument('--fixture', choices=list(SOURCES))
    p.add_argument('--backend', choices=['classic','karity','mov'])
    p.add_argument('--mode', choices=['minimal','protected'])
    p.add_argument('--artifact', type=Path)
    args=p.parse_args()
    args.output=args.output.resolve()
    if args.worker_root:
        sys.path[:0]=[str(args.worker_root),str(args.worker_root/'test'),str(ROOT/'tools')]
        from obfuscator.vm import VMPass
        from obfuscator.vm.targets.profile import TargetProfile
        from explore_vm_semantics import settings
        from lua_runtime import lua_executable
        random.seed(124)
        options=settings(args.backend,args.mode,124)
        source=source_for(args.fixture,args.version)
        start=time.perf_counter()
        output=VMPass(target=TargetProfile(args.version,args.backend),
                      vm_options=options,vm_output_passes=[]).run(source)
        row={'build_seconds':time.perf_counter()-start,'output_bytes':len(output.encode()),
             'lua':lua_executable() if args.version=='5.3' else 'lupa.lua51','options':options,
             'source_sha256':hashlib.sha256(source.encode()).hexdigest(),
             'output_sha256':hashlib.sha256(output.encode()).hexdigest()}
        args.artifact.with_suffix('.lua').write_text(output,encoding='utf-8',newline='\n')
        args.artifact.with_suffix('.json').write_text(json.dumps(row),encoding='utf-8')
        return
    if not args.before or args.samples<1:
        p.error('--before and positive --samples are required')
    sys.path.insert(0,str(ROOT/'tools'))
    from compare_literal_mosaic import run
    artifact_parent=args.output.parent if args.output.is_relative_to(ROOT) else ROOT/'local/performance'
    work=artifact_parent/'vm-lifetime-artifacts';work.mkdir(parents=True,exist_ok=True)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    harness=work/'timed.lua'
    harness.write_text("local t=os.clock();assert(loadfile(arg[1]))();print('__VM_AUDIT_CPU__',os.clock()-t)",encoding='utf-8')
    report={'python':sys.version,'seed':124,'records':[],
            'scope':'VM only; identical options; no source/output passes or packing',
            'iterations':'5.1: 200 arithmetic / 100 calls; 5.3: 4000 arithmetic / 500 calls',
            'timing':'serial; one build per condition; repeated executions include load and initialization',
            'memory':'child peak working set sampled every 50 ms; excludes grandchildren'}
    for version,fixture,backend,mode in product(args.versions,SOURCES,('classic','karity','mov'),('minimal','protected')):
        source=source_for(fixture,version)
        original=work/(version+'-'+fixture+'-original.lua')
        original.write_text(source,encoding='utf-8',newline='\n')
        rows=[]
        for revision,checkout in (('before',args.before.resolve()),('after',ROOT)):
            tag=f'{version}-{fixture}-{backend}-{mode}-{revision}'
            artifact=work/tag
            build=run([sys.executable,__file__,'--worker-root',str(checkout),
                       '--version',version,'--fixture',fixture,'--backend',backend,'--mode',mode,
                       '--artifact',str(artifact)],checkout,artifact.with_suffix('.build.log'),timeout=300)
            row=json.loads(artifact.with_suffix('.json').read_text(encoding='utf-8'))
            expected=subprocess.run(lua_command(version,row['lua'],original),capture_output=True,check=True,timeout=120).stdout.decode().splitlines()
            row.update(version=version,fixture=fixture,backend=backend,mode=mode,revision=revision,
                       build_memory_bytes=build['peak_working_set_bytes'],samples=[])
            rows.append((row,artifact))
        assert rows[0][0]['options']==rows[1][0]['options']
        assert rows[0][0]['source_sha256']==rows[1][0]['source_sha256']
        for sample in range(args.samples):
            for row,artifact in rows[::1 if sample%2==0 else -1]:
                log=artifact.with_suffix(f'.run-{sample}.log')
                measured=run(lua_command(version,row['lua'],harness,artifact.with_suffix('.lua')),ROOT,log,timeout=120)
                lines=log.read_text(encoding='utf-8').splitlines()
                assert lines[:-1]==expected,(artifact,lines,expected)
                assert lines[-1].startswith('__VM_AUDIT_CPU__\t'),lines[-1]
                row['samples'].append({'cpu_seconds':float(lines[-1].split('\t')[1]),
                                       'wall_seconds':measured['wall_seconds'],
                                       'memory_bytes':measured['peak_working_set_bytes']})
        for row,_ in rows:
            row['cpu_seconds_median']=statistics.median(s['cpu_seconds'] for s in row['samples'])
            row['wall_seconds_median']=statistics.median(s['wall_seconds'] for s in row['samples'])
            report['records'].append(row)
            print('lifetime-benchmark',version,fixture,backend,mode,row['revision'],row['cpu_seconds_median'],flush=True)
        args.output.write_text(json.dumps(report,indent=2),encoding='utf-8')


if __name__=='__main__':
    main()
