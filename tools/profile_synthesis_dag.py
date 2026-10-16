"""Isolated paired VM-only measurements for ordered DAGs and raw temporaries."""
from pathlib import Path
import argparse
import importlib
import json
import statistics
import subprocess
import sys
import types

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools')]
FIXTURES={
    'scalar': 'local s=0;for i=1,2000 do local a=i*1.5;local b=a*2;local c=b*3;s=s+c end;print(s)',
    'capture': 'local s=0;local function get()return s end;for i=1,200 do local a=i*3;local b=a+7;local c=b*5;s=s+c end;print(get())',
    'table': 'local t={4,7,9};local s=0;for i=1,200 do local a=t[1];local b=a*3;local c=b+7;s=s+c end;print(s)',
    'vararg': 'local function f(...)local s=0;for i=1,200 do local a=i*3;local b=a+7;local c=b*5;s=s+c end;return s,... end;print(f(nil,9,nil))',
}


def historical(ref):
    # Load only the historical synthesis subsystem in this short-lived worker.
    # The runtime, options, cache fix and all other code stay identical. No
    # working-tree swaps, import patches across builds or entropy differences.
    package=importlib.import_module('obfuscator.vm.synthesis')
    for name in ('model','planner','lowering','emission','kernels','costs'):
        path='obfuscator/vm/synthesis/'+name+'.py'
        source=subprocess.run(['git','-c',f'safe.directory={ROOT.as_posix()}',
            'show',f'{ref}:{path}'],capture_output=True,check=True,cwd=ROOT).stdout.decode('utf-8')
        full='obfuscator.vm.synthesis.'+name
        module=types.ModuleType(full);module.__package__=package.__name__;module.__file__=str(ROOT/path)
        sys.modules[full]=module;setattr(package,name,module)
        exec(compile(source,module.__file__,'exec'),module.__dict__)


def worker(args):
    if args.mode=='before':historical(args.before)
    from profile_opcode_synthesis import build,BASE,PROTECTED
    from profile_vm_runtime import execute
    from obfuscator.vm.backends.runtime_layout import iter_functions
    source=FIXTURES[args.fixture]
    options={**BASE,**(PROTECTED if args.protected else {}),'opcode_synthesis':True,
        'synthesis_policy':'protection','synthesis_max_code_growth':64,
        'block_variant_rate':0,'physical_block_permutation_rate':0}
    output,data,p=build(source,args.backend,args.lua,options,seed=args.seed)
    actual,seconds=execute(output,args.lua)
    assert actual==execute(source,args.lua)[0]
    counted,_,_=build(source,args.backend,args.lua,options,seed=args.seed,instrument=True)
    text,_=execute(counted,args.lua)
    counters=[int(x) for x in text.split(b'SYN-COUNTERS\t')[1].splitlines()[0].split(b'\t')]
    rows=[e for f in iter_functions(p.last_lowered_ir.backend_data['layout'].functions) for e in f.synthesis]
    stats=p.last_lowered_ir.backend_data.get('runtime_emission',{})
    return {key:data[key] for key in ('build_seconds','build_cpu_seconds','output_bytes','runtime_bytes','blob_bytes','regions','handlers','rejected')}|{
        'execution_seconds':seconds,'counters':counters,'forms':[e.execution_form for e in rows],
        'guarded_local_handlers':sum(r.get('guarded_register_local_handlers',0) for r in p.last_lowered_ir.backend_data.get('synthesis_emission',{}).values()),
        'graph_counts':{key:stats.get(key) for key in ('arithmetic_kinds','arithmetic_dags_after',
            'arithmetic_dags_per_kind','native_arithmetic_variants_per_kind','occurrence_families',
            'audited_helpers_before','audited_helpers_after')}}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker',action='store_true')
    parser.add_argument('--before',default='2815766')
    parser.add_argument('--mode',choices=('before','after'),default='after')
    parser.add_argument('--backend',default='karity')
    parser.add_argument('--lua',default='5.3')
    parser.add_argument('--fixture',default='scalar')
    parser.add_argument('--protected',action='store_true')
    parser.add_argument('--seed',type=int,default=1400)
    parser.add_argument('--repeats',type=int,default=3)
    parser.add_argument('--concurrent-ci',action='store_true',help='Record concurrent local CI load in timing provenance.')
    parser.add_argument('--output',type=Path,default=ROOT/'local/performance/synthesis-dag.json')
    args=parser.parse_args()
    if args.worker:
        print(json.dumps(worker(args),separators=(',',':')));return
    report={'before':args.before,'scope':'historical synthesis subsystem; same current runtime; VM only',
        'execution_timer':'Lua os.clock() inside chunk; parse/process startup excluded',
        'python':sys.version,'seed':args.seed,'repeats':args.repeats,'concurrent_ci':args.concurrent_ci,'records':[]}
    for fixture in FIXTURES:
        for protected in (False,True):
            samples={'before':[],'after':[]}
            for repeat in range(args.repeats):
                for mode in (('before','after') if repeat%2==0 else ('after','before')):
                    command=[sys.executable,__file__,'--worker','--before',args.before,'--mode',mode,
                        '--backend',args.backend,'--lua',args.lua,'--fixture',fixture,'--seed',str(args.seed)]
                    if protected:command.append('--protected')
                    result=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,encoding='utf-8')
                    if result.returncode:raise RuntimeError(result.stdout+result.stderr)
                    samples[mode].append(json.loads(result.stdout))
            medians={mode:{key:statistics.median(s[key] for s in rows)
                for key in ('build_seconds','build_cpu_seconds','output_bytes','runtime_bytes','blob_bytes','execution_seconds')}
                for mode,rows in samples.items()}
            report['records'].append({'backend':args.backend,'lua':args.lua,'fixture':fixture,'protected':protected,
                'samples':samples,'median':medians})
            x,y=samples['before'][0]['graph_counts'],samples['after'][0]['graph_counts']
            for key in ('arithmetic_dags_per_kind','native_arithmetic_variants_per_kind','occurrence_families'):
                assert x[key]==y[key],('protection variant count changed',fixture,protected,key,x,y)
            args.output.parent.mkdir(parents=True,exist_ok=True)
            args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
            print(fixture,protected,medians,flush=True)
    write_summary(report,args.output)


def write_summary(report,path):
    first=report['records'][0]
    lines=['# Ordered DAG and guarded-local measurements','',
        f"Python {report['python'].split()[0]}, Lua {first['lua']}, {first['backend']}; seed {report['seed']}, "
        f"{report['repeats']} alternating samples. Historical synthesis: `{report['before']}`. "
        'All other runtime code/options are identical. VM only; generous Protection budgets expose the feature, '
        'so these are not full GUI preset timings. Build wall includes synthesis; execution uses Lua os.clock() '
        'inside the chunk, including runtime loading/initialization but excluding parsing/process startup. '
        'Counter builds are separate and all results match native Lua. '
        + ('Concurrent local CI was running; timings are indicative, not regression thresholds.' if report['concurrent_ci'] else ''),'',
        '| Input / protection | Build wall s | Lua os.clock s | Output bytes | Regions | Reads, median | Writes, median |',
        '|---|---|---|---|---|---|---|']
    for r in report['records']:
        a,b=r['median']['before'],r['median']['after'];x,y=r['samples']['before'][0],r['samples']['after'][0]
        counts={side:[statistics.median(s['counters'][n] for s in samples) for n in range(5)]
                for side,samples in r['samples'].items()}
        lines.append(f"| {r['fixture']} / {r['protected']} | {a['build_seconds']:.3f} → {b['build_seconds']:.3f} | "
            f"{a['execution_seconds']:.3f} → {b['execution_seconds']:.3f} | {int(a['output_bytes']):,} → {int(b['output_bytes']):,} | "
            f"{x['regions']} → {y['regions']} | {counts['before'][1]:,} → {counts['after'][1]:,} | {counts['before'][2]:,} → {counts['after'][2]:,} |")
    lines+=['','Mandatory Karity encoded writes and graph/pending/route/state events are retained. '
        'Raw local values bypass reads only when epoch, map generation and pending-state checks succeed. '
        'The cost selector can retain the materialized kernel instead; lower dispatch counts do not guarantee '
        'lower runtime. Additional ordered recipes expand protection coverage and can increase source size. '
        'Counter totals include state-dependent graph/junk activity. Per-operation graph/native variant '
        'counts and occurrence families are checked unchanged and retained in the raw samples. '
        'Short-input timings are noisy. Raw samples include blob/runtime sizes, forms and rejection reasons.','']
    path.with_suffix('.md').write_text('\n'.join(lines),encoding='utf-8')


if __name__=='__main__':main()
