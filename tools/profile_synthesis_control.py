"""Paired VM-only terminal synthesis measurements against a historical revision."""
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
    'call': '''local function f(x)return x+1,nil,false,nil end
local function run(f,n)local s=0;for i=1,n do
local a=i*3;local b=a+7;local c=b*5;local p,q,r,t=f(c);s=s+p end;return s end
print(run(f,200))''',
    'branch': '''local function f(x)local a=x*3;local b=a+7
if b<200 then return 1 else return 2 end end
local s=0;for i=1,200 do s=s+f(i)end;print(s)''',
}


def historical(ref):
    package=importlib.import_module('obfuscator.vm.synthesis')
    for name in ('strategies','model','planner','lowering','emission','kernels','costs'):
        path='obfuscator/vm/synthesis/'+name+'.py'
        source=subprocess.run(['git','-c',f'safe.directory={ROOT.as_posix()}',
            'show',f'{ref}:{path}'],capture_output=True,check=True,cwd=ROOT).stdout.decode('utf-8')
        full=package.__name__+'.'+name;module=types.ModuleType(full)
        module.__package__=package.__name__;module.__file__=str(ROOT/path)
        sys.modules[full]=module;setattr(package,name,module)
        exec(compile(source,module.__file__,'exec'),module.__dict__)


def worker(args):
    if args.mode=='before':historical(args.before)
    from profile_opcode_synthesis import build,BASE,PROTECTED
    from profile_vm_runtime import execute
    source=FIXTURES[args.fixture]
    settings={**BASE,**(PROTECTED if args.protected else {}),'opcode_synthesis':True,
        'synthesis_policy':'protection','synthesis_max_steps':10,
        'synthesis_max_code_growth':64,'block_variant_rate':0,'physical_block_permutation_rate':0}
    output,data,p=build(source,'karity','5.3',settings,seed=args.seed)
    actual,seconds=execute(output,'5.3');assert actual==execute(source,'5.3')[0]
    plan=p.last_lowered_ir.backend_data['synthesis_plan'];recipes={r.id:r for r in plan.recipes}
    runtime=p.last_lowered_ir.backend_data['runtime_emission']
    return {k:data[k] for k in ('build_seconds','build_cpu_seconds','output_bytes','runtime_bytes','blob_bytes','regions','handlers')}|{
        'execution_seconds':seconds,
        'terminal_regions':sum(recipes[o.recipe].steps[-1].operation in ('CALL','TEST','EQUAL','LESS_THAN','LESS_EQUAL') for o in plan.occurrences),
        'graph_counts':{k:runtime.get(k) for k in ('arithmetic_kinds','arithmetic_dags_per_kind',
            'native_arithmetic_variants_per_kind','occurrence_families')}}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker',action='store_true')
    parser.add_argument('--before',default='b6aceea')
    parser.add_argument('--mode',choices=('before','after'),default='after')
    parser.add_argument('--fixture',choices=FIXTURES,default='call')
    parser.add_argument('--protected',action='store_true')
    parser.add_argument('--seed',type=int,default=1400)
    parser.add_argument('--repeats',type=int,default=3)
    parser.add_argument('--output',type=Path,default=ROOT/'docs/performance/synthesis-control.json')
    args=parser.parse_args()
    if args.worker:print(json.dumps(worker(args)));return
    report={'before':args.before,'python':sys.version,'seed':args.seed,'repeats':args.repeats,
        'scope':'Karity Lua 5.3, VM only, protection policy with ample budgets, no block clones/permutation',
        'timing':'Lua os.clock inside chunk, including initialization; parsing/process startup excluded; concurrent local regressions',
        'records':[]}
    for fixture in FIXTURES:
        for protected in (False,True):
            samples={'before':[],'after':[]}
            for repeat in range(args.repeats):
                for mode in (('before','after') if repeat%2==0 else ('after','before')):
                    command=[sys.executable,__file__,'--worker','--before',args.before,'--mode',mode,
                        '--fixture',fixture,'--seed',str(args.seed)]
                    if protected:command.append('--protected')
                    result=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,check=True,timeout=180)
                    samples[mode].append(json.loads(result.stdout))
            if protected:
                assert samples['before'][0]['graph_counts']==samples['after'][0]['graph_counts']
            median={side:{k:statistics.median(s[k] for s in values) for k in values[0] if k!='graph_counts'}
                    for side,values in samples.items()}
            report['records'].append({'fixture':fixture,'protected':protected,'samples':samples,'median':median})
            args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
            print(f'{fixture} protected={protected} measured',flush=True)
    lines=['# Terminal opcode synthesis measurements','',
        f"Baseline `{args.before}`; Python {sys.version.split()[0]}, Karity / Lua 5.3, seed {args.seed}, "
        f'{args.repeats} alternating samples. VM only, ample Protection budgets. '
        'Block clones and physical permutation are disabled to isolate these recipes; '
        'other protected settings retain graphs, alias/state, integrity, mutation and pending work. '
        'These are not full GUI preset timings. Concurrent local regressions make timings indicative. '
        'Lua os.clock includes initialization, excluding parsing and process launch. All outputs match native Lua.','',
        '| Input / protection | Build s | Execute s | Output bytes | Terminal regions |',
        '|---|---|---|---|---|']
    for r in report['records']:
        a,b=r['median']['before'],r['median']['after']
        lines.append(f"| {r['fixture']} / {r['protected']} | {a['build_seconds']:.3f} → {b['build_seconds']:.3f} | "
            f"{a['execution_seconds']:.3f} → {b['execution_seconds']:.3f} | {int(a['output_bytes']):,} → {int(b['output_bytes']):,} | "
            f"{int(a['terminal_regions'])} → {int(b['terminal_regions'])} |")
    lines+=['','Terminal synthesis expands the opcode vocabulary; it does not guarantee a smaller or faster build. '
        'Original encoded stores and logical events remain. Terminal mixed recipes retain materialization '
        "and do not borrow the scalar strategy's raw temporaries, which can add work relative to a scalar-only region. "
        'Per-kind arithmetic DAG, native variant and '
        'occurrence-family counts are asserted equal for protected pairs. Raw records include runtime/blob sizes. '
        'If grouping a terminal would remove existing selected block clones, the generator recovers eligible '
        'prefix DAGs using shared discovery and records `terminal_block_variants`; recovered candidates '
        'still pass the ordinary budgets.','']
    args.output.with_suffix('.md').write_text('\n'.join(lines),encoding='utf-8')


if __name__=='__main__':main()
