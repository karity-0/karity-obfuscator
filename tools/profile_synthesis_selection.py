"""Alternating historical/current selection costs through full user presets.

The benchmark alone freezes nonce entropy. Production never runs input programs
to choose an ISA. Peak working set excludes compiler grandchildren; Lua CPU time
includes loading and initialization. Ordinary timed builds omit the Profiler.
"""
from contextlib import ExitStack, contextmanager
from pathlib import Path, PureWindowsPath
from unittest.mock import patch
import argparse, json, random, statistics, subprocess, sys, time, types

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools')]
from profile_opcode_synthesis import SOURCE, FUNCTIONS, LONG_DAG
from profile_vm_runtime import execute
from compare_literal_mosaic import run

FIXTURES={'hello':"print('hi')",'dag':SOURCE,'functions':FUNCTIONS,'long':LONG_DAG,
    'strings':'local t={"hello world","한글 🍤","dependency reconstruction"};for i=1,#t do print(i,#t[i],t[i]:sub(1,4)) end'}
REF='8e3d9a0'


@contextmanager
def historical(enabled):
    if not enabled:
        yield;return
    from obfuscator.vm.synthesis import planner,lowering,costs
    old={}
    for short,current in (('planner',planner),('costs',costs)):
        name=current.__name__
        source=subprocess.run(['git','-c',f'safe.directory={ROOT.as_posix()}','show',
            REF+':'+name.replace('.','/')+'.py'],capture_output=True,check=True).stdout.decode()
        module=types.ModuleType(name);module.__package__=current.__package__;module.__file__=current.__file__
        exec(compile(source,'<baseline-'+short+'>','exec'),module.__dict__);old[short]=module
    # Restore discovery/proof too: strategy-owned sets no longer read a
    # patched planner.SCALAR alias dynamically.
    old['costs'].validate_plan=old['planner'].validate_plan
    with ExitStack() as stack:
        for module in (planner,lowering):
            for name in ('build_plan','validate_plan'):
                stack.enter_context(patch.object(module,name,getattr(old['planner'],name)))
        stack.enter_context(patch.object(costs,'choose_regions',old['costs'].choose_regions))
        yield


def compact_vm_profile(rows):
    result=[]
    for row in rows:
        if not row['phase'].startswith(('opcode_synthesis','synthesis_','serialize_blob','mov_lowering')):continue
        value={k:v for k,v in row.items() if k not in ('decisions','backend_work')}
        if 'decisions' in row:
            decisions=row['decisions']
            value.update(accepted=sum(bool(d.get('accepted_for')) for d in decisions),
                fallback_reasons=dict(__import__('collections').Counter(d['fallback'] for d in decisions if d.get('fallback'))),
                decision_examples=list(decisions[:2]))
        result.append(value)
    return result


def worker(args):
    from obfuscator.registry import resolve_config_profile,build_pipeline_from_config
    from obfuscator.pipeline import Pipeline
    from obfuscator.profiling import Profiler
    from obfuscator.toolchain import LuaToolchain
    root=json.loads((ROOT/'config.example.json').read_text(encoding='utf-8'))
    config=resolve_config_profile(root,'builtin:'+args.preset)
    config['signature']={'mode':'none'};config['vm_options']['backend']=args.backend
    entropy=random.Random(args.seed^0xA54F);random.seed(args.seed)
    pipeline=build_pipeline_from_config(config,Pipeline,show_header=False)
    profiler=Profiler() if args.diagnostic else None
    with ExitStack() as stack:
        stack.enter_context(historical(args.mode=='before'))
        stack.enter_context(patch('secrets.choice',entropy.choice))
        stack.enter_context(patch('os.urandom',lambda n:entropy.randbytes(n)))
        start,cpu=time.perf_counter(),time.process_time()
        output=pipeline.run(FIXTURES[args.fixture],profiler=profiler)
        data={'build_seconds':time.perf_counter()-start,'build_cpu_seconds':time.process_time()-cpu,
            'output_bytes':len(output.encode()),'options':config['vm_options'],'lua':LuaToolchain.from_config(config).lua(),
            'vm_profiles':[compact_vm_profile(p.last_profile) for p in pipeline._post_passes if hasattr(p,'last_lowered_ir')]}
    if profiler:data['profile']=profiler.as_dict()
    args.artifact.with_suffix('.lua').write_text(output,encoding='utf-8')
    args.artifact.with_suffix('.json').write_text(json.dumps(data,ensure_ascii=False),encoding='utf-8')


def normalize_lua_paths(report):
    # Workers keep absolute paths for execution; published reports need only the executable name.
    # Normalize every sample so --resume also cleans reports written by older workers.
    for record in report['records']:
        for samples in record['samples'].values():
            for sample in samples:
                sample['lua']=PureWindowsPath(sample['lua']).name


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker',action='store_true');parser.add_argument('--mode',choices=('before','after'))
    parser.add_argument('--preset');parser.add_argument('--backend',default='karity');parser.add_argument('--fixture')
    parser.add_argument('--artifact',type=Path);parser.add_argument('--diagnostic',action='store_true')
    parser.add_argument('--profiles',nargs='+',default=['fast','balanced','strong','maximum'])
    parser.add_argument('--fixtures',nargs='+',choices=tuple(FIXTURES),default=['hello','dag','functions','strings','long'])
    parser.add_argument('--backends',nargs='+',choices=('karity','classic','mov'),default=['karity'])
    parser.add_argument('--seed',type=int,default=1400);parser.add_argument('--repeats',type=int,default=3)
    parser.add_argument('--output',type=Path,default=ROOT/'local/performance/synthesis-pipeline.json')
    parser.add_argument('--resume',action='store_true')
    args=parser.parse_args()
    if args.worker:return worker(args)
    if args.repeats<1:parser.error('repeats must be positive')
    work=ROOT/'temp-synthesis-selection';work.mkdir(exist_ok=True)
    report={'baseline':REF,'python':sys.version,'seed':args.seed,'repeats':args.repeats,
        'shared_runtime':'validated register caches on both sides; baseline isolates selector and vocabulary',
        'scope':'full built-in pipeline; ordinary timings, separate diagnostic build; alternating same seed/nonce pairs',
        'records':[]}
    if args.resume:
        previous=json.loads(args.output.read_text(encoding='utf-8'))
        assert all(previous[k]==report[k] for k in ('baseline','python','seed','repeats','scope','shared_runtime'))
        report=previous
    done={(r['preset'],r['fixture'],r['backend']) for r in report['records']}
    for backend in args.backends:
        for preset in args.profiles:
            for fixture in args.fixtures:
                if (preset,fixture,backend) in done:continue
                expected=execute(FIXTURES[fixture],'5.3')[0];samples={'before':[],'after':[]}
                for repeat in range(args.repeats):
                    for mode in (('before','after') if repeat%2==0 else ('after','before')):
                        artifact=work/f'{backend}-{preset}-{fixture}-{mode}-{repeat}'
                        cmd=[sys.executable,__file__,'--worker','--mode',mode,'--backend',backend,
                            '--preset',preset,'--fixture',fixture,'--seed',str(args.seed),'--artifact',str(artifact)]
                        memory=run(cmd,ROOT,artifact.with_suffix('.log'),timeout=600)
                        row=json.loads(artifact.with_suffix('.json').read_text(encoding='utf-8'))
                        output=artifact.with_suffix('.lua').read_text(encoding='utf-8')
                        actual,cpu=execute(output,'5.3');assert actual==expected,(backend,preset,fixture,mode,actual,expected)
                        runtime=run([row['lua'],str(artifact.with_suffix('.lua'))],ROOT,
                            artifact.with_suffix('.run.log'),timeout=120)
                        assert artifact.with_suffix('.run.log').read_bytes().replace(b'\r\n',b'\n').rstrip(b'\n')==expected
                        row.update(execution_seconds=cpu,build_memory_bytes=memory['peak_working_set_bytes'],
                            runtime_wall_seconds=runtime['wall_seconds'],runtime_memory_bytes=runtime['peak_working_set_bytes'],
                            stdout_matches=True)
                        samples[mode].append(row)
                artifact=work/f'{backend}-{preset}-{fixture}-diagnostic'
                subprocess.run([sys.executable,__file__,'--worker','--mode','after','--backend',backend,
                    '--preset',preset,'--fixture',fixture,'--seed',str(args.seed),'--artifact',str(artifact),
                    '--diagnostic'],cwd=ROOT,stdout=subprocess.DEVNULL,check=True,timeout=600)
                diagnostic=json.loads(artifact.with_suffix('.json').read_text(encoding='utf-8'))['profile']
                medians={}
                for mode,data in samples.items():
                    medians[mode]={}
                    for key in ('build_seconds','build_cpu_seconds','execution_seconds','output_bytes',
                                'build_memory_bytes','runtime_wall_seconds','runtime_memory_bytes'):
                        values=[s[key] for s in data if s[key] is not None]
                        medians[mode][key]=statistics.median(values) if values else None
                row={'backend':backend,'preset':preset,'fixture':fixture,'samples':samples,'diagnostic':diagnostic,'median':medians}
                report['records'].append(row);args.output.parent.mkdir(parents=True,exist_ok=True)
                normalize_lua_paths(report)
                args.output.write_text(json.dumps(report,ensure_ascii=False,separators=(',',':')),encoding='utf-8')
                print('synthesis-pipeline',backend,preset,fixture,row['median'],flush=True)
    lines=['# Synthesis selection through full user presets','',
        'Python 3.15 / native Lua 5.3, seed 1400. Three alternating historical/current pairs, with identical nonce entropy. '
        'Both sides use the corrected epoch/generation-validating register cache; the baseline isolates the historical selector and vocabulary. '
        'Source passes, VM output passes and Maximum packing remain enabled. Execution includes loading and initialization. '
        'Every timed output matches native Lua. Diagnostics are separate from ordinary timed builds. '
        'Native Lua wall time also includes source parsing/process startup; runtime peak memory is sampled separately. '
        'Peak builder working set excludes compiler grandchildren. [Raw samples](synthesis-pipeline.json).','',
        '| Backend / preset / input | Build wall s | Execution CPU s | Output bytes | Builder MiB | Lua wall s | Lua MiB | Regions / handlers |',
        '|---|---|---|---|---|---|---|---|']
    for r in report['records']:
        a=r['median']['before'];b=r['median']['after']
        memory=lambda value:f'{value/2**20:.1f}' if value is not None else '—'
        counts={}
        for mode in ('before','after'):
            phases=[p for vm in r['samples'][mode][0]['vm_profiles'] for p in vm if p['phase']=='synthesis_physical']
            counts[mode]=f"{sum(p['regions'] for p in phases)} / {sum(p['handlers'] for p in phases)}"
        lines.append(f"| {r['backend']} / {r['preset']} / {r['fixture']} | {a['build_seconds']:.3f} → {b['build_seconds']:.3f} | "
            f"{a['execution_seconds']:.3f} → {b['execution_seconds']:.3f} | {int(a['output_bytes']):,} → {int(b['output_bytes']):,} | "
            f"{memory(a['build_memory_bytes'])} → {memory(b['build_memory_bytes'])} | "
            f"{a['runtime_wall_seconds']:.3f} → {b['runtime_wall_seconds']:.3f} | "
            f"{memory(a['runtime_memory_bytes'])} → {memory(b['runtime_memory_bytes'])} | "
            f"{counts['before']} → {counts['after']} |")
    lines+=['','## Separate diagnostic stage costs','',
        'These are separately profiled after builds, not the ordinary timing samples above. '
        'VM generation, output processing and synthesis are distinct boundaries; nested parent times are not added together.','',
        '| Preset / input | Source CFF s | VM code generation s | VM output transforms s | Synthesis discovery + selection s |',
        '|---|---|---|---|---|']
    for r in report['records']:
        passes=r['diagnostic']['passes']
        cff=sum(p['elapsed'] for p in passes if p['name']=='FunctionObfuscationPass')
        details=[d for p in passes if p['name']=='VMPass' for d in p.get('details',())]
        phase=lambda name:sum(d.get('elapsed',0) for d in details if d['phase']==name)
        lines.append(f"| {r['preset']} / {r['fixture']} | {cff:.3f} | {phase('build_vm_code'):.3f} | "
            f"{phase('obfuscate_vm_output'):.3f} | {phase('opcode_synthesis')+phase('synthesis_cost_selection'):.3f} |")
    lines+=['','No source pass, VM protection option, VM output signature pass or packing stage was removed. '
        'More accepted bit DAGs can increase generation cost and output size under Protection. '
        'Unchanged output/region counts do not establish a causal speedup from timing noise. '
        'Compiler costs and SCC frequencies remain estimates; all runtime branches are not calibrated to nanoseconds.','']
    args.output.with_suffix('.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')


if __name__=='__main__':main()
