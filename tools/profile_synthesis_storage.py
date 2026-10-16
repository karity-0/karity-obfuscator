"""Compare exact historical/current synthesis with the same host, hash seed and settings."""
from contextlib import ExitStack,contextmanager
import importlib
import json
from pathlib import Path
import statistics
import subprocess
import types
from collections import Counter
from unittest.mock import patch
from profile_opcode_synthesis import ROOT,BASE,SOURCE,LONG_DAG,build
from profile_vm_runtime import execute
from obfuscator.presets import user_preset

LARGE='local s=0;for i=1,3 do local a;'+('a=i*3;a=a+7;a=a*5;s=s+a;'*256)+'end;print(s)'
OPTIONS={**BASE,'opcode_synthesis':True,'synthesis_policy':'efficiency','synthesis_max_steps':4,
    'synthesis_max_recipes':64,'synthesis_max_occurrences':1024,'synthesis_max_code_growth':64}
REF='ce20b16'


def compact_profile(data):
    """Keep measurements and decision totals, avoiding repeated large dumps."""
    for phase in data['profile']:
        if 'decisions' not in phase:continue
        decisions=phase.pop('decisions')
        phase['decision_count']=len(decisions)
        phase['decision_outcomes']=dict(Counter(d.get('fallback') or d.get('accepted_for','unknown') for d in decisions))
        phase['execution_forms']=dict(Counter(d.get('form','fallback') for d in decisions))
        examples={}
        for d in decisions:
            key=(d.get('form'),d.get('domain'),d.get('fallback'),d.get('accepted_for'),len(d['sources']),bool(d.get('incremental_bytes')))
            examples.setdefault(key,d)
        phase['decision_examples']=list(examples.values())
    return data


def historical():
    result=[]
    for suffix,function in (('backends.handler_codec','serialize'),('backends.runtime_emitter','emit_runtime'),
        ('backends.handler_emission','single_handlers'),('synthesis.costs','choose_regions'),('synthesis.emission','inject_handlers')):
        name='obfuscator.vm.'+suffix
        module=importlib.import_module(name)
        source=subprocess.run(['git','-c',f'safe.directory={ROOT.as_posix()}','show',
            REF+':'+name.replace('.','/')+'.py'],capture_output=True,check=True).stdout.decode()
        old=types.ModuleType(name);old.__package__=module.__package__;old.__file__=module.__file__
        exec(compile(source,'<baseline:'+name+'>','exec'),old.__dict__)
        result.append((module,function,getattr(old,function)))
    return result


@contextmanager
def baseline(modules):
    with ExitStack() as stack:
        for module,name,function in modules:stack.enter_context(patch.object(module,name,function))
        yield


def main():
    (ROOT/'local/performance').mkdir(parents=True,exist_ok=True)
    modules=historical();records=[]
    cases=[(backend,version,fixture,source,OPTIONS) for backend in ('classic','karity','mov')
        for version in ('5.1','5.3') for fixture,source in (('dag',SOURCE),('large',LARGE))]
    cases.append(('karity','5.3','maximum',LONG_DAG,{**user_preset('maximum')['vm_options'],'blob_form':'string'}))
    for backend,version,fixture,source,options in cases:
        expected=execute(source,version)[0];samples={'before':[],'after':[]}
        for repeat in range(3):
            for mode in (('before','after') if repeat%2==0 else ('after','before')):
                with baseline(modules) if mode=='before' else ExitStack():
                    output,data,_=build(source,backend,version,options)
                actual,cpu=execute(output,version)
                assert actual==expected,(backend,version,fixture,mode,actual,expected)
                data['execution_seconds']=cpu
                data['profile']=[row for row in data['profile'] if row['phase'].startswith(('synthesis_','serialize_blob'))]
                samples[mode].append(compact_profile(data))
        row={'backend':backend,'lua':version,'fixture':fixture,'options':options,'samples':samples,
            'median':{mode:{key:statistics.median(s[key] for s in data) for key in
                ('build_seconds','build_cpu_seconds','execution_seconds','output_bytes','runtime_bytes','blob_bytes')}
                for mode,data in samples.items()}}
        records.append(row)
        report={'baseline':REF,'seed':1400,'hash_seed':__import__('os').environ.get('PYTHONHASHSEED'),
            'repeats':3,'scope':'VM-only; alternating same-process historical/current builds; loader time included',
            'records':records}
        (ROOT/'local/performance/synthesis-storage.json').write_text(json.dumps(report,separators=(',',':')),encoding='utf-8')
        print('synthesis-storage-bench',backend,version,fixture,row['median'],flush=True)
    lines=['# Numeric DAG runtime and storage follow-up','',
        'Baseline `ce20b16` and current code: same process, Python 3.15, hash seed 0, random seed 1400. '
        'Three alternating pairs per case, VM only. Source/output passes and packing are excluded. '
        'Execution includes loading/initialization. All results match native Lua. '
        'Options, samples, pruning/storage/reuse profiles and decision totals/examples: [report](synthesis-storage.json). '
        'Full per-region decisions remain available through the synthesis debug dump.','',
        '| Backend / Lua / input | Build wall s | Execution CPU s | Output bytes | Change | Blob bytes |',
        '|---|---|---|---|---|---|']
    for row in records:
        a=row['median']['before'];b=row['median']['after'];delta=b['output_bytes']-a['output_bytes']
        lines.append(f"| {row['backend']} / {row['lua']} / {row['fixture']} | {a['build_seconds']:.3f} → {b['build_seconds']:.3f} | "
            f"{a['execution_seconds']:.3f} → {b['execution_seconds']:.3f} | {a['output_bytes']:,} → {b['output_bytes']:,} | "
            f"{delta:+,} ({delta/a['output_bytes']:+.2%}) | {a['blob_bytes']:,} → {b['blob_bytes']:,} |")
    lines+=['','The large fixture contains 256 repeated four-step numeric DAGs; it exercises operand dictionary storage. '
        'The maximum case uses the actual built-in VM settings. Smaller inputs retain KVM2 whenever dictionary '
        'and reader overhead cannot be recovered. MOV number-only HOST fallback bodies remain required. '
        'Logical PCs, all 48 word bits, accumulator updates, graph/state records and planned protection variants '
        'are retained. Timing differences include startup and scheduling noise; these are not full GUI preset times.','']
    (ROOT/'local/performance/synthesis-storage.md').write_text('\n'.join(lines),encoding='utf-8')


if __name__=='__main__':main()
