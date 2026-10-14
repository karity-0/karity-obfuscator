"""Paired VM-only synthesis cost under actual built-in protection settings."""
import argparse
import json
from pathlib import Path
import statistics
import sys

from profile_opcode_synthesis import SOURCE, FUNCTIONS, LONG_DAG, build, write_report
from profile_vm_runtime import execute
from obfuscator.presets import user_preset


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--repeats',type=int,default=3)
    parser.add_argument('--resume',action='store_true')
    args=parser.parse_args()
    report={'python':sys.version,'seed':1400,'repeats':args.repeats,
        'scope':'Karity Lua 5.3 VM-only, actual built-in VM settings, no source/output passes or packing',
        'records':[]}
    if args.resume:
        previous=json.loads(args.output.read_text(encoding='utf-8'))
        assert all(previous[key]==report[key] for key in ('python','seed','repeats','scope'))
        report=previous
    completed={(r['preset'],r['fixture'],r['enabled']) for r in report['records']}
    for preset in ('fast','balanced','strong','maximum'):
        fixtures=(('hello',"print('hi')"),('dag',SOURCE),('functions',FUNCTIONS))
        if preset=='maximum':fixtures+=(('long_dag',LONG_DAG),)
        for fixture,source in fixtures:
            expected=execute(source,'5.3')[0]
            for enabled in (False,True):
                if (preset,fixture,enabled) in completed:continue
                samples=[]
                options={**user_preset(preset)['vm_options'],'opcode_synthesis':enabled,'blob_form':'string'}
                for repeat in range(args.repeats):
                    output,data,_=build(source,'karity','5.3',options)
                    actual,cpu=execute(output,'5.3')
                    assert actual==expected,(preset,fixture,enabled,actual,expected)
                    data['execution_seconds']=cpu
                    data['synthesis_profile']=[x for x in data.pop('profile') if x['phase'].startswith(('opcode_synthesis','synthesis_'))]
                    samples.append(data)
                row={'preset':preset,'fixture':fixture,'enabled':enabled,'options':options,'samples':samples,
                    'regions':data['regions'],'handlers':data['handlers'],'rejected':data['rejected'],
                    'median':{key:statistics.median(x[key] for x in samples) for key in
                        ('build_seconds','build_cpu_seconds','execution_seconds','output_bytes','runtime_bytes','blob_bytes')}}
                report['records'].append(row)
                args.output.parent.mkdir(parents=True,exist_ok=True)
                write_report(report,args.output)
                print('preset-synthesis-bench',preset,fixture,enabled,row['regions'],row['handlers'],row['median'],flush=True)
    index={(r['preset'],r['fixture'],r['enabled']):r for r in report['records']}
    lines=['# Synthesis under built-in VM protection settings','',
        'Karity / Lua 5.3 / Python 3.15, seed 1400, three timed runs per condition. '
        'VM only: source/output passes and packing are excluded. All other preset VM options remain enabled. '
        'Execution includes loading and initialization; every result matches native Lua. '
        'Raw samples and options: [report](synthesis-presets.json).','',
        '| Preset / input | Build wall s, off → on | Execution CPU s, off → on | Output bytes, off → on | Change | Regions / handlers |',
        '|---|---|---|---|---|---|']
    for preset in ('fast','balanced','strong','maximum'):
        for fixture in ('hello','dag','functions')+(('long_dag',) if preset=='maximum' else ()):
            a=index[preset,fixture,False]['median'];r=index[preset,fixture,True];b=r['median']
            delta=b['output_bytes']-a['output_bytes']
            lines.append(f"| {preset} / {fixture} | {a['build_seconds']:.3f} → {b['build_seconds']:.3f} | "
                f"{a['execution_seconds']:.3f} → {b['execution_seconds']:.3f} | {a['output_bytes']:,} → {b['output_bytes']:,} | "
                f"{delta:+,} ({delta/a['output_bytes']:+.2%}) | {r['regions']} / {r['handlers']} |")
    lines+=['','An enabled feature may admit no numeric DAG. Existing junk/morphing and type/effect boundaries '
        'can interrupt eligible regions, especially in small inputs. No preceding protection was disabled to '
        'increase these counts. Feature-request entropy can alter frame keys and runtime layout even when '
        'no recipe is admitted; source-size differences alone are not recipe cost. The raw profile separates '
        'discovery, cost admission and physical emission. CPU resolution and scheduling make small timing '
        'differences noisy. These VM-only numbers are not full GUI preset build times.','']
    args.output.with_suffix('.md').write_text('\n'.join(lines),encoding='utf-8')


if __name__=='__main__':main()
