"""Paired VM-only and full-preset measurements of actual structural protection."""
from pathlib import Path
import sys
import json
import random
import time
import argparse
from copy import deepcopy

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from obfuscator import Pipeline,build_pipeline_from_config
from obfuscator.presets import user_preset,USER_PRESETS
from obfuscator.vm.ir.morphing import RATES
from obfuscator.vm import VMPass
from profile_vm_runtime import build,execute,FIXTURES

MIXED='''local function choose(a,b)return a or b end
local function branch(n)local x;if n>0 then x=n+7 else x=n-9 end;return x+1 end
local x=1;for i=1,24 do local s=i~x;local a=s&255;local b=s>>2
if i%2==0 then x=a+b else x=a-b end end
local c=choose(false,9);local d=branch(-2);print(x,c,d)'''
INPUTS={'hello':"print('hi')",'mixed':MIXED,'closures':FIXTURES['closures']}


def sizes(ir):
    return {'instructions':sum(len(b.instructions) for f in ir.functions() for b in f.blocks),
            'blocks':sum(len(f.blocks) for f in ir.functions())}


def measure(source,preset,enabled,seed,full,overrides=None):
    config=user_preset(preset)
    config['vm_options'].update(overrides or {})
    if not enabled:
        for key in (*RATES,'physical_block_permutation_rate'):config['vm_options'][key]=0
    config['signature']={'mode':'none'}
    if full:
        pipeline=build_pipeline_from_config(config,Pipeline,show_header=False)
        random.seed(seed);start=time.perf_counter();cpu=time.process_time()
        output=pipeline.run(source)
        wall=time.perf_counter()-start;cpu=time.process_time()-cpu
        vm=next(p for p in pipeline._post_passes if isinstance(p,VMPass))
        physical=vm.last_lowered_ir.backend_data['layout']
        from obfuscator.vm.backends.runtime_layout import iter_functions
        row={'output_bytes':len(output.encode()),'build_seconds':wall,'build_cpu_seconds':cpu,
             'source_ir':sizes(vm.last_optimized_ir),'morphed_ir':sizes(vm.last_morphed_ir),
             'physical_instructions':sum(len(f.code) for f in iter_functions(physical.functions)),
             'profile':vm.last_profile}
    else:
        raw=build(source,config['vm_options'],seed)
        output=raw.pop('output');raw.pop('runtime')
        row=raw
    actual,elapsed=execute(output)
    assert actual==execute(source)[0],(preset,enabled,actual)
    row['execution_cpu_seconds']=elapsed
    row['structural_profile']=[r for r in row.pop('profile') if r['phase'].startswith(('ir_morph','semantic_ir_morphing','physical_block_permutation'))]
    return row


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--full',action='store_true')
    parser.add_argument('--presets',nargs='+',choices=USER_PRESETS,default=list(USER_PRESETS))
    parser.add_argument('--inputs',nargs='+',choices=INPUTS,default=list(INPUTS))
    parser.add_argument('--seed',type=int,default=7361)
    parser.add_argument('--ablation',action='store_true',help='measure each strategy or permutation alone')
    args=parser.parse_args()
    report={'seed':args.seed,'full_presets':args.full,'ablation':args.ablation,'python':sys.version,'records':[]}
    for preset in args.presets:
        for name in args.inputs:
            for strategy in (*RATES,'physical_block_permutation_rate') if args.ablation else ('combined',):
                overrides={**dict.fromkeys((*RATES,'physical_block_permutation_rate'),0),strategy:1} if args.ablation else {}
                pair={}
                for enabled in (False,True):pair['after' if enabled else 'before']=measure(INPUTS[name],preset,enabled,args.seed,args.full,overrides)
                report['records'].append({'preset':preset,'input':name,'strategy':strategy,**pair})
                args.output.parent.mkdir(parents=True,exist_ok=True)
                args.output.write_text(json.dumps(report,indent=2),encoding='utf-8')
                print('ir-morph-pair',preset,name,strategy,pair['before']['output_bytes'],pair['after']['output_bytes'],
                      round(pair['before']['build_seconds'],3),round(pair['after']['build_seconds'],3),flush=True)


if __name__=='__main__':main()
