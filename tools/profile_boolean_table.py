"""Compare source literal passes to a Git baseline, including runtime cost."""
from pathlib import Path
import argparse
import json
import random
import statistics
import subprocess
import sys
import time
import types

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lupa.lua53 import LuaRuntime
from obfuscator import Pipeline
from obfuscator.passes.boolean_obfuscation import BooleanObfuscationPass
from obfuscator.passes.table_obfuscation import TableObfuscationPass
from obfuscator.passes.number_obfuscation import NumberObfuscationPass
from obfuscator.passes.ts_utils import parse

FIXTURES = {
    'booleans': ('boolean', 'local n=0;for i=1,100 do local a=true;local b=false;'
                 'if a and not b then n=n+1 end end return n,true,false'),
    'records': ('table', 'local sum=0;for i=1,100 do local t={a=1,b=2,c=3,d=4,e=5,f=6};'
                'sum=sum+t.a+t.f end return sum'),
    'nested': ('table', 'local t={a={b=1,c=2},d={e=3,f=4},g=5};return t.a.c,t.d.f,t.g'),
    'dense_array': ('table', 'local t={1,2,3,4,5,6};return #t,t[1],t[6]'),
    'sparse_array': ('table', 'local t={1,nil,nil,4,nil};return #t,t[1],t[4]'),
}


def baseline_class(revision, module_name, class_name):
    result = subprocess.run(['git', '-c', 'safe.directory='+str(ROOT), 'show',
                             revision+':obfuscator/passes/'+module_name+'.py'],
                            cwd=ROOT, capture_output=True, check=True, encoding='utf-8')
    module=types.ModuleType('obfuscator.passes._baseline_'+module_name)
    exec(compile(result.stdout,module_name+'.py','exec'),module.__dict__)
    return getattr(module,class_name)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline',default='69ff179')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    old_boolean=baseline_class(args.baseline,'boolean_obfuscation','BooleanObfuscationPass')
    old_table=baseline_class(args.baseline,'table_obfuscation','TableObfuscationPass')
    rows=[]
    for name,(kind,source) in FIXTURES.items():
        for layered in (False,True):
            for variant in ('before','after','dataflow' if kind=='boolean' else 'reconstruct'):
                factory=(old_boolean if kind=='boolean' else old_table) if variant=='before' else (
                    BooleanObfuscationPass if kind=='boolean' else TableObfuscationPass)
                options={'mode':variant} if variant in ('dataflow','reconstruct') else {}
                times=[]
                for _ in range(4):
                    random.seed(7201)
                    pipeline=Pipeline(show_header=False).add(factory(**options))
                    if layered:pipeline.add(NumberObfuscationPass())
                    start=time.perf_counter();output=pipeline.run(source);times.append(time.perf_counter()-start)
                lua=LuaRuntime(unpack_returned_tuples=True)
                original=lua.eval('function() '+source+' end')()
                execute=lua.eval('function() '+output+' end')
                actual=execute()
                runtime=[]
                for _ in range(3):
                    start=time.perf_counter()
                    for _ in range(1000):execute()
                    runtime.append((time.perf_counter()-start)/1000)
                scopes=sum(n.type=='function_definition' for n in parse(output).walk())
                rows.append({'fixture':name,'number_obf':layered,'variant':variant,'seed':7201,
                             'source_bytes':len(source.encode()),'output_bytes':len(output.encode()),
                             'build_seconds':statistics.median(times[1:]),
                             'runtime_seconds':statistics.median(runtime),'helper_functions':scopes,
                             'semantic_match':actual==original,
                             'profile':getattr(pipeline._passes[0],'last_profile',[])})
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps({'baseline':args.baseline,'python':sys.version,'rows':rows},indent=2),encoding='utf-8')
    for row in rows:
        print(row['fixture'],row['number_obf'],row['variant'],row['output_bytes'],
              round(row['build_seconds']*1000,3),round(row['runtime_seconds']*1e6,3),row['semantic_match'])


if __name__=='__main__':main()
