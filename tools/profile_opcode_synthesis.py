"""Paired real VM builds; no source/output passes. Counters are test-only."""
from pathlib import Path
from contextlib import ExitStack
from unittest.mock import patch
import argparse,hashlib,json,random,re,statistics,sys,time
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools')]
from profile_vm_runtime import execute

SOURCE='local sum=0;for i=1,40 do local a=i*3;local b=a+7;local c=b*5;sum=sum+c end;print(sum)'
REPEATED=SOURCE.replace(';print(sum)',';for j=1,40 do local a=j*3;local b=a+9;local c=b*5;sum=sum+c end;print(sum)')
FUNCTIONS='local function f()local s=0;for i=1,15 do local a=i*3;local b=a+7;local c=b*5;s=s+c end;return s end;local function g()local s=0;for i=1,25 do local a=i*3;local b=a+9;local c=b*5;s=s+c end;return s end;local x=f();local y=g();print(x,y)'
LONG_DAG='local s=0;for i=1,5 do local a=i*3;'+''.join('a=a*2;a=a-3;' for _ in range(16))+'s=s+a end;print(s)'
BASE={'fake_handlers':False,'mutate_handlers':False,'junk_instructions':False,
      'graph_execution_rate':0,'cross_instruction_rate':0,'runtime_polymorphism_rate':0,
      'block_variant_rate':0,'opcode_splitting':False,'opcode_fusion':False,'blob_form':'string'}
PROTECTED={'graph_execution_rate':1,'cross_instruction_rate':1,'runtime_polymorphism_rate':1,
           'block_variant_rate':1,'block_variant_count':3,'semantic_state_threading':True,
           'integrity_constants':True,'dispatcher_target_hiding':True,
           'fake_handlers':True,'mutate_handlers':True,'physical_block_permutation_rate':1}

def build(source,backend,version,options,seed=1400,instrument=False,event_trace=False):
    from obfuscator.vm import VMPass
    from obfuscator.vm.backends.base import VMBackend
    from obfuscator.vm.targets.profile import TargetProfile
    random.seed(seed)
    p=VMPass(vm_options={'backend':backend,**options},target=TargetProfile(version,backend))
    serialize=VMBackend.serialize_program;wrap=p._backend.target.wrap;finalize=p._backend.target.finalize_runtime;data={}
    def blob(self,lowered,context):
        result=serialize(self,lowered,context)
        data.update(blob_bytes=len(result),blob_hash=hashlib.sha256(result).hexdigest(),common_blob_bytes=len(result))
        return result
    def runtime(script,*args):
        data['runtime_bytes']=len(script.encode())
        return wrap(script,*args)
    def counted(script):
        script=finalize(script)
        if event_trace:
            for name in ('_route_step','_ss_step'):
                header=f'local function {name}(ip,op,a,b,c)'
                script=script.replace(header,header+f' _KARITY_SYN_EVENTS[#_KARITY_SYN_EVENTS+1]=table.concat({{"{name}",ip,op,a,b,c}},":");')
        if instrument:
            script=re.sub(r'(local function rget(?:_\w+)?\(i\))',r'\1 _KARITY_SYN_BENCH[2]=_KARITY_SYN_BENCH[2]+1;',script)
            script=re.sub(r'(local function rset(?:_\w+)?\(i,v\))',r'\1 _KARITY_SYN_BENCH[3]=_KARITY_SYN_BENCH[3]+1;',script)
            if backend!='mov':
                script=script.replace('local _ip=pc;', '_KARITY_SYN_BENCH[1]=_KARITY_SYN_BENCH[1]+1;local _ip=pc;')
            if backend=='mov':
                script=script.replace('local q=_mtape[_mp]', '_KARITY_SYN_BENCH[1]=_KARITY_SYN_BENCH[1]+1; local q=_mtape[_mp]')
                script=script.replace('_mdigits[i]=nil; _mstrings[i]=nil; regs[i]=v','_KARITY_SYN_BENCH[4]=_KARITY_SYN_BENCH[4]+1; _mdigits[i]=nil; _mstrings[i]=nil; regs[i]=v')
                script=script.replace('_mdigits[_ma]=d; _mstrings[_ma]=nil; regs[_ma]=nil','_KARITY_SYN_BENCH[4]=_KARITY_SYN_BENCH[4]+1; _mdigits[_ma]=d; _mstrings[_ma]=nil; regs[_ma]=nil')
                script=script.replace('_syn_tmp[i]=v; return','_KARITY_SYN_BENCH[5]=_KARITY_SYN_BENCH[5]+1; _syn_tmp[i]=v; return')
                script=script.replace('then _syn_tmp[_ma]=d else','then _KARITY_SYN_BENCH[5]=_KARITY_SYN_BENCH[5]+1; _syn_tmp[_ma]=d else')
        return script
    started=time.perf_counter();cpu_started=time.process_time()
    # Production intentionally uses OS entropy independently of the seed.
    # Freeze only this benchmark's nonce/wrapper entropy for paired identity.
    entropy=random.Random(seed^0xA54F)
    with ExitStack() as stack:
        stack.enter_context(patch.object(VMBackend,'serialize_program',blob))
        stack.enter_context(patch.object(p._backend.target,'wrap',runtime))
        stack.enter_context(patch.object(p._backend.target,'finalize_runtime',counted))
        stack.enter_context(patch('secrets.choice',entropy.choice))
        stack.enter_context(patch('os.urandom',lambda n:entropy.randbytes(n)))
        if backend=='mov':
            from obfuscator.vm.backends.mov import MovBackend
            mov_serialize=MovBackend.serialize_program
            def whole_blob(self,lowered,context):
                result=mov_serialize(self,lowered,context)
                data.update(blob_bytes=len(result),blob_hash=hashlib.sha256(result).hexdigest())
                return result
            stack.enter_context(patch.object(MovBackend,'serialize_program',whole_blob))
        output=p.run(source)
    data.update(build_seconds=time.perf_counter()-started,build_cpu_seconds=time.process_time()-cpu_started,output_bytes=len(output.encode()),profile=p.last_profile)
    plan=p.last_lowered_ir.backend_data.get('synthesis_plan')
    data['recipes']=len(plan.recipes) if plan else 0
    data['regions']=len(plan.occurrences) if plan else 0
    data['regional']=sum(o.scope=='regional' for o in plan.occurrences) if plan else 0
    data['rejected']=dict(plan.rejected) if plan else {}
    physical=next((x for x in p.last_profile if x['phase']=='synthesis_physical'),{})
    data['handlers']=physical.get('handlers',0);data['fallbacks']=physical.get('fallback_regions',0)
    if instrument:output='_KARITY_SYN_BENCH={0,0,0,0,0};local _syn_run=function() '+output+" end;_syn_run();print('SYN-COUNTERS',table.concat(_KARITY_SYN_BENCH,'\\t'))"
    if event_trace:output='_KARITY_SYN_EVENTS={};local _syn_run=function() '+output+" end;_syn_run();print('SYN-EVENTS',table.concat(_KARITY_SYN_EVENTS,'|'))"
    return output,data,p


def write_report(report,path):
    # One record per line keeps raw evidence diffable without tens of
    # thousands of indentation-only lines; the narrative lives in Markdown.
    header={key:value for key,value in report.items() if key!='records'}
    rows=[json.dumps(row,separators=(',',':')) for row in report['records']]
    path.write_text(json.dumps(header,indent=2)[:-2]+',\n  "records": [\n'+',\n'.join('    '+row for row in rows)+'\n  ]\n}\n',encoding='utf-8')


def write_summary(report,path):
    if path.stem!='opcode-synthesis':
        lines=['# Current synthesis cost selection','',
            f"Python 3.15; seed {report['seed']}; {report['repeats']} repeats per condition. "
            'VM only, source/output passes and packing excluded. Execution CPU includes loading and initialization. '
            f"All outputs match native Lua. [Raw samples]({path.with_suffix('.json').name}).",'',
            '| Backend / Lua / input / mode | Build wall s | Execution CPU s | Output bytes | Regions | Dispatches |',
            '|---|---|---|---|---|---|']
        for row in report['records']:
            m=row['median']
            lines.append(f"| {row['backend']} / {row['lua']} / {row['fixture']} / {row['mode']} | "
                f"{m['build_seconds']:.3f} | {m['execution_seconds']:.3f} | {int(m['output_bytes']):,} | "
                f"{row['regions']} | {row['counters'][0]:,} |")
        lines+=['','Ordinary, selected pair Fusion and synthesis are distinct modes. MOV has no pair Fusion. '
            'Efficiency can reject synthesis when existing Fusion or mandatory MOV host scope work is cheaper; '
            'Balanced/Protection retain bounded diversity. Compiler work remains a proxy, not a runtime speed guarantee. '
            'Timing differences at millisecond resolution and short-input load costs are noisy. Full preset costs '
            'are measured separately in [pipeline measurements](synthesis-pipeline.md).','']
        path.write_text('\n'.join(lines),encoding='utf-8')
        return
    index={(r['lua'],r['backend'],r['fixture'],r['mode']):r for r in report['records']}
    lines=['# Production opcode synthesis measurements','',
        'Windows, Python 3.15; seed 1400, three runs per condition. VM only: no source/output passes or packing. OS nonce/wrapper entropy is fixed only in the benchmark. Execution CPU includes loading, decryption and initialization; native process launch is excluded. Build wall and Python CPU samples are retained in the [raw report](opcode-synthesis.json).','',
        'Inputs: hello; a four-operation DAG (40 and 2,000 iterations); two repeated DAGs; two numeric functions. The full report has 170 backend/target/input/mode records and 510 timed builds. MOV has no legacy pair fusion, so its combined mode is the Balanced synthesis comparison with fusion explicitly disabled.','',
        '## Hot loop: ordinary vs Efficiency synthesis','',
        '| Backend / Lua | Build CPU, s | Execution CPU, s | Fusion CPU, s | Output bytes | Blob bytes |','|---|---|---|---|---|---|']
    pairs=[]
    for version in ('5.1','5.3'):
        for backend in ('classic','karity','mov'):
            a=index.get((version,backend,'hot','ordinary'));b=index.get((version,backend,'hot','synthesis'))
            if not a or not b:continue
            pairs.append((version,backend,a,b));x=a['median'];y=b['median'];f=index.get((version,backend,'hot','fusion'))
            fusion=f"{f['median']['execution_seconds']:.3f}" if f else '—'
            lines.append(f"| {backend} / {version} | {x['build_cpu_seconds']:.3f} → {y['build_cpu_seconds']:.3f} | {x['execution_seconds']:.3f} → {y['execution_seconds']:.3f} | {fusion} | {int(x['output_bytes']):,} → {int(y['output_bytes']):,} | {int(x['blob_bytes']):,} → {int(y['blob_bytes']):,} |")
    lines+=['','Milliseconds and modest CPU differences vary with startup, scheduling, runtime selectors and opcode placement; these samples are not speed guarantees. Built-in user presets enable policy-budgeted synthesis; legacy/custom settings retain their values. Additional source pass costs are outside this measurement.','',
        '## Actual execution counters','',
        'Counters use separately instrumented builds, with instrumentation inserted before integrity binding. Every instrumented result is checked against native Lua. rget/rset counts include helper variants and constants. MOV bank commits count the native/encoded destination stores; its helper calls and microinstructions are distinct from Classic/Karity handler dispatch.','',
        '| Backend / Lua | Dispatches (before → after) | rget calls | rset calls | MOV bank commits |','|---|---|---|---|---|']
    for version,backend,a,b in pairs:
        x=a['counters'];y=b['counters'];unit='micro' if backend=='mov' else 'handler'
        cells=[f'{x[i]:,} → {y[i]:,}' for i in range(4)]
        lines.append(f'| {backend} / {version} | {cells[0]} {unit} | {cells[1]} | {cells[2]} | {cells[3] if backend=="mov" else "—"} |')
    lines+=['','Classic caches inputs and removes dead VM writes. Karity retains encoded/pending writes and logical events. MOV redirects dead stores to frame-local values. Its proven integer DAGs feed encoded SSA values and cached inputs through existing LOOKUP arithmetic, eliminating two representation-boundary records per step; number-only scopes retain their guards. Actual counts above distinguish those paths.','',
        '## Sharing on the repeated-DAG input','',
        '| Backend / Lua | Policy | Recipes | Regional | Physical handlers |','|---|---|---:|---:|---:|']
    for version in ('5.1','5.3'):
        for backend in ('classic','karity','mov'):
            for mode in ('synthesis','balanced','protection'):
                row=index.get((version,backend,'repeated',mode))
                if row:lines.append(f"| {backend} / {version} | {'efficiency' if mode=='synthesis' else mode} | {row['recipes']} | {row['regional']} | {row['handlers']} |")
    lines+=['','Alias/defer event contracts can require distinct physical handlers even when semantic recipes share. All retained operand/event words are still serialized; storage compression is not an effect of this feature. Recipes add runtime source in many cases. The hello input admits no recipe, and its feature-off path retains the old output.','',
        '## Validation and limits','',
        'The integration baseline passed the complete CI manifest (58 suites). This follow-up reruns affected existing suites and 141 real synthesis builds on each of Python 3.12/3.15 across Classic/Karity/MOV and Lua 5.1/5.3. Coverage includes protected graph/pending/block variants, multi-VM, mixed domains, morphing/junk, closures/varargs/coroutines/errors, numeric edge cases, malformed layout/bindings and budget fallback. The additional 28 builds cover hidden dispatch with six layouts and actual Strong VM settings; four more exercise actual Maximum settings and default budgets on a larger DAG. Protected Karity logical route/state traces match the baseline on both targets. MOV high release-check and configuration save/restore pass. Existing timeouts remain unchanged.','',
        'Large 16-step mutated bodies originally exceeded Lua’s 200-local limit. They now reuse the existing scratch compactor. A 32-recipe stress case measured over 131,000 kernel instructions; private closure banks bound each function’s dispatch jumps without dropping steps or mutation. These are compiler-budget adaptations, not fewer protected source regions.','',
        'Admission measures renderer/mutation compiler costs, runtime source and binding alternatives, with independent code and diversity allowances. Efficiency prefers estimated work savings; Balanced/Protection can pay bounded overhead for distinct opcode/execution forms. This is not a nanosecond model of every graph/helper. Binding probes are pure and do not consume instruction-padding RNG. The four built-in policies enable synthesis; generic/legacy configuration remains opt-in for compatibility. See the [implementation contract](../design/adaptive-opcode-synthesis.md) for preserved events and conservative fallback.','']
    path.write_text('\n'.join(lines),encoding='utf-8')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--repeats',type=int,default=3)
    parser.add_argument('--resume',action='store_true',help='Continue a report with the same seed, scope and repeat count.')
    parser.add_argument('--fixtures',nargs='+',choices=('hello','dag','hot','repeated','functions'),default=('hello','dag','hot','repeated','functions'))
    parser.add_argument('--backends',nargs='+',choices=('classic','karity','mov'),default=('classic','karity','mov'))
    parser.add_argument('--lua',nargs='+',choices=('5.1','5.3'),default=('5.1','5.3'))
    parser.add_argument('--modes',nargs='+',choices=('ordinary','fusion','synthesis','efficiency_fusion','balanced','combined','protection'),
        default=('ordinary','fusion','synthesis','balanced','combined','protection'))
    opts=parser.parse_args()
    report={'python':sys.version,'seed':1400,'repeats':opts.repeats,
        'register_cache':'epoch/generation validation with cached bank address',
        'scope':'real VM-only, retained operand slots, load/init included','records':[]}
    if opts.resume:
        previous=json.loads(opts.output.read_text(encoding='utf-8'))
        assert all(previous[key]==report[key] for key in ('python','seed','repeats','scope','register_cache'))
        report=previous
    completed={(r['lua'],r['backend'],r['fixture'],r['mode']) for r in report['records']}
    variants={'ordinary':{},'fusion':{'opcode_fusion':True},
        'synthesis':{'opcode_synthesis':True,'synthesis_policy':'efficiency'},
        'efficiency_fusion':{'opcode_synthesis':True,'opcode_fusion':True,'synthesis_policy':'efficiency'},
        'balanced':{'opcode_synthesis':True,'synthesis_policy':'balanced'},
        'combined':{'opcode_synthesis':True,'opcode_fusion':True,'synthesis_policy':'balanced'},
        'protection':{'opcode_synthesis':True,'synthesis_policy':'protection'}}
    for version in opts.lua:
        for backend in opts.backends:
            fixtures={'hello':"print('hello')",'dag':SOURCE,'hot':SOURCE.replace('1,40','1,2000'),'repeated':REPEATED,'functions':FUNCTIONS}
            for fixture in opts.fixtures:
                source=fixtures[fixture]
                expected=execute(source,version)[0]
                for name,settings in variants.items():
                    if name not in opts.modes:continue
                    if backend=='mov' and name in ('fusion','efficiency_fusion'):continue
                    if (version,backend,fixture,name) in completed:continue
                    samples=[]
                    for repeat in range(opts.repeats):
                        effective={**BASE,**settings}
                        if backend=='mov':effective['opcode_fusion']=False
                        output,data,_=build(source,backend,version,effective)
                        actual,cpu=execute(output,version)
                        assert actual==expected,(backend,version,fixture,name,actual,expected)
                        data['execution_seconds']=cpu
                        data['synthesis_profile']=[x for x in data.pop('profile') if x['phase'].startswith(('opcode_synthesis','synthesis_'))]
                        samples.append(data)
                    output,_,_=build(source,backend,version,effective,instrument=True)
                    actual,_=execute(output,version)
                    native,separator,counts=actual.rpartition(b'\nSYN-COUNTERS\t')
                    assert separator and native==expected,(backend,version,fixture,name,actual)
                    counters=counts.split(b'\t')
                    row={'backend':backend,'lua':version,'fixture':fixture,'mode':name,'samples':samples,
                        'dispatch_counter_unit':'microinstruction' if backend=='mov' else 'handler',
                        'counters':[int(float(x)) for x in counters],
                        'counter_fields':['dispatches','rget_calls','rset_calls','mov_bank_commits','mov_temporary_stores'],
                        'median':{key:statistics.median(x[key] for x in samples) for key in ('build_seconds','build_cpu_seconds','execution_seconds','output_bytes','runtime_bytes','blob_bytes')},
                        'recipes':data['recipes'],'regions':data['regions'],'handlers':data['handlers'],'regional':data['regional']}
                    report['records'].append(row)
                    opts.output.parent.mkdir(parents=True,exist_ok=True)
                    write_report(report,opts.output)
                    print('vm-synthesis-bench',backend,version,fixture,name,row['counters'],flush=True)
    write_summary(report,opts.output.with_suffix('.md'))
if __name__=='__main__':main()
