"""Compare storage ABIs on identical protected physical programs.

Requires a baseline commit with the same physical handler IR. Source passes
run normally; VM output passes/packing are excluded from the storage snapshot.
Native reader probes exclude encryption, keystream generation, string masking
and execution setup. CPU medians describe storage work, not whole-build speed.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import random
import statistics
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT/'tools'))


def historical(ref, path):
    return subprocess.run(['git','-c',f'safe.directory={ROOT.as_posix()}',
                           'show',f'{ref}:{path}'],cwd=ROOT,capture_output=True,check=True).stdout.decode('utf-8')


def legacy_sections(codec, blob, tags):
    r=codec.BinReader(blob);stats={}
    def mark(name,start):stats[name]=stats.get(name,0)+r._pos-start
    def constant():
        tag=r.u8()
        if tag==tags['bool']:r.u8()
        elif tag in (tags['int'],tags['float']):r.u64()
        elif tag==tags['str']:r.string()
        elif tag==tags['iexpr']:r.u64();codec._read_integrity_program(r)
    r.u16();r.u32();r.u16();mark('header',0)
    start=r._pos
    for _ in range(r.u32()):constant()
    mark('fake_constants',start)
    def proto():
        start=r._pos
        for _ in range(4):r.u8()
        n=r.u32();mark('proto_headers',start)
        start=r._pos
        for _ in range(n):r.u64()
        mark('instructions',start)
        start=r._pos
        for _ in range(n):
            for _ in range(r.u8()):r.u8()
        mark('avalanche',start)
        start=r._pos
        for _ in range(n):
            for _ in range(r.u8()):r.u8();r.u8();r.u16();r.u32();r.u32()
        mark('graph_sites',start)
        start=r._pos
        for _ in range(r.u16()):
            for _ in range(r.u8()):r.u32()
        mark('routes',start)
        start=r._pos
        for _ in range(r.u32()):constant()
        mark('constants',start)
        start=r._pos
        for _ in range(r.u32()):r.u8();r.u8()
        mark('upvalues',start)
        start=r._pos;children=r.u32();mark('children',start)
        for _ in range(children):proto()
    proto()
    assert r._pos==len(blob)
    return stats


def storage_reader(source, tags, layout, legacy):
    from lupa.lua51 import LuaRuntime as Lua51
    from lupa.lua53 import LuaRuntime as Lua53
    from obfuscator.vm.vm_variants import apply_instr_layout
    def region(name):return source.split(f'--<<TARGET_{name}>>',1)[1].split(f'--<<ENDTARGET_{name}>>',1)[0]
    body='local function read_proto(r, acc_state)'+source.split('local function read_proto(r, acc_state)',1)[1].split('--<<TARGET_INTEGRITY_MIX>>',1)[0]
    names=('nil','bool','int','float','str','iexpr')
    declaration='local '+','.join('CTAG_'+n.upper() for n in names)+'='+','.join(str(tags[n]) for n in names)+'\n'
    declaration+='local '+','.join('CK_'+n.upper() for n in names)+'=0,1,2,3,4,5\n'
    declaration+='local _SH_A,_SH_B,_SH_C,_SH_V=32,23,14,40\nlocal _MASK_OV=0xFF000000007F\n'
    wrapper='''return function(blob)
        local r=make_reader(blob)
        HEADER
        local seed=r.u16();r.u32();r.u16()
        for i=1,COUNT do
            local tag=r.u8()
            if tag==CTAG_BOOL then r.u8() elseif tag==CTAG_INT then r.i64()
            elseif tag==CTAG_FLOAT then r.f64() elseif tag==CTAG_STR then r.str()
            elseif tag==CTAG_IEXPR then
                r.u64();for j=1,r.u8() do if r.u8()==1 then r.u32() end end
            end
        end
        return read_proto(r,{seed,0})
    end'''.replace('HEADER','' if legacy else 'r.header()').replace('COUNT','r.u32()' if legacy else 'r.uint()')
    text=(region('READER_PRIMITIVES')+region('INSTRUCTION_XOR')+declaration+
          'local function _ksm(i) return 0 end\nlocal function _kss(s) return s end\n'+body+wrapper)
    version51='return {lo,hi}' in region('WORD_READ')
    runtime=(Lua51 if version51 else Lua53)(encoding=None)
    return runtime.execute(apply_instr_layout(text,layout).encode())


def storage_value(value):
    if hasattr(value,'items'):
        return {key:({i:int(word)&0xFFFFFFFFFFFF for i,word in item.items()}
                     if key==b'code' else storage_value(item))
                for key,item in value.items()}
    return value


def measure_pair(operations, repeats):
    # Batch short probes so Windows CPU-clock granularity cannot round them to
    # zero. Both implementations use the same batch size and alternating order.
    estimates=[]
    for operation in operations.values():
        start=time.perf_counter()
        for _ in range(3):operation()
        estimates.append((time.perf_counter()-start)/3)
    batch=max(1,min(5000,int(0.1/max(estimates))))
    samples={name:{'wall':[],'cpu':[]} for name in operations}
    for repeat in range(repeats):
        for name in (('before','after') if repeat%2==0 else ('after','before')):
            start,cpu=time.perf_counter(),time.process_time()
            for _ in range(batch):operations[name]()
            samples[name]['wall'].append((time.perf_counter()-start)/batch)
            samples[name]['cpu'].append((time.process_time()-cpu)/batch)
    return {name:{'batch':batch,**{metric:statistics.median(values) for metric,values in data.items()}}
            for name,data in samples.items()}


def main():
    from benchmark_user_presets import FIXTURES
    from obfuscator.pipeline import Pipeline
    from obfuscator.registry import resolve_config_profile,build_pipeline_from_config
    from obfuscator.vm.backends.base import VMBackend
    from obfuscator.vm.backends import handler_codec as current
    from obfuscator.vm.backends.runtime_layout import iter_functions
    from obfuscator.vm.mov.serializer import serialize as mov_serialize
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-ref',required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--profiles',nargs='+',default=['fast','balanced','strong','maximum'])
    parser.add_argument('--backends',nargs='+',default=['classic','karity','mov'])
    parser.add_argument('--fixtures',nargs='+',default=['small','strings','closures'])
    parser.add_argument('--seed',type=int,default=9450)
    parser.add_argument('--repeats',type=int,default=5)
    args=parser.parse_args()
    if args.repeats<1:parser.error('--repeats must be positive')
    codec_path='obfuscator/vm/backends/handler_codec.py'
    runtime_paths={'5.3':'obfuscator/vm/vm.lua','5.1':'obfuscator/vm/runtimes/lua51/vm.lua'}
    old_runtime={v:historical(args.baseline_ref,p) for v,p in runtime_paths.items()}
    new_runtime={v:(ROOT/p).read_text(encoding='utf-8') for v,p in runtime_paths.items()}
    report={'baseline_ref':args.baseline_ref,'python':sys.version,'seed':args.seed,'repeats':args.repeats,
            'scope':'Same source-protected physical programs; native storage readers omit encryption/key generation/string masking/execution setup. CPU medians are not whole-build or startup timings.',
            'records':[]}
    config_root=json.loads((ROOT/'config.example.json').read_text(encoding='utf-8'))
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='karity-storage-') as work:
        path=Path(work)/'legacy_codec.py';path.write_text(historical(args.baseline_ref,codec_path),encoding='utf-8')
        spec=importlib.util.spec_from_file_location('obfuscator.vm.backends._profile_legacy_codec',path)
        legacy=importlib.util.module_from_spec(spec);spec.loader.exec_module(legacy)
        for fixture in args.fixtures:
            for backend in args.backends:
                for preset in args.profiles:
                    config=resolve_config_profile(config_root,preset)
                    config['vm_options']['backend']=backend
                    config['signature']={'mode':'none'}
                    config['passes']=[p for p in config['passes'] if p!='pack']
                    snapshots=[]
                    def capture(self,lowered,context):
                        layout=lowered.backend_data['layout']
                        extension=b''
                        if backend=='mov':
                            extension=mov_serialize(lowered.backend_data['programs'],lowered.backend_data['kits'],linked=lowered.backend_data['linked'])
                        snapshots.append((layout,extension,hashlib.sha256(lowered.protection_plan.dump().encode()).hexdigest()))
                        return 'return'
                    random.seed(args.seed)
                    pipeline=build_pipeline_from_config(config,Pipeline,show_header=False)
                    with patch.object(VMBackend,'emit',capture):pipeline.run(FIXTURES[fixture])
                    for snapshot_index,(layout,extension,plan_hash) in enumerate(snapshots):
                        kwargs={'layout':layout.instruction_layout,'constant_tags':layout.constant_tags,'vm_count':layout.vm_count,
                                'integrity_options':{'enabled':config['vm_options'].get('integrity_constants',False)}}
                        rng=random.getstate();blobs={};stats={};rng_after={}
                        def write_old():
                            random.setstate(rng)
                            return legacy.serialize(layout.functions,**kwargs)
                        def write_new():
                            random.setstate(rng)
                            return current.serialize(layout.functions,stats=stats,**kwargs)
                        operations={'before':write_old,'after':write_new}
                        for name,operation in operations.items():
                            blobs[name]=operation();rng_after[name]=random.getstate()
                        assert rng_after['before']==rng_after['after']
                        timings=measure_pair(operations,args.repeats)
                        functions=list(iter_functions(layout.functions))
                        row={'fixture':fixture,'backend':backend,'preset':preset,'snapshot':snapshot_index,'plan_sha256':plan_hash,
                             'physical_instructions':sum(len(f.code) for f in functions),
                             'graph_descriptors':sum(len(i.graph_sites) for f in functions for i in f.code),
                             'avalanche_slots':sum(len(i.avalanche) for f in functions for i in f.code),
                             'prototypes':len(functions),'integrity_constants':sum(len(f.integrity_indices) for f in functions),
                             'block_routes':sum(len(f.routes) for f in functions),'mov_extension_bytes':len(extension),
                             'before':{'shared_bytes':len(blobs['before']),'total_bytes':len(blobs['before'])+len(extension),
                                       'section_bytes':legacy_sections(legacy,blobs['before'],layout.constant_tags)},
                             'after':{'shared_bytes':len(blobs['after']),'total_bytes':len(blobs['after'])+len(extension),**stats}}
                        for name in ('before','after'):
                            row[name]['serialize_cpu_seconds_median']=timings[name]['cpu']
                            row[name]['serialize_wall_seconds_median']=timings[name]['wall']
                            row[name]['serialize_batch']=timings[name]['batch']
                            row[name]['reader_cpu_seconds_median']={}
                            row[name]['reader_wall_seconds_median']={}
                        for version in ('5.1','5.3'):
                            readers={name:storage_reader((old_runtime if name=='before' else new_runtime)[version],layout.constant_tags,layout.instruction_layout,name=='before') for name in ('before','after')}
                            probes={}
                            for name in ('before','after'):
                                probe=readers[name](blobs[name])
                                assert len(probe[b'code'])==len(layout.functions.code)
                                probes[name]=storage_value(probe)
                            assert probes['before']==probes['after']
                            timings=measure_pair({name:(lambda n=name:readers[n](blobs[n])) for name in ('before','after')},args.repeats)
                            for name in ('before','after'):
                                row[name]['reader_cpu_seconds_median'][version]=timings[name]['cpu']
                                row[name]['reader_wall_seconds_median'][version]=timings[name]['wall']
                        report['records'].append(row)
                        args.output.write_text(json.dumps(report,indent=2),encoding='utf-8')
                        reduction=100*(1-row['after']['total_bytes']/row['before']['total_bytes'])
                        print(f'{fixture} {backend} {preset}: {row["before"]["total_bytes"]} -> {row["after"]["total_bytes"]} ({reduction:.2f}%)',flush=True)


if __name__=='__main__':main()
