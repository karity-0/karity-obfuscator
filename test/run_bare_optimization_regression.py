"""Bare code-generation proofs, frame lifetimes and native Lua semantics."""
from pathlib import Path
from unittest.mock import patch
import random
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'test')]
from obfuscator import Pipeline,build_pipeline_from_config
from obfuscator.vm import VMPass
from obfuscator.vm.targets.profile import TargetProfile
from obfuscator.vm.backends.bare_emitter import Function
from obfuscator.vm.backends import bare_registers
from obfuscator.vm.protection import protect
from obfuscator.vm.ir import validate_semantic_ir
from run_vm_backend_regression import options
from run_cross_backend_generated_regression import execute,generated_source


def build(source,version='5.3',seed=1810,protected=False,passes=()):
    random.seed(seed)
    vm=VMPass(target=TargetProfile(version,'bare'),vm_options={**options('bare'),
        'integrity_constants':protected,'integrity_constant_rate':1.0 if protected else 0.0},
        vm_output_passes=list(passes))
    texts={}
    original=Function.source
    def observe(emitter):
        text=original(emitter);texts[emitter.function.id]=text;return text
    with patch.object(Function,'source',observe):
        output=vm.run(source)
    return output,vm,texts


class BareOptimizationTests(unittest.TestCase):
    def test_dynamic_helpers_are_emitted_only_for_actual_uses(self):
        for version in ('5.1','5.3'):
            source='local function pass(...)return ... end;print(pass(7,nil,false,nil))'
            vm,texts=self.compare(source,version)
            self.assertGreater(vm.last_lowered_ir.backend_data['optimization'].get('frame_getters_elided',0),0)
            text=texts['f0.0']
            self.assertIn('local function _Bstore',text)
            self.assertIn('local function _Bs',text)
            self.assertNotIn('local function _Bg',text)
            source='local function pass(...)return ... end;local t={pass(7,nil,false,nil)};print(t[1],t[2],t[3],t[4])'
            _,texts=self.compare(source,version)
            self.assertIn('local function _Bg',texts['f0'])
            source='local function f('+','.join(f'p{i}' for i in range(64))+')return p0,p63 end;f('+','.join(str(i) for i in range(64))+');print("done")'
            vm,texts=self.compare(source,version)
            self.assertGreater(vm.last_lowered_ir.backend_data['optimization'].get('frame_setters_elided',0),0)
            for frame in vm.last_lowered_ir.backend_data['bare_frame_plans']:
                text=texts[frame['function']]
                if '_Bstore(' not in text and '_Bfixed(' not in text:
                    self.assertNotIn('local function _Bs',text)

    def test_chunked_result_stores_keep_counts_nil_padding_and_shrinking_tops(self):
        for version in ('5.1','5.3'):
            for count in (0,3,16,33,64,129):
                with self.subTest(version=version,count=count):
                    arguments=','.join('nil' if i%3==0 else str(i) for i in range(1,count+1))
                    source='''local function values(...)return ... end
local function packet(...)return {n=select('#',...),...} end
local function run(...)return packet(values(...))end
local value=run('''+arguments+''')
print(value.n,value[1],value[3],value['''+str(count)+'''])
local empty=run();print(empty.n,empty[1])
'''
                    names=','.join(f'v{i}' for i in range(64))
                    source+='local '+names+'=values(7,nil,false);print(v0,v1,v2,v63)'
                    vm,_=self.compare(source,version)
                    self.assertEqual(1,vm.last_lowered_ir.backend_data['optimization']['shared_result_store_helpers'])

    def test_chunked_result_stores_preserve_captured_cells_and_collection(self):
        names=','.join(f'v{i}' for i in range(64))
        source='''local unpack=table.unpack or unpack
local weak=setmetatable({},{__mode='v'});local objects={};local keep
for i=1,64 do objects[i]={i};weak[i]=objects[i]end
local function values(...)return ... end
do local '''+names+'''=values(unpack(objects,1,64))
 keep=function()return v0,v63 end;objects=nil
 collectgarbage('collect');assert(weak[1]~=nil and weak[32]~=nil)
end
collectgarbage('collect');collectgarbage('collect')
assert(weak[32]==nil);local first,last=keep();assert(first[1]==1 and last[1]==64)
first=nil;last=nil;keep=nil
collectgarbage('collect');collectgarbage('collect');print(weak[1]==nil,weak[64]==nil)'''
        for version in ('5.1','5.3'):
            self.compare(source,version,protected=True)

    def compare(self,source,version='5.3',**kwargs):
        output,vm,texts=build(source,version,**kwargs)
        self.assertEqual(execute(version,source),execute(version,output))
        return vm,texts

    def compare_frame_allocation(self,source,version,**kwargs):
        vm,texts=self.compare(source,version,**kwargs)
        allocate=bare_registers.allocate
        with patch.object(bare_registers,'allocate',lambda e:allocate(e,expand=False)):
            before,_=self.compare(source,version,**kwargs)
        def guards(lowered):
            return [(f.id,i.metadata.get('guard_event'),i.metadata.get('guard_proof'),i.metadata['bare_call'])
                for f in lowered.semantic_ir.functions() if not f.debug_metadata.get('security_owned')
                for b in f.blocks for i in b.instructions if i.metadata.get('bare_call',())[0:1]==('guard',)]
        self.assertEqual(guards(before.last_lowered_ir),guards(vm.last_lowered_ir))
        for frame in vm.last_lowered_ir.backend_data['bare_frame_plans']:
            self.assertLessEqual(frame['local_prefix'],frame['dynamic_start'])
            if frame['local_prefix']>frame['initial_prefix']:
                self.assertLessEqual(frame['locals'],frame['local_budget'])
        return vm,texts

    @staticmethod
    def live_frame(count):
        return ('local '+','.join('v'+str(i) for i in range(count))+'='+
                ','.join(str(i+1) for i in range(count))+';local n=0;for k=1,8 do n=n+'+
                '+'.join('v'+str(i) for i in range(count))+' end;print(n,v0,v'+str(count-1)+')')

    def test_native_prefix_expands_with_physical_budget(self):
        for version in ('5.1','5.3'):
            vm,texts=self.compare_frame_allocation(self.live_frame(70),version,protected=True)
            frame=next(p for p in vm.last_lowered_ir.backend_data['bare_frame_plans'] if p['function']=='f0')
            self.assertGreater(frame['local_prefix'],48)
            self.assertFalse(frame['spill'])
            self.assertNotIn('_BS',texts['f0'])
            self.assertGreater(vm.last_lowered_ir.backend_data['optimization']['native_registers_promoted'],0)

    def test_native_prefix_falls_back_before_lua_limits(self):
        for version in ('5.1','5.3'):
            vm,_=self.compare_frame_allocation(self.live_frame(170),version,protected=True)
            frame=next(p for p in vm.last_lowered_ir.backend_data['bare_frame_plans'] if p['function']=='f0')
            self.assertGreater(frame['local_prefix'],48)
            self.assertTrue(frame['spill'])
            self.assertLessEqual(frame['locals'],frame['local_budget'])

    def test_large_logical_prefix_can_reuse_few_physical_locals(self):
        count=170
        source=('local '+','.join('v'+str(i) for i in range(count))+'='+
                ','.join(str(i+1) for i in range(count))+';print(v0,v169)')
        for version in ('5.1','5.3'):
            vm,_=self.compare_frame_allocation(source,version,protected=True)
            frame=next(p for p in vm.last_lowered_ir.backend_data['bare_frame_plans'] if p['function']=='f0')
            self.assertGreater(frame['local_prefix'],frame['local_budget'])
            self.assertLessEqual(frame['locals'],frame['local_budget'])
            self.assertFalse(frame['spill'])

    def test_expanded_frame_with_output_transforms_and_protected_junk(self):
        from run_bare_flow_regression import build as build_flow
        source=self.live_frame(70)
        passes=('strip_info','function_obf','rename_obf','localize_globals','string_encode','minify')
        for version in ('5.1','5.3'):
            # The existing 5.1 localizer uses _ENV when new globals remain
            # after function_obf. Both frame layouts fail without that host
            # binding; exercise the ordinary 5.1 passes independently of it.
            target_passes=tuple(p for p in passes if version!='5.1' or p!='localize_globals')
            self.compare_frame_allocation(source,version,protected=True,passes=target_passes)
            output,vm,rendered=build_flow(source,version,extra={'junk_instructions':True,'junk_rate':1.0})
            self.assertEqual(execute(version,source),execute(version,output))
            data=vm.last_lowered_ir.backend_data
            expected={i.id for f in data['bare_emission_ir'].functions() for b in f.blocks for i in b.instructions
                      if i.metadata.get('protection_origin')=='junk'}
            self.assertEqual(expected,rendered)
            frames={p['function']:p for p in data['bare_frame_plans']}
            for f in data['bare_emission_ir'].functions():
                mapping=dict(frames[f.id]['register_map'])
                for b in f.blocks:
                    for ins in b.instructions:
                        if ins.metadata.get('protection_origin')=='junk':
                            for operand in ins.operands:
                                if operand.kind=='register' and operand.value in mapping:
                                    self.assertEqual(operand.value,mapping[operand.value])

    def test_expanded_frame_preserves_capture_close_and_weak_roots(self):
        prefix=self.live_frame(70)
        source=prefix+'''
local weak=setmetatable({},{__mode='v'});local saved={}
for i=1,3 do
 do local object={n=i};weak[1]=object
  saved[i]=function()return object.n,v69 end
  collectgarbage('collect');assert(weak[1]~=nil)
 end
end
print(saved[1](),saved[3]());saved=nil
collectgarbage('collect');collectgarbage('collect');assert(weak[1]==nil)
local function show(...)print(select('#',...),...)end
local function values()return 7,nil,false,nil end
show(values());print(v0,v69)'''
        for version in ('5.1','5.3'):
            self.compare_frame_allocation(source,version,protected=True)

    def test_expanded_frame_reserves_long_call_temporaries(self):
        count=80
        source=self.live_frame(count)+'''
local function sink(...)return select('#',...)end
local n=sink('''+','.join('v'+str(i%count) for i in range(160))+''')
print(n,v0,v79)'''
        for version in ('5.1','5.3'):
            self.compare_frame_allocation(source,version)

    def test_parameter_storage_stays_within_native_local_budget(self):
        for count in (100,127,128):
            params=','.join('p'+str(i) for i in range(count))
            source=('local function f('+params+')local function get()return p'+str(count-1)+
                    ' end;return p0,get()end;print(f('+','.join(str(i) for i in range(count))+'))')
            for version in ('5.1','5.3'):
                self.compare_frame_allocation(source,version)

    def test_expanded_frames_keep_immediate_host_tamper_detection(self):
        from run_source_protection_regression import run
        count=70
        source=('local '+','.join('v'+str(i) for i in range(count))+'='+
                ','.join(str(i+1) for i in range(count))+';local n=host();AFTER=true;print(n+'+
                '+'.join('v'+str(i) for i in range(count))+')')
        allocate=bare_registers.allocate
        for version in ('5.1','5.3'):
            for expanded in (False,True):
                with patch.object(bare_registers,'allocate',lambda e:allocate(e,expand=expanded)):
                    output,_,_=build(source,version,protected=True,passes=('strip_info','rename_obf','minify'))
                for mutation in ("string.byte=function()return 0 end", "debug.sethook(function()end,'',100)"):
                    setup=('AFTER=false;function host()'+mutation+';return 7 end').encode()
                    observe=b"local ok=pcall(assert((loadstring or load)(source)));debug.sethook();return ok,AFTER"
                    self.assertEqual((False,False),run(version,output,setup,observe))

    def test_reachability_keeps_original_proof_and_reachable_guards(self):
        source='local function f(a)return a+7 end;print(f(3))'
        for version in ('5.1','5.3'):
            vm,_=self.compare(source,version,protected=True)
            lowered=vm.last_lowered_ir
            protect(lowered.semantic_ir,lowered.protection_plan)
            view=lowered.backend_data['bare_emission_ir'];validate_semantic_ir(view)
            self.assertGreater(lowered.backend_data['optimization']['unreachable_blocks'],0)
            originals={f.id:f for f in lowered.semantic_ir.functions()}
            for function in view.functions():
                old=originals[function.id]
                blocks={b.id:b for b in old.blocks};pending=[old.blocks[0].id];seen=set()
                while pending:
                    key=pending.pop()
                    if key in seen:continue
                    seen.add(key);pending.extend(blocks[key].successors)
                self.assertEqual(seen,{b.id for b in function.blocks})
                for block in function.blocks:
                    self.assertEqual(blocks[block.id].instructions,block.instructions)

    def test_scratch_tables_follow_real_use(self):
        source='local function f(a,b)local c=a+b;return c end;print(f(3,4))'
        for version in ('5.1','5.3'):
            for protected in (False,True):
                vm,texts=self.compare(source,version,protected=protected)
                child=vm.last_lowered_ir.semantic_ir.root.children[0]
                self.assertNotRegex(texts[child.id],r'\b_BX\b')
                self.assertGreater(vm.last_lowered_ir.backend_data['optimization']['scratch_tables_elided'],0)

    def test_dynamic_tail_retains_static_prefix_and_nil_counts(self):
        source='''local function values(a)return a,nil,false,nil end
local total=0;for i=1,20 do total=total+i end
local function show(...)print(select('#',...),...)end
show(values(total));show(values(3));print(total)'''
        for version in ('5.1','5.3'):
            vm,_=self.compare(source,version)
            frames=vm.last_lowered_ir.backend_data['bare_frame_plans']
            prefix=[p for p in frames if p['dynamic'] and p['locals']>0]
            self.assertTrue(prefix)
            self.assertTrue(all(p['locals']<=p['dynamic_start'] for p in prefix))

    def test_open_spans_use_private_storage_without_losing_nil_counts(self):
        source='''local function values(...)return ...end
local function show(...)print(select('#',...),...)end
local function forward(...)show(...);return values(...)end
show(forward());show(forward(nil));show(forward(7,nil,false,nil))
local function suspend(...)coroutine.yield(...);return ...end
local co=coroutine.create(suspend)
show(coroutine.resume(co,7,nil,false,nil));show(coroutine.resume(co))
local t={values(7,nil,false,nil)};print(t[1],t[2],t[3],t[4])'''
        for version in ('5.1','5.3'):
            vm,texts=self.compare(source,version,protected=True)
            self.assertGreater(vm.last_lowered_ir.backend_data['optimization'].get('dynamic_value_copies_elided',0),0)
            self.assertTrue(any('_BS,' in text and '_BT)' in text for text in texts.values()))

    def test_open_spans_keep_overlapping_capture_cells(self):
        # Open calls below a later captured local must still use _Bg. They may
        # cross that slot at runtime, even when the observed result is short.
        source='''local saved
local function f(...)
 do local a,b,c=7,nil,9
  saved=function()return a,b,c end
 end
 return ...
end
local function show(...)print(select('#',...),...)end
show(f(3,nil,false,nil));show(saved());show(f());show(saved())'''
        for version in ('5.1','5.3'):
            _,texts=self.compare(source,version,protected=True)
            self.assertTrue(any('local function _Bvalues(a,n) local t={}' in text
                                and 'local _BC=' in text for text in texts.values()))

    def test_captured_prefix_and_tail_close_reentry_and_coroutines(self):
        source='''local function factory(...)
local args={...};local value={n=7}
local function get()return value.n,args[1] end
local function change(n)value={n=n} end
return get,change end
local a,b=factory(31,nil,9);local c,d=factory(41,nil,8)
b(12);d(22);print(a());print(c())
local saved={};for i=1,4 do local value={n=i};saved[i]=function()return value.n end end
print(saved[1](),saved[4]())
local function pause(...)
local args={...};local value=args[1];coroutine.yield(value,nil)
local function get()return value end;value=value+3;return get(),nil,args[3],nil end
local co=coroutine.create(pause)
local function show(...)print(select('#',...),...)end
show(coroutine.resume(co,7,nil,9));show(coroutine.resume(co))'''
        for version in ('5.1','5.3'):
            for seed in (1811,1812):self.compare(source,version,seed=seed)

    def test_primitive_expressions_and_parallel_assignments(self):
        source='''local total=0;for i=1,20 do local a=i+3;local b=a*5;total=total+b end
print(total)'''
        for version in ('5.1','5.3'):
            vm,texts=self.compare(source,version)
            stats=vm.last_lowered_ir.backend_data['optimization']
            self.assertGreater(stats.get('expression_fusions',0),0)
            self.assertGreater(stats.get('primitive_clears_elided',0),0)
            self.assertGreater(stats.get('parallel_assignments',0)+stats.get('parallel_rejections',0),0)
            # Lua itself needs extra MOVEs for this ordinary local grouping.
            # A blind Prometheus-style merge would increase interpreter work.
            self.assertGreater(stats.get('parallel_rejections',0),0)
            protected,_=self.compare(source,version,protected=True)
            data=protected.last_lowered_ir.backend_data
            self.assertGreater(data['optimization'].get('expression_fusions',0),0)
            for info in data['bare_facts'].values():
                for instruction in info.producers.values():
                    if instruction.operation=='CALL':
                        self.assertTrue(info.effects[instruction.id].may_call)
                        self.assertFalse(info.effects[instruction.id].pure)

    def test_dependencies_metamethods_errors_and_weak_lifetimes(self):
        source='''local trace={};local value=1
local object=setmetatable({},{__add=function(a,b)trace[#trace+1]='add';value=value+1;return b+value end})
local a=object+3;local b=object+a;print(a,b,value,table.concat(trace,','))
local x,y=1,2;x=x+y;y=x*3;print(x,y)
local weak=setmetatable({},{__mode='v'})
do local t={};weak[1]=t;local n=not t;t=nil;n=not n;print(n) end
collectgarbage('collect');collectgarbage('collect');print(weak[1]==nil)
local function fault()trace[#trace+1]='fault';error('expected',0)end
local ok,err=pcall(function()local x=fault()+1;trace[#trace+1]='after';return x end)
print(ok,err,table.concat(trace,','))'''
        for version in ('5.1','5.3'):
            for protected in (False,True):self.compare(source,version,protected=protected)

    def test_wide_open_frames_and_captured_cells(self):
        names=','.join(f'v{i}' for i in range(80))
        source=('local function values()return '+','.join(str(i) if i%3 else 'nil' for i in range(80))+' end\n'
            'local '+names+'=values();local function get()return v1,v79 end;print(get())\n'
            'local function show(...)print(select("#",...),...)end;show(values())')
        for version in ('5.1','5.3'):self.compare(source,version)

    def test_generated_programs_and_determinism(self):
        for version in ('5.1','5.3'):
            for seed in (1813,1814,1815):self.compare(generated_source(seed),version,seed=seed,protected=True)
        source='local n=0;for i=1,8 do n=n+i*3 end;print(n)'
        first,_,_=build(source,passes=('rename_obf','minify'))
        second,_,_=build(source,passes=('rename_obf','minify'))
        self.assertEqual(first,second)

    def test_numeric_types_zero_sign_and_throwing_boundaries(self):
        common='''local sum=-0.0
for i=1,20 do local a=i+0.5;local b=a*1.25;sum=sum+b end
local a=-0.0;local b=a*2.0;print(sum,1/b,1/(a+0.0))
local trace={};local function mark()trace[#trace+1]='after';return 2 end
local ok=pcall(function()local x=error('stop',0);return x+mark() end)
print(ok,#trace)'''
        for version in ('5.1','5.3'):self.compare(common,version)
        integer='''local n=0;for i=1,20 do local x=i+9223372036854775807;local y=x*3;n=n+y end
print(n,math.type(n));local ok=pcall(function()return 1//0 end);print(ok)'''
        self.compare(integer)

    def test_source_merge_output_literals_and_packer(self):
        source='''local function first(a,b)local x=a+b;return x,nil,b,nil end
local function second(a,b)local x=a*b;return x,nil,b,nil end
print(first(3,4));print(second(5,6))'''
        for pack in (False,True):
            random.seed(1816)
            pipeline=build_pipeline_from_config({'passes':['function_obf','vm']+(['pack'] if pack else []),
                'vm_options':{**options('bare'),'integrity_constants':True,'integrity_constant_rate':1.0},
                'function_obf_options':{'inline':False,'junk':False},
                'vm_output_passes':['strip_info','rename_obf','number_obf','meme_strings','minify'],
                'packer_output_passes':['minify'],'signature':{'mode':'none'}},Pipeline,show_header=False)
            self.assertEqual(execute('5.3',source),execute('5.3',pipeline.run(source)))


if __name__=='__main__':unittest.main()
