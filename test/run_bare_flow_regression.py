"""Bare chains, physical registers, branch forms and inner-loop semantics."""
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch
import random
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'test')]
from obfuscator.vm import VMPass
from obfuscator.vm.targets.profile import TargetProfile
from obfuscator.vm.backends import bare_flow,bare_registers
from obfuscator.vm.backends.bare_emitter import Function,literal
from run_vm_backend_regression import options
from run_cross_backend_generated_regression import execute,generated_source


def build(source,version='5.3',seed=1911,extra=None,passes=(),baseline=False,trace=False):
    random.seed(seed)
    vm=VMPass(target=TargetProfile(version,'bare'),vm_options={**options('bare'),**(extra or {})},
              vm_output_passes=list(passes))
    original=Function.instruction
    rendered_junk=set()
    def instruction(emitter,ins,block):
        text=original(emitter,ins,block)
        if ins.metadata.get('protection_origin')=='junk':rendered_junk.add(ins.id)
        call=ins.metadata.get('bare_call')
        if trace and call and call[0]=='guard':
            tag=emitter.function.id+':'+ins.id+':'+str(call[1])
            text=('do local _Bguard_trace=_BE["TRACE"];if _Bguard_trace then '
                  '_Bguard_trace[#_Bguard_trace+1]='+literal(tag)+' end end\n')+text
        return text
    with ExitStack() as stack:
        stack.enter_context(patch.object(Function,'instruction',instruction))
        if baseline:
            stack.enter_context(patch.object(bare_registers,'allocate',lambda e:{i:i for i in range(e.local_count)}))
            stack.enter_context(patch.object(bare_flow,'transform',lambda *args:None))
            stack.enter_context(patch.object(bare_flow,'_branch_forms',lambda version:()))
        output=vm.run(source)
    return output,vm,rendered_junk


class BareFlowTests(unittest.TestCase):
    def compare(self,source,version='5.3',**kwargs):
        output,vm,junk=build(source,version,**kwargs)
        self.assertEqual(execute(version,source),execute(version,output))
        return vm,junk

    def test_chains_preserve_segments_and_admit_compiler_cost(self):
        source='local total=INPUT or 0;'+''.join(f'total=total+{i%17};' for i in range(180))+'print(total)'
        for version in ('5.1','5.3'):
            vm,_=self.compare(source,version)
            data=vm.last_lowered_ir.backend_data
            self.assertGreater(data['optimization'].get('chain_links_elided',0),0)
            for plan in data['bare_flow_plans']:
                inventory=[source for group in plan['groups'] for source in group['sources']]
                self.assertEqual(list(range(plan['segments_before'])),sorted(inventory))
                if plan['admitted']:
                    self.assertLessEqual(plan['source_bytes_after'],plan['source_bytes_before'])
                    self.assertLessEqual(plan['compiler_after'],plan['compiler_before'])

    def test_physical_reuse_and_copy_lifetime(self):
        source='''local n=0;while n<8 do n=n+1 end
local function pair(a,b)return a,b,nil end
local x,y=pair({n=n},{n=3});print(x.n,y.n,n)
local weak=setmetatable({},{__mode='v'})
do local t={};weak[1]=t;local value=t;print(type(value));t=nil;value=nil end
collectgarbage('collect');collectgarbage('collect');print(weak[1]==nil)'''
        for version in ('5.1','5.3'):
            for seed in (1911,1912):
                vm,_=self.compare(source,version,seed=seed)
                stats=vm.last_lowered_ir.backend_data['optimization']
                self.assertGreater(stats.get('native_slots_elided',0),0)
                self.assertGreater(stats.get('copies_elided',0),0)
                for frame in vm.last_lowered_ir.backend_data['bare_frame_plans']:
                    self.assertLessEqual(frame['locals'],frame['local_prefix'])

    def test_branch_forms_truthiness_comparisons_and_nan(self):
        source='''local function choose(v)if v then return 1 else return 2 end end
print(choose(false),choose(nil),choose(0),choose(''),choose({}))
local calls=0;local mt={__lt=function(a,b)calls=calls+1;return a.n<b.n end,
__le=function(a,b)calls=calls+1;return a.n<=b.n end,__eq=function(a,b)calls=calls+1;return a.n==b.n end}
local a,b=setmetatable({n=3},mt),setmetatable({n=5},mt)
if a<b then print('lt')else print('bad')end
if not(a<=b)then print('bad')else print('le')end
print(a==b,calls)
local nan=0/0;if nan<1 then print('bad')else print('nan')end'''
        for version in ('5.1','5.3'):
            vm,_=self.compare(source,version)
            self.assertGreater(vm.last_lowered_ir.backend_data['optimization'].get('compact_branches',0),0)
            self.assertTrue(bare_flow._branch_forms(version))

    def test_for_while_repeat_generic_and_nested_loops(self):
        source='''local n=0;while n<4 do n=n+1 end
repeat n=n-1 until n<=1
for i='4','1','-1'do n=n+i end
local values={2,3,5};for k,v in ipairs(values)do n=n+k*v end
for i=1,3 do for j=1,4 do n=n+i*j end end
print(n)'''
        for version in ('5.1','5.3'):
            for seed in (1913,1914):
                vm,_=self.compare(source,version,seed=seed)
                self.assertGreater(vm.last_lowered_ir.backend_data['optimization'].get('inner_loops',0),0)

    def test_loop_captures_yields_reentry_errors_and_collection(self):
        source='''local weak=setmetatable({},{__mode='v'});local saved={}
for i=1,4 do local value={n=i};weak[i]=value;saved[i]=function()return value.n end end
print(saved[1](),saved[4]());saved[2]=nil
collectgarbage('collect');collectgarbage('collect');print(weak[2]==nil,weak[1]~=nil,saved[1]())
local function run(base)
 local n=0;while n<3 do n=n+1;coroutine.yield(base+n,nil)end;return base+n,nil end
local a,b=coroutine.create(function()return run(10)end),coroutine.create(function()return run(20)end)
local function show(...)print(select('#',...),...)end
for i=1,4 do show(coroutine.resume(a));show(coroutine.resume(b))end
local n=0;local ok,err=pcall(function()while n<5 do n=n+1;if n==3 then error('stop',0)end end end)
print(ok,err,n)'''
        for version in ('5.1','5.3'):self.compare(source,version)

    def test_unused_source_local_stays_resident_during_gc(self):
        source='''local weak=setmetatable({},{__mode='v'});local saved={}
for i=1,4 do local value={n=i};weak[i]=value;saved[i]=function()return value.n end end
print(saved[1](),saved[4]());saved[2]=nil
collectgarbage('collect');collectgarbage('collect');print(weak[2]==nil,weak[1]~=nil)'''
        for version in ('5.1','5.3'):self.compare(source,version)

    def test_multi_instruction_initializers_and_iterator_gc(self):
        source='''local weak=setmetatable({},{__mode='v'});local saved={value={n=7}}
weak[1]=saved;collectgarbage('collect');print(weak[1]~=nil)
local n=0;local function iter()
n=n+1;collectgarbage('collect');if n>1 then print(weak[2]==nil)end
if n<=2 then return n end end
for k in iter do local value={n=k};weak[2]=value end'''
        for version in ('5.1','5.3'):self.compare(source,version)

    def test_scope_exit_releases_on_branches_and_call_initializers(self):
        source='''local weak=setmetatable({},{__mode='v'})
local function create()local value={n=7};weak[1]=value;return value end
local unused=create()
collectgarbage('collect');print(weak[1]~=nil)
do local value={n=8};weak[2]=value;local n=1;n=n+3 end
collectgarbage('collect');collectgarbage('collect');print(weak[2]==nil)
local n=0;while n<3 do local value={n=n};weak[3]=value;n=n+1;if n==2 then break end end
collectgarbage('collect');collectgarbage('collect');print(weak[3]==nil)'''
        for version in ('5.1','5.3'):self.compare(source,version)

    def test_guard_trace_order_is_unchanged(self):
        source='''TRACE={};local n=0
for i=1,3 do n=n+i end
while n<8 do n=n+1 end
repeat n=n-1 until n<=5
if n==5 then n=n+10 end;print(n)'''
        for version in ('5.1','5.3'):
            for extra in ({},{'junk_instructions':True,'junk_rate':1.0}):
                before,_,_=build(source,version,baseline=True,trace=True,extra=extra)
                after,_,_=build(source,version,trace=True,extra=extra)
                def observed(output):
                    # Same-line embedding preserves finalized source line binding.
                    return 'local function _observe(...) '+output+' end;_observe();print(table.concat(TRACE,"|"))'
                self.assertEqual(execute(version,observed(before)),execute(version,observed(after)))

    def test_explicit_junk_and_morph_are_not_erased(self):
        source='local total=0;for i=1,8 do total=total+i*3 end;print(total)'
        for version in ('5.1','5.3'):
            vm,rendered=self.compare(source,version,extra={'junk_instructions':True,'junk_rate':1.0})
            data=vm.last_lowered_ir.backend_data
            expected={i.id for f in data['bare_emission_ir'].functions() for b in f.blocks for i in b.instructions
                      if i.metadata.get('protection_origin')=='junk'}
            self.assertEqual(expected,rendered)
            self.assertTrue(expected)
            self.assertEqual(0,data['optimization'].get('inner_loops',0))
            frames={p['function']:p for p in data['bare_frame_plans']}
            for f in data['bare_emission_ir'].functions():
                mapping=dict(frames[f.id]['register_map'])
                for b in f.blocks:
                    for i in b.instructions:
                        if i.metadata.get('protection_origin')=='junk':
                            for o in i.operands:
                                if o.kind=='register' and o.value in mapping:self.assertEqual(o.value,mapping[o.value])
        vm,_=self.compare(source,extra={'ir_mba_rate':1.0,'ir_test_set_rate':1.0,'ir_tail_duplication_rate':1.0})
        self.assertEqual(0,vm.last_lowered_ir.backend_data['optimization'].get('inner_loops',0))

    def test_multiple_entry_cfg_and_break_keep_dispatcher(self):
        source='''local n=0;if INPUT then goto body end
::check:: if n>=4 then goto finish end
::body:: n=n+1;goto check
::finish::print(n)'''
        vm,_=self.compare(source)
        self.assertEqual(0,vm.last_lowered_ir.backend_data['optimization'].get('inner_loops',0))
        source='local n=0;while n<8 do n=n+1;if n==3 then break end end;print(n)'
        for version in ('5.1','5.3'):self.compare(source,version)

    def test_generated_programs_literal_passes_and_determinism(self):
        for version in ('5.1','5.3'):
            for seed in (1915,1916,1917):self.compare(generated_source(seed),version,seed=seed,
                extra={'integrity_constants':True,'integrity_constant_rate':1.0})
        source='local n=0;for i=1,10 do n=n+i end;print(n)'
        a,_,_=build(source,passes=('rename_obf','number_obf','meme_strings','minify'))
        b,_,_=build(source,passes=('rename_obf','number_obf','meme_strings','minify'))
        self.assertEqual(a,b)
        self.assertEqual(execute('5.3',source),execute('5.3',a))


if __name__=='__main__':unittest.main()
