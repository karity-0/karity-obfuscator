"""Expression graph semantics, storage aliases, boundaries and compiler admission."""
from pathlib import Path
from unittest.mock import patch
from contextlib import ExitStack
import random,sys,unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'test')]
from obfuscator.vm import VMPass
from obfuscator.vm.targets.profile import TargetProfile
from obfuscator.vm.backends import bare_expressions
from obfuscator.vm.backends.bare_emitter import Function
from obfuscator.vm.protection import protect
from obfuscator.vm.ir import validate_semantic_ir
from run_cross_backend_generated_regression import execute,generated_source
from run_vm_backend_regression import options


def build(source,version,enabled=True,*,seed=519,extra=None,passes=()):
    random.seed(seed);vm=VMPass(target=TargetProfile(version,'bare'),
        vm_options={**options('bare'),**(extra or {})},vm_output_passes=list(passes))
    texts={};original=Function.source
    def capture(emitter):
        text=original(emitter)
        if not emitter.function.debug_metadata.get('security_owned'):texts[emitter.function.id]=text
        return text
    entropy=random.Random(seed)
    with ExitStack() as stack:
        stack.enter_context(patch.object(Function,'source',capture))
        stack.enter_context(patch('secrets.choice',entropy.choice))
        stack.enter_context(patch('os.urandom',entropy.randbytes))
        if enabled:output=vm.run(source)
        else:
            with patch.object(bare_expressions,'prepare',lambda e:None):output=vm.run(source)
    return output,vm,texts


class BareExpressionTests(unittest.TestCase):
    def compare(self,source,version,**kwargs):
        expected=execute(version,source);results=[]
        for enabled in (False,True):
            output,vm,texts=build(source,version,enabled,**kwargs)
            self.assertEqual(expected,execute(version,output),(version,enabled))
            protect(vm.last_lowered_ir.semantic_ir,vm.last_lowered_ir.protection_plan)
            validate_semantic_ir(vm.last_lowered_ir.semantic_ir)
            results.append((vm,texts))
        def guards(vm):
            return [(f.id,i.id,i.metadata['bare_call'],i.metadata.get('guard_event'))
                for f in vm.last_lowered_ir.semantic_ir.functions()
                for b in f.blocks for i in b.instructions if i.metadata.get('bare_call',())[0:1]==('guard',)]
        self.assertEqual(guards(results[0][0]),guards(results[1][0]))
        return results

    def test_nonadjacent_and_multiple_input_producers(self):
        sources=(
            'local n=0;for i=1,20 do local a=i+1;local gap=i+2;local b=a*3;n=n+b+gap end;print(n)',
            'local n=0;for i=1,20 do local a=i+1;local b=i+2;n=n+a*b end;print(n)')
        for version in ('5.1','5.3'):
            for source in sources:
                results=self.compare(source,version)
                data=results[1][0].last_lowered_ir.backend_data
                self.assertGreater(data['optimization'].get('expression_graph_regions',0),0)
                self.assertGreater(data['optimization'].get('nonadjacent_fusions',0),0)
                before={f['function']:f for f in results[0][0].last_lowered_ir.backend_data['bare_frame_plans']}
                for frame in data['bare_frame_plans']:
                    self.assertLessEqual(frame['locals'],before[frame['function']]['locals'])

    def test_common_subtrees_and_multiuse_results_are_not_duplicated(self):
        source='''local n=0;for i=1,20 do
local a=(i+1)*(i+3)+(i+1);local b=(i+1)*(i+3)+(i+1)
n=n+a+b end;print(n)'''
        for version in ('5.1','5.3'):
            results=self.compare(source,version)
            self.assertGreater(results[1][0].last_lowered_ir.backend_data['optimization'].get('common_expressions',0),0)
            self.assertEqual(1,results[1][1]['f0'].count('*'))
            from obfuscator.passes.function_costs import measure
            before=measure(results[0][1]['f0'],version=version)
            after=measure(results[1][1]['f0'],version=version)
            self.assertLess(after['total_instructions'],before['total_instructions'])
            multi='local n=0;for i=1,20 do local a=(i+1)*(i+3);n=n+a+a+a end;print(n)'
            results=self.compare(multi,version)
            self.assertEqual(1,results[1][1]['f0'].count('*'))

    def test_logical_overwrites_and_physical_slot_reuse(self):
        source='''local n=0;for i=1,20 do
local a=i+1;local x=a*3;a=i+9;local y=x+1;n=n+a+y
local p=i+1;local gap=i*11;local q=p*5;n=n+gap+q
local first=a*a;a=a+3;local second=a*a;n=n+first+second
end;print(n)'''
        for version in ('5.1','5.3'):
            for seed in (519,17,41):self.compare(source,version,seed=seed)

    def test_reference_overwrite_keeps_gc_release_point(self):
        source='''local weak=setmetatable({},{__mode='v'})
do local value={};weak[1]=value;value=3
 local gap=7;local result=value*5;local result2=result+gap
 collectgarbage('collect');collectgarbage('collect')
 assert(weak[1]==nil);print(result2)
end
local n=0;for i=1,10 do local x=i+1;local gap=i+2;n=n+x*3+gap end;print(n)'''
        for version in ('5.1','5.3'):self.compare(source,version)

    def test_compiler_failure_rejects_plan_without_changing_output(self):
        source='local n=0;for i=1,10 do local a=i+1;local gap=i+2;n=n+a*3+gap end;print(n)'
        for version in ('5.1','5.3'):
            before,_,_=build(source,version,False)
            with patch.object(bare_expressions,'_native_cost',lambda *args:None):
                after,_,_=build(source,version,True)
            self.assertEqual(before,after)

    def test_numeric_order_types_nan_zero_and_integer_wrap(self):
        source='''local zero=-0.0;local inf=1e999;local n=0.0
for i=1,10 do local a=zero*2.0;local gap=i+0.5;local b=a+0.0
 n=n+gap;print(1/a,1/b) end
local a=inf-inf;local b=inf-inf;print(a~=a,b~=b,n)'''
        for version in ('5.1','5.3'):self.compare(source,version)
        self.compare('''local n=0;local large=9223372036854775807
for i=1,10 do local a=i+large;local gap=i+3;local b=a*5;n=n+b+gap end
print(n,math.type(n))''','5.3')

    def test_effects_captures_errors_and_coroutines_are_boundaries(self):
        source='''local trace={};local held=1
local object=setmetatable({},{__add=function(a,b)held=held+1;trace[#trace+1]='add';return held+b end})
local n=0;for i=1,8 do local a=i+1;local gap=object+i;local b=a*3;n=n+b+gap end
local function read()return held end;print(n,read(),table.concat(trace,','))
local ok,e=pcall(function()local x=error('expected',0);held=99;return x end);print(ok,e,held)
local co=coroutine.create(function()local a=2;local b=a*3;coroutine.yield(b);a=5;return a*3 end)
print(coroutine.resume(co));print(coroutine.resume(co))'''
        for version in ('5.1','5.3'):self.compare(source,version)

    def test_guard_trace_is_identical(self):
        from run_bare_flow_regression import build as flow
        source='''TRACE={};local n=0;for i=1,8 do
local a=i+1;local gap=i+2;local b=a*3;n=n+b+gap end;print(n)'''
        for version in ('5.1','5.3'):
            with patch.object(bare_expressions,'prepare',lambda e:None):before,_,_=flow(source,version,trace=True)
            after,_,_=flow(source,version,trace=True)
            def observe(text):return 'local function run(...) '+text+' end;run();print(table.concat(TRACE,"|"))'
            self.assertEqual(execute(version,observe(before)),execute(version,observe(after)))

    def test_active_graph_keeps_immediate_tamper_rejection(self):
        from run_source_protection_regression import run
        source='''local n=0;for i=1,10 do
local a=(i+1)*(i+3);local b=(i+1)*(i+3);n=n+a+b end
host();AFTER=true;return n'''
        for version in ('5.1','5.3'):
            for enabled in (False,True):
                output,vm,_=build(source,version,enabled,passes=('strip_info','rename_obf','minify'))
                if enabled:self.assertGreater(vm.last_lowered_ir.backend_data['optimization'].get('common_expressions',0),0)
                for edit in ("string.byte=function()return 0 end", "debug.sethook(function()end,'',100)"):
                    setup=('AFTER=false;function host()'+edit+' end').encode()
                    observe=b"local ok=pcall(assert((loadstring or load)(source)));debug.sethook();return ok,AFTER"
                    self.assertEqual((False,False),run(version,output,setup,observe))

    def test_constant_recovery_junk_and_output_passes(self):
        source='local n=0;for i=1,10 do local a=i+1;local gap=i+2;local b=a*3;n=n+b+gap end;print(n)'
        for version in ('5.1','5.3'):
            self.compare(source,version,extra={'integrity_constants':True,'integrity_constant_rate':1.0},
                         passes=('strip_info','rename_obf','string_encode','minify'))
            self.compare(source,version,extra={'junk_instructions':True,'junk_rate':1.0,
                         'ir_mba_rate':1.0,'ir_test_set_rate':1.0})
            for seed in (271,811):self.compare(generated_source(seed),version,seed=seed)


if __name__=='__main__':unittest.main()
