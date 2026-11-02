"""Guard scan equivalence, conservative IR call proofs and sensitive boundaries."""
from pathlib import Path
from dataclasses import replace
import random
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'test')]
from lupa.lua51 import LuaRuntime as Lua51
from lupa.lua53 import LuaRuntime as Lua53
from obfuscator.vm.host_guards import GUARD_SOURCE
from obfuscator.vm import VMPass
from obfuscator.vm.targets.profile import TargetProfile
from obfuscator.vm.guard_policy import internal_calls
from obfuscator.toolchain import LuaToolchain
from obfuscator.vm.ir import validate_semantic_ir
from run_vm_backend_regression import options
from run_source_protection_regression import run,rejected


def build(source,version):
    random.seed(2931)
    vm=VMPass(target=TargetProfile(version,'bare'),vm_options=options('bare'),
        vm_output_passes=['strip_info','rename_obf','minify'])
    return vm,vm.run(source)


def guard_kernel(runtime,size,bindings=False):
    source='''local bank,records,log={},{},{}
for i=1,SIZE do bank[i]=function()end;records[i]={bank,i,bank[i]}end
local trusted,bindings=RECORDS
local ticks,failed=0,false
local function fail()failed=true;error(nil,0)end
local function raw(t,k)log[#log+1]=k;return rawget(t,k)end
local same=rawequal
local function hook0()return nil,'',0 end
local S={}
GUARD
return S.guard,function(i)bank[i]=function()end end,function()return failed end,
function()return log end'''
    source=source.replace('SIZE',str(size)).replace('RECORDS','{},records' if bindings else 'records,{}').replace('GUARD',GUARD_SOURCE)
    return runtime.execute(source)


class GuardPolicyTests(unittest.TestCase):
    def test_original_ir_proofs_reject_unknowns_and_unreachable_calls(self):
        cases=(
            ('local function f(g)local n=g(3);return n end;return f',0),
            ('local f;if CHOICE then f=function()return 3 end else f=host end;local n=f();return n',0),
            ('local f=function()return 3 end;local function setter(v)f=v end;setter(host);local n=f();return n',1),
            ('local function f(...)return ...end;local n=f(...);return n',0),
            ('local n=tonumber("3");return n',0),
            ('local function f()return 3,4 end;local x,y=f();local function g()return y end;return x,g',0),
            ('local function f(a)return a end;local '+','.join('a'+str(i) for i in range(50))+';local n=f(3);return n,a0,a49',0))
        for version in ('5.1','5.3'):
            adapter=TargetProfile(version,'bare').adapter()
            tools=LuaToolchain(lua_version=version)
            for source,count in cases:
                ir=adapter.build_ir(adapter.compile(source,tools))
                self.assertEqual(count,sum(len(internal_calls(f,version)) for f in ir.functions()))
            ir=adapter.build_ir(adapter.compile('local function f(a)return a+1 end;local n=f(3);return n',tools))
            f=ir.root
            call=next(i for b in f.blocks for i in b.instructions if i.operation=='CALL')
            returned=next(i for b in f.blocks for i in b.instructions if i.operation=='RETURN')
            dead=replace(f.blocks[-1],id=f.id+':unreachable',successors=(),instructions=(
                replace(call,id=call.id+':unreachable'),replace(returned,id=returned.id+':unreachable')))
            amended=replace(ir,root=replace(f,blocks=(*f.blocks,dead)))
            validate_semantic_ir(amended)
            self.assertNotIn(call.id+':unreachable',internal_calls(amended.root,version))

    def test_order_tail_and_every_record_mutation(self):
        for runtime_type in (Lua51,Lua53):
            for size in range(10):
                for bindings in (False,True):
                    runtime=runtime_type(unpack_returned_tuples=True)
                    guard,mutate,failed,log=guard_kernel(runtime,size,bindings)
                    self.assertIsNone(guard(True))
                    if not bindings:self.assertEqual(list(range(1,size+1)),list(log().values()))
                    for index in range(1,size+1):
                        runtime=runtime_type(unpack_returned_tuples=True)
                        guard,mutate,failed,log=guard_kernel(runtime,size,bindings)
                        mutate(index)
                        self.assertEqual((False,None),runtime.eval('function(f)return pcall(f,true)end')(guard))
                        self.assertTrue(failed())
                        if not bindings:self.assertEqual(list(range(1,index+1)),list(log().values()))

    def test_periodic_detection_bound_and_latched_failure(self):
        for runtime_type in (Lua51,Lua53):
            runtime=runtime_type(unpack_returned_tuples=True)
            guard,mutate,failed,_=guard_kernel(runtime,5)
            mutate(5)
            invoke=runtime.eval('function(f)return pcall(f,false)end')
            for _ in range(126):self.assertTrue(invoke(guard))
            self.assertEqual((False,None),invoke(guard))
            self.assertTrue(failed())
            self.assertEqual((False,None),invoke(guard))

    def test_reference_comparison_never_calls_guest_equality(self):
        for runtime_type in (Lua51,Lua53):
            runtime=runtime_type(unpack_returned_tuples=True)
            text='''local called=0;local mt={__eq=function()called=called+1;return true end}
local expected=setmetatable({},mt);local bank={value=setmetatable({},mt)}
local trusted={{bank,'value',expected}};local bindings={};local ticks,failed=0,false
local raw,same=rawget,rawequal;local function hook0()return nil,'',0 end
local function fail()failed=true;error(nil,0)end;local S={}
GUARD
local ok=pcall(S.guard,true);return ok,called,failed'''.replace('GUARD',GUARD_SOURCE)
            self.assertEqual((False,0,True),runtime.execute(text))

    def test_proved_internal_calls_keep_full_callee_and_terminal_checks(self):
        source='local function f(a)return a+1 end;local n=f(3);return n'
        for version in ('5.1','5.3'):
            vm,output=build(source,version)
            self.assertEqual(4,run(version,output))
            guards=[i for f in vm.last_lowered_ir.semantic_ir.functions() for b in f.blocks for i in b.instructions
                    if i.metadata.get('bare_call',())[0:1]==('guard',)]
            internal=[i for i in guards if i.metadata.get('guard_proof')=='generated-closure']
            self.assertEqual({'call-before','call-after'},{i.metadata['guard_event'] for i in internal})
            self.assertTrue(all(i.metadata['bare_call']==('guard',False) for i in internal))
            self.assertTrue(all(i.metadata['bare_call']==('guard',True) for i in guards
                if i.metadata.get('guard_event') in ('entry','return','tail_call')))

    def test_unknown_captured_open_and_native_calls_remain_sensitive(self):
        cases=(
            'local function f(g)local n=g(3);return n end;return f',
            'local f;if CHOICE then f=function()return 3 end else f=host end;local n=f();return n',
            'local f=function()return 3 end;local function setter(v)f=v end;setter(host);local n=f();return n',
            'local function f(...)return ...end;local n=f(...);return n',
            'local n=tonumber("3");return n')
        for version in ('5.1','5.3'):
            for source in cases:
                vm,_=build(source,version)
                for f in vm.last_lowered_ir.semantic_ir.functions():
                    for b in f.blocks:
                        for i in b.instructions:
                            if (i.metadata.get('guard_event')=='call-before' and not i.metadata.get('guard_proof')
                                    and i.metadata.get('bare_call')):
                                self.assertEqual(('guard',True),i.metadata['bare_call'])
            # Explicitly inspect an ordinary closed native call.
            vm,_=build(cases[-1],version)
            guards=[i for f in vm.last_lowered_ir.semantic_ir.functions() for b in f.blocks for i in b.instructions
                    if i.metadata.get('guard_event')=='call-before' and i.metadata.get('bare_call')]
            self.assertTrue(guards)
            self.assertTrue(all(i.metadata['bare_call']==('guard',True) for i in guards))

    def test_unknown_callback_changes_detected_before_result_use(self):
        for version in ('5.1','5.3'):
            _,output=build('local function f()local n=host();return n end;local n=f();return n',version)
            rejected(version,output,b'host=function()string.byte=function()return 0 end;return 17 end')
            _,output=build('local ok=pcall(host);return 17',version)
            rejected(version,output,b'host=function()string.byte=function()return 0 end;error("stop",0)end')

    def test_sensitive_boundary_has_no_additional_guest_step_delay(self):
        for version in ('5.1','5.3'):
            _,output=build('local n=host();MARKER=1;return n',version)
            setup=b'MARKER=0;host=function()string.byte=function()return 0 end;return 17 end'
            call=b'local f=assert((loadstring or load)(source));local ok=pcall(f);return ok,MARKER'
            self.assertEqual((False,0),run(version,output,setup,call))
            _,output=build('return function()MARKER=1;return 9 end',version)
            setup=b'MARKER=0'
            call=b'''local f=assert((loadstring or load)(source))()
string.byte=function()return 0 end
local ok=pcall(f);return ok,MARKER'''
            self.assertEqual((False,0),run(version,output,setup,call))

    def test_coroutine_resume_checks_current_thread_hook(self):
        for version in ('5.1','5.3'):
            _,output=build('return function()coroutine.yield(7);return 9 end',version)
            call=b'''local f=assert((loadstring or load)(source))()
local co=coroutine.create(f);local ok,value=coroutine.resume(co);assert(ok and value==7)
debug.sethook(co,function()end,'',100)
local accepted=coroutine.resume(co);debug.sethook(co);return accepted'''
            self.assertFalse(run(version,output,call=call))


if __name__=='__main__':unittest.main()
