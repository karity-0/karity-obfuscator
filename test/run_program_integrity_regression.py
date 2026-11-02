"""Build-bound program domains, real corruption, entry and periodic latency."""
from pathlib import Path
from unittest.mock import patch
import random
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'test')]
from obfuscator.vm import VMPass,program_integrity
from obfuscator.vm.targets.profile import TargetProfile
from run_vm_backend_regression import options
from run_source_protection_regression import run

SOURCE='''MARKER=1;local n=5;local function f(x)return n+x end
return function(x)return f(x)end'''


def build(version,backend,mutation='',late=False,guest=SOURCE,config=None):
    original=program_integrity.prepare
    def inject(source,layout,context,blob,**kwargs):
        result=original(source,layout,context,blob,**kwargs)
        export='''_ENV_NATIVE.PROGRAM_TEST_GUARD=function(force)return _PS_GUARD(force) end
_ENV_NATIVE.PROGRAM_TEST_COUNT=function()return __COUNT__ end
_ENV_NATIVE.PROGRAM_TEST_REINITIALIZE=function()return _PG.initialize(proto)end
'''.replace('__COUNT__',str(next(r for r in reversed(context.profile) if r['phase']=='program_integrity')['periodic_regions']))
        marker=program_integrity.initialization_source(version,backend)
        assert result.count(marker)==1
        if late:
            if late=='child-word':
                export+='''local test_words=proto.protos[2].code
local test_original=test_words[1]
_ENV_NATIVE.PROGRAM_TEST_EDIT=function(restore)
test_words[1]=restore and test_original or _ixor(test_original,1)
end
'''
            elif late=='bank':
                export+='''local test_cell=_mov_kits[1].banks[1][0][0][0]
local test_original=test_cell[1]
_ENV_NATIVE.PROGRAM_TEST_EDIT=function(restore)
test_cell[1]=restore and test_original or (test_original+1)%16
end
'''
            else:export+='''_ENV_NATIVE.PROGRAM_TEST_EDIT=function(restore)
if restore then proto.max_stack_size=proto.max_stack_size-1
else proto.max_stack_size=proto.max_stack_size+1 end
end
'''
        return result.replace(marker,export+('' if late else mutation+'\n')+marker)
    random.seed(18437)
    vm=VMPass(target=TargetProfile(version,backend),vm_options={**options(backend),**(config or {})},
              vm_output_passes=['strip_info','rename_obf','minify'])
    with patch.object(program_integrity,'prepare',inject):source=vm.run(guest)
    return vm,source


def iterate(function):
    yield function
    for child in function.children:yield from iterate(child)


class ProgramIntegrityTests(unittest.TestCase):
    def test_bare_consumed_factories_collect_without_retiring_guest_constructors(self):
        from obfuscator.vm.backends.bare_emitter import Program
        original=Program.source
        for version in ('5.1','5.3'):
            def observe(program):
                source=original(program)
                root=program.factories[program.functions[0].id]
                validation=program.factories[program.security.validation_id]
                guest=program.factories[program.functions[1].id]
                marker='local _Bsecurity=('
                self.assertEqual(1,source.count(marker))
                return source.replace(marker,
                    '_BN.PROGRAM_FACTORY_WEAK=setmetatable({'+validation+','+root+','+guest+'},{__mode="v"})\n'+marker)
            random.seed(18437)
            vm=VMPass(target=TargetProfile(version,'bare'),vm_options=options('bare'),
                      vm_output_passes=['strip_info','rename_obf','minify'])
            with patch.object(Program,'source',observe):source=vm.run(SOURCE)
            profile=next(r for r in vm.last_profile if r['phase']=='program_integrity')
            self.assertEqual(2,profile['monitored_factories'])
            result=run(version,source,call=b'''
local loader=assert((loadstring or load)(source));local f=loader();loader=nil
collectgarbage('collect');collectgarbage('collect')
return f(3),PROGRAM_FACTORY_WEAK[1]==nil,PROGRAM_FACTORY_WEAK[2]==nil,PROGRAM_FACTORY_WEAK[3]~=nil''')
            self.assertEqual((8,True,True,True),result)

    def test_bare_factory_bank_uses_existing_ir_guard_without_blob(self):
        from obfuscator.vm.backends.bare_emitter import Program
        original=Program.source
        for version in ('5.1','5.3'):
            for mode in ('identity','metatable','initial-missing'):
                def inject(program):
                    source=original(program)
                    # Choose a future guest constructor; consumed root/security
                    # factories are deliberately retired after initialization.
                    factory=program.factories[program.functions[1].id]
                    if mode=='initial-missing':
                        anchor='local _Bsecurity=('
                        self.assertEqual(1,source.count(anchor))
                        return source.replace(anchor,f'{factory}=nil\n'+anchor)
                    anchor=f'local _Bguard=_Bsecurity[{program.security.slots["guard"]}]\n'
                    self.assertEqual(1,source.count(anchor))
                    return source.replace(anchor,anchor+f'''
local original_factory={factory}
_BN.PROGRAM_TEST_EDIT=function(restore)
 {factory}=restore and original_factory or function()end
end
_BN.PROGRAM_TEST_META=function()setmetatable(_BF,{{}})end
_BN.PROGRAM_TEST_GUARD=function(force)return _Bguard(force)end
''')
                random.seed(18437)
                vm=VMPass(target=TargetProfile(version,'bare'),vm_options=options('bare'),
                          vm_output_passes=['strip_info','rename_obf','minify'])
                with patch.object(Program,'source',inject):source=vm.run(SOURCE)
                self.assertNotIn('__FACTORY_SLOTS__',source)
                self.assertNotIn('KARITY/',source)
                if mode=='initial-missing':
                    self.assertEqual((False,True),run(version,source,b'MARKER=0',
                        call=b'return pcall(assert((loadstring or load)(source))),MARKER==0'))
                else:
                    body=(b'PROGRAM_TEST_META();return not pcall(PROGRAM_TEST_GUARD,true)' if mode=='metatable' else b'''
PROGRAM_TEST_EDIT(false);PROGRAM_TEST_EDIT(true);assert(pcall(PROGRAM_TEST_GUARD,true))
PROGRAM_TEST_EDIT(false);local detected
for n=1,127 do if not pcall(PROGRAM_TEST_GUARD,false)then detected=n;break end end
return detected~=nil,detected and detected<=127,not pcall(PROGRAM_TEST_GUARD,true)''')
                    result=run(version,source,call=b'local f=assert((loadstring or load)(source))();assert(f(3)==8);'+body)
                    self.assertEqual(True if mode=='metatable' else (True,True,True),result)

    def test_before_seal_corruption_rejects_and_latches_every_blob_target(self):
        cases={
            'word':"proto.code[1]=_ixor(proto.code[1],1)",
            'header':"proto.max_stack_size=proto.max_stack_size+1",
            'graph':"proto.graph_sites[1]={{0,0,0,0,0}}",
            'routes':"proto.block_routes[1]={1}",
            'capture':"proto.protos[1].upvalues[1].idx=proto.protos[1].upvalues[1].idx+1",
            'child':"proto.protos[1]=proto.protos[#proto.protos]",
            'global-layout':"_IT.layout=_IT.layout+1",
            'number':"for i=1,#proto.constants do local k=proto.constants[i];if type(k[2])=='number' then k[2]=k[2]+1;break end end",
            'number-modulus-offset':"for i=1,#proto.constants do local k=proto.constants[i];if type(k[2])=='number' then k[2]=k[2]+2147483647;break end end",
        }
        for version in ('5.1','5.3'):
            for backend in ('classic','karity','mov'):
                for name,mutation in cases.items():
                    with self.subTest(version=version,backend=backend,mutation=name):
                        _,source=build(version,backend,mutation)
                        result=run(version,source,b'MARKER=0',call=b'''
local ok=pcall(assert((loadstring or load)(source)))
local again=pcall(PROGRAM_TEST_GUARD,true)
return ok,again,MARKER==0''')
                        self.assertEqual((False,False,True),result)

    def test_mov_regions_reject_before_guest(self):
        cases=(
            '_mov_kits[1].tape[1][2]=_mov_kits[1].tape[1][2]+1',
            '_mov_kits[1].banks[1][0][0][0][1]=(_mov_kits[1].banks[1][0][0][0][1]+1)%16',
            '_mov_kits[1].encode[0]=(_mov_kits[1].encode[0]+1)%16',
            'proto.mov_entries[1]=proto.mov_entries[1]+1',
        )
        for version in ('5.1','5.3'):
            for mutation in cases:
                with self.subTest(version=version,mutation=mutation):
                    _,source=build(version,'mov',mutation)
                    result=run(version,source,b'MARKER=0',call=b'''
return pcall(assert((loadstring or load)(source))),not pcall(PROGRAM_TEST_GUARD,true),MARKER==0''')
                    self.assertEqual((False,True,True),result)

    def test_native_numeric_edges_and_integrity_expression_values(self):
        from obfuscator.vm.backends.bare_emitter import literal
        guest='return 0.0,-0.0,1.5,1e-310,1.7976931348623157e308,1e999,-1e999,9007199254740991,9223372036854775807,-9223372036854775808'
        for version in ('5.1','5.3'):
            for backend in ('classic','karity','mov'):
                with self.subTest(version=version,backend=backend):
                    _,source=build(version,backend,guest=guest,
                        config={'integrity_constants':True,'integrity_constant_rate':1.0})
                    result=run(version,source,('BASE='+literal(guest)).encode(),call=b'''
local function pack(...)return {n=select('#',...),...}end
local a=pack(assert((loadstring or load)(BASE))());local b=pack(assert((loadstring or load)(source))())
assert(a.n==b.n)
for i=1,a.n do local x,y=a[i],b[i]
 assert(type(x)==type(y));assert((x~=x and y~=y) or x==y)
 if x==0 then assert(1/x==1/y)end
 if math.type then assert(math.type(x)==math.type(y))end
end
return true''')
                    self.assertTrue(result)

    def test_constant_recovery_rejects_mid_function_edit_before_return(self):
        original=program_integrity.prepare
        guest='return function()PROGRAM_TOUCH();return 991 end'
        for version in ('5.1','5.3'):
            for backend in ('classic','karity','mov'):
                def inject(source,layout,context,blob,**kwargs):
                    result=original(source,layout,context,blob,**kwargs)
                    child=layout.functions.children[0]
                    index=next(i for i,v in enumerate(child.source.constants,1) if v==991)
                    marker=program_integrity.initialization_source(version,backend)
                    result=result.replace(marker,marker+f'''
local original_test_guard=_PS_GUARD
_ENV_NATIVE.PROGRAM_TOUCH=function()
 local k=proto.protos[1].constants[{index}];k[2]=k[2]+1
 _PG.check=function()return true end
 _PS_GUARD=function()end
end
_ENV_NATIVE.PROGRAM_TEST_GUARD=function(force)return original_test_guard(force)end
''')
                    marker='if not success or result~=true then reject() end'
                    self.assertEqual(1,result.count(marker))
                    return result.replace(marker,
                        'if not success or result~=true then _ENV_NATIVE.PROGRAM_VALUE_REJECTED=true;reject() end')
                random.seed(18437)
                vm=VMPass(target=TargetProfile(version,backend),vm_options=options(backend),
                          vm_output_passes=['strip_info','rename_obf','minify'])
                with patch.object(program_integrity,'prepare',inject):source=vm.run(guest)
                result=run(version,source,b'PROGRAM_VALUE_REJECTED=false',call=b'''
local f=assert((loadstring or load)(source))()
local ok=pcall(f)
return ok,PROGRAM_VALUE_REJECTED,not pcall(PROGRAM_TEST_GUARD,true)''')
                self.assertEqual((False,True,True),result,(version,backend))

    def test_periodic_bound_and_transient_window(self):
        for version in ('5.1','5.3'):
            for backend in ('classic','karity','mov'):
                for region in ((True,'bank') if backend=='mov' else (True,)):
                    with self.subTest(version=version,backend=backend,region=region):
                        _,source=build(version,backend,late=region)
                        result=run(version,source,call=b'''
local f=assert((loadstring or load)(source))();assert(f(2)==7)
PROGRAM_TEST_EDIT(false);PROGRAM_TEST_EDIT(true)
assert(pcall(PROGRAM_TEST_GUARD,true))
PROGRAM_TEST_EDIT(false)
local limit=127*PROGRAM_TEST_COUNT();local detected
for n=1,limit do
 if not pcall(PROGRAM_TEST_GUARD,false) then detected=n;break end
end
return detected,limit,not pcall(PROGRAM_TEST_GUARD,true)
''')
                        detected,limit,latched=result
                        self.assertIsInstance(detected,int)
                        self.assertLessEqual(detected,limit)
                        self.assertTrue(latched)
                        print('program-latency',version,backend,'lookup' if region=='bank' else 'active-header',
                              detected,'of',limit,'guard events',flush=True)

    def test_after_seal_word_edit_is_rejected_on_next_function_entry(self):
        for version in ('5.1','5.3'):
            for backend in ('classic','karity','mov'):
                _,source=build(version,backend,late='child-word')
                result=run(version,source,call=b'''
local f=assert((loadstring or load)(source))();assert(f(3)==8)
PROGRAM_TEST_EDIT(false)
return pcall(f,3),not pcall(PROGRAM_TEST_GUARD,true)''')
                self.assertEqual((False,True),result,(version,backend))

    def test_normal_all_blob_targets(self):
        schemas=set()
        for version in ('5.1','5.3'):
            for backend in ('classic','karity','mov'):
                vm,source=build(version,backend)
                fields=next(r['manifest_fields'] for r in vm.last_profile if r['phase']=='program_integrity')
                self.assertEqual(set(program_integrity.SPEC_FIELDS),set(fields))
                schemas.add(tuple(fields))
                self.assertEqual((8,False,False),run(version,source,call=b'''
local f=assert((loadstring or load)(source))();local answer=f(3)
local first=pcall(PROGRAM_TEST_REINITIALIZE);local again=pcall(PROGRAM_TEST_GUARD,true)
return answer,first,again'''))
        self.assertGreater(len(schemas),1)

    def test_only_new_invocations_are_admitted_not_karity_continuation_returns(self):
        original=program_integrity.prepare
        def count(*args,**kwargs):
            source=original(*args,**kwargs);marker='function out.check(p)\n'
            self.assertEqual(1,source.count(marker))
            return source.replace(marker,marker+' _ENV_NATIVE.PROGRAM_ENTRIES=(_ENV_NATIVE.PROGRAM_ENTRIES or 0)+1\n')
        guest='local function bump(x)return x+10 end;return function()local n=0;for i=1,60 do n=bump(n)end;return n end'
        for version in ('5.1','5.3'):
            for backend in ('classic','karity','mov'):
                random.seed(18437)
                vm=VMPass(target=TargetProfile(version,backend),vm_options=options(backend),
                          vm_output_passes=['strip_info','rename_obf','minify'])
                with patch.object(program_integrity,'prepare',count):source=vm.run(guest)
                result=run(version,source,call=b'''
local f=assert((loadstring or load)(source))();local before=PROGRAM_ENTRIES
local answer=f();return answer,PROGRAM_ENTRIES-before''')
                self.assertEqual((600,61),result,(version,backend))

    def test_encoded_stream_verification_does_not_call_plain_integer_resolver(self):
        original=program_integrity.prepare
        def reject_plain(source,layout,context,blob,**kwargs):
            source=original(source,layout,context,blob,**kwargs)
            index=next(i for i,v in enumerate(layout.functions.source.constants,1) if v==777)
            self.assertTrue(layout.functions.stream_integrity)
            self.assertIn(index-1,layout.functions.integrity_indices)
            marker=program_integrity.initialization_source('5.3','karity')
            source=source.replace(marker,
                f'_ENV_NATIVE.PROGRAM_ENCODED_TARGET=proto.constants[{index}]\n'+marker)
            marker='local function _program_kval(k,proto,_program_mix)'
            self.assertEqual(1,source.count(marker))
            source=source.replace(marker,marker+"\n if _ENV_NATIVE.PROGRAM_INTEGRITY_ONLY and k==_ENV_NATIVE.PROGRAM_ENCODED_TARGET then error('unexpected original integer materialization',0) end")
            source=source.replace('local function digest(p,id,all_constants)',
                'local function digest(p,id,all_constants)\n _ENV_NATIVE.PROGRAM_INTEGRITY_ONLY=true')
            # Actual native-value consumers retain their existing semantics.
            # The test forbids new recovery solely for integrity and stream checks.
            source=source.replace('return g==spec[', '_ENV_NATIVE.PROGRAM_INTEGRITY_ONLY=false;return g==spec[')
            source=source.replace('function out.encoded(p,k)',
                'function out.encoded(p,k)\n _ENV_NATIVE.PROGRAM_INTEGRITY_ONLY=true')
            return source.replace('return raw(k,2)', '_ENV_NATIVE.PROGRAM_INTEGRITY_ONLY=false;return raw(k,2)')
        random.seed(18437)
        vm=VMPass(target=TargetProfile('5.3','karity'),vm_options={**options('karity'),
            'encoded_bitwise':True,'distributed_integrity':True,
            'integrity_constants':True,'integrity_constant_rate':1.0},
            vm_output_passes=['strip_info','rename_obf','minify'])
        with patch.object(program_integrity,'prepare',reject_plain):source=vm.run('return 777')
        self.assertEqual(777,run('5.3',source))


if __name__=='__main__':unittest.main()
