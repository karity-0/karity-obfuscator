"""Actual consumers under bypassed gateways, policy edits and lifecycle resets."""
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch
import random
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'test')]
from obfuscator.vm import VMPass,program_integrity,runtime_probes
from obfuscator.vm.targets.profile import TargetProfile
from run_vm_backend_regression import options
from run_source_protection_regression import run

GUEST='return function()CONSUMPTION_TOUCH();return 991 end'


def build(version,backend,transform=None,probe=None,guest=GUEST,bare_template=None):
    prepare=program_integrity.prepare
    collect=runtime_probes.bootstrap_source
    read=Path.read_text
    def program(source,layout,context,blob,**kwargs):
        result=prepare(source,layout,context,blob,**kwargs)
        return transform(result,layout,context) if transform else result
    def bootstrap(namespace,**kwargs):
        result=collect(namespace,**kwargs)
        if probe:
            marker='pending_evidence=observations'
            assert result.count(marker)==1
            result=result.replace(marker,probe+'\n'+marker)
        return result
    def template(path,*args,**kwargs):
        text=read(path,*args,**kwargs)
        if bare_template and path.name=='source_security.lua':text=bare_template(text)
        return text
    random.seed(18437)
    vm=VMPass(target=TargetProfile(version,backend),vm_options=options(backend),
        vm_output_passes=['strip_info','rename_obf','minify'])
    with ExitStack() as stack:
        stack.enter_context(patch.object(program_integrity,'prepare',program))
        stack.enter_context(patch.object(runtime_probes,'bootstrap_source',bootstrap))
        stack.enter_context(patch.object(Path,'read_text',template))
        source=vm.run(guest)
    return vm,source


def inject_once(source,marker,extra,before=False):
    assert source.count(marker)==1,marker
    return source.replace(marker,extra+'\n'+marker if before else marker+'\n'+extra)


def scalar_index(layout):
    return next(i for i,value in enumerate(layout.functions.children[0].source.constants,1) if value==991)


class IntegrityConsumptionTests(unittest.TestCase):
    def test_policy_and_stage_checks_survive_structural_output_passes(self):
        from obfuscator.passes.packer import PackerPass
        guest="local function f(x)return x+17 end;return f(25),'alive',select('#',...),..."
        call=b"return assert((loadstring or load)(source))(9,nil,false,nil)"
        for version,backend in (('5.1','classic'),('5.3','classic'),('5.3','karity')):
            random.seed(18437)
            passes=(['number_obf','boolean_obf'] if version=='5.3' else [])+[
                'table_obf','function_obf','strip_info','rename_obf','minify']
            vm=VMPass(target=TargetProfile(version,backend),vm_options=options(backend),
                vm_output_passes=passes)
            source=vm.run(guest)
            self.assertEqual((42,b'alive',4,9,None,False,None),run(version,source,call=call))
            if version=='5.3':
                packed=PackerPass(['minify']).run(source)
                self.assertEqual((42,b'alive',4,9,None,False,None),run(version,packed,call=call))

    def test_skipping_complete_cannot_admit_guest_even_with_matching_ledger(self):
        # Intentionally bless the substituted method in the old reference ledger:
        # this isolates the stage check from an unrelated method identity alarm.
        probe='''local previous=S.complete
S.complete=function()native.CONSUMPTION_SKIPPED=validation_phase end
for i=1,#trusted do local r=trusted[i]
 if same(r[1],S) and same(r[3],previous) then r[3]=S.complete end
end
native.CONSUMPTION_PHASE=function()return validation_phase end'''
        for version in ('5.1','5.3'):
            for backend in ('bare','classic','karity','mov'):
                with self.subTest(version=version,backend=backend):
                    _,source=build(version,backend,probe=probe,guest='MARKER=1;return 42')
                    result=run(version,source,b'MARKER=0',call=b'''
local ok=pcall(assert((loadstring or load)(source)))
return ok,MARKER,CONSUMPTION_SKIPPED,CONSUMPTION_PHASE()''')
                    self.assertEqual((False,0,1,3),result)

    def test_original_initializer_survives_public_method_bypass(self):
        for version in ('5.1','5.3'):
            for backend in ('classic','karity','mov'):
                def transform(source,layout,context):
                    return inject_once(source,program_integrity.initialization_source(version,backend),
                        '_PG.initialize=function()end;proto.max_stack_size=proto.max_stack_size+1',before=True)
                _,source=build(version,backend,transform,guest='MARKER=1;return 42')
                result=run(version,source,b'MARKER=0',call=b'''
local ok=pcall(assert((loadstring or load)(source)));return ok,MARKER''')
                self.assertEqual((False,0),result,(version,backend))

    def test_scalar_consumer_survives_both_guard_and_method_bypass(self):
        for version in ('5.1','5.3'):
            for backend in ('classic','karity','mov'):
                def transform(source,layout,context):
                    index=scalar_index(layout)
                    source=inject_once(source,program_integrity.initialization_source(version,backend),f'''
local original_guard=_PS_GUARD
_ENV_NATIVE.CONSUMPTION_GUARD=function()return original_guard(true)end
_ENV_NATIVE.CONSUMPTION_TOUCH=function()
 _PS_GUARD=function()end
 _PG.value=function()return 991 end
 proto.protos[1].constants[{index}][2]=992
end''')
                    return source.replace('if not success or result~=true then reject() end',
                        'if not success or result~=true then _ENV_NATIVE.CONSUMPTION_VALUE=true;reject() end')
                _,source=build(version,backend,transform)
                result=run(version,source,call=b'''
local f=assert((loadstring or load)(source))()
local ok=pcall(f);return ok,CONSUMPTION_VALUE,not pcall(CONSUMPTION_GUARD)''')
                self.assertEqual((False,True,True),result,(version,backend))

    def test_scalar_policy_and_data_coordinated_edit_is_rejected_at_consumer(self):
        for version in ('5.1','5.3'):
            for backend in ('classic','karity','mov'):
                for delta in (1,2147483647):
                    def transform(source,layout,context):
                        index=scalar_index(layout)
                        fields=next(r for r in reversed(context.profile) if r['phase']=='program_integrity')['manifest_fields']
                        slot=fields.index('constants')+1
                        source=inject_once(source,'_PS.bind_program(out)',f'''
function out.test_edit(p)
 local expected=specs[ids[p]][{slot}][{index}]
 local value=991+{delta}
 local lo,hi=words(value,expected[5]==1)
 expected[3]=(lo+expected[2])%4294967296
 expected[4]=(hi+expected[2]*65599%4294967296)%4294967296
 p.constants[{index}][2]=value
end''',before=True)
                        return inject_once(source,program_integrity.initialization_source(version,backend),'''
_ENV_NATIVE.CONSUMPTION_TOUCH=function()
 _PS_GUARD=function()end;_PG.test_edit(proto.protos[1])
end''')
                    _,source=build(version,backend,transform)
                    self.assertFalse(run(version,source,call=b'''
local f=assert((loadstring or load)(source))();return (pcall(f))'''),(version,backend,delta))
                # Strong negative control: when ONLY the new leaf policy check
                # is omitted, correctly forged data + old expected limbs pass
                # the existing native-value comparison and change guest output.
                def disabled(source,layout,context):
                    result=transform(source,layout,context)
                    marker='local function policy(domain,ordinal,value)'
                    return inject_once(result,marker,' if ordinal>0 then return true end')
                _,source=build(version,backend,disabled)
                self.assertEqual(991+2147483647,run(version,source,call=b'''
local f=assert((loadstring or load)(source))();return f()'''),(version,backend))

    def test_header_policy_and_runtime_header_edit_is_rejected_on_entry(self):
        for version in ('5.1','5.3'):
            for backend in ('classic','karity','mov'):
                def transform(source,layout,context):
                    fields=next(r for r in reversed(context.profile) if r['phase']=='program_integrity')['manifest_fields']
                    slot=fields.index('header')+1
                    source=inject_once(source,'_PS.bind_program(out)',f'''
function out.test_edit(p)
 specs[ids[p]][{slot}][3]=specs[ids[p]][{slot}][3]+1
 p.max_stack_size=p.max_stack_size+1
end''',before=True)
                    return inject_once(source,program_integrity.initialization_source(version,backend),
                        '_ENV_NATIVE.CONSUMPTION_EDIT=function()_PG.test_edit(proto.protos[1])end')
                _,source=build(version,backend,transform,guest='return function()return 991 end')
                result=run(version,source,call=b'''
local f=assert((loadstring or load)(source))();assert(f()==991)
CONSUMPTION_EDIT();return (pcall(f))''')
                self.assertFalse(result,(version,backend))

    def test_forged_masked_seal_still_fails_periodic_canonical_validation(self):
        for version in ('5.1','5.3'):
            for backend in ('classic','karity','mov'):
                def transform(source,layout,context):
                    profile=next(r for r in reversed(context.profile) if r['phase']=='program_integrity')
                    slot=profile['manifest_fields'].index('code_seed')+1
                    source=inject_once(source,'_PS.bind_program(out)',f'''
function out.test_edit(p)
 local id=ids[p];p.code[1]=_ixor(p.code[1],1)
 local h=specs[id][{slot}]
 for i=1,#p.code do local word=p.code[i]
  h=((h*65599+word%16777216)%2147483647*65599+floor(word/16777216))%2147483647
 end
 seals[id]=h
end''',before=True)
                    return inject_once(source,program_integrity.initialization_source(version,backend),f'''
_ENV_NATIVE.CONSUMPTION_EDIT=function()_PG.test_edit(proto.protos[1])end
_ENV_NATIVE.CONSUMPTION_GUARD=function()return _PS_GUARD(false)end
_ENV_NATIVE.CONSUMPTION_LIMIT={profile['periodic_regions']*127}
''')
                _,source=build(version,backend,transform,guest='return function()return 991 end')
                result=run(version,source,call=b'''
local f=assert((loadstring or load)(source))();assert(f()==991)
CONSUMPTION_EDIT();local detected
for i=1,CONSUMPTION_LIMIT do if not pcall(CONSUMPTION_GUARD)then detected=i;break end end
return detected~=nil,detected and detected<=CONSUMPTION_LIMIT''')
                self.assertEqual((True,True),result,(version,backend))

    def test_restoring_shared_flags_and_data_cannot_recreate_program_admission(self):
        probe='native.CONSUMPTION_RESET=function()failed=false;validation_phase=2 end'
        for version in ('5.1','5.3'):
            for backend in ('classic','karity','mov'):
                def transform(source,layout,context):
                    index=scalar_index(layout)
                    return inject_once(source,program_integrity.initialization_source(version,backend),f'''
local k=proto.protos[1].constants[{index}]
_ENV_NATIVE.CONSUMPTION_TOUCH=function()k[2]=992 end
_ENV_NATIVE.CONSUMPTION_RESTORE=function()
 k[2]=991;_ENV_NATIVE.CONSUMPTION_TOUCH=function()end
end''')
                _,source=build(version,backend,transform,probe)
                result=run(version,source,call=b'''
local f=assert((loadstring or load)(source))();local first=pcall(f)
CONSUMPTION_RESTORE();CONSUMPTION_RESET();local again=pcall(f)
return first,again''')
                self.assertEqual((False,False),result,(version,backend))

    def test_mov_tape_and_old_expected_tag_edit_cannot_change_literal_policy(self):
        for version in ('5.1','5.3'):
            def transform(source,layout,context):
                profile=next(r for r in reversed(context.profile) if r['phase']=='program_integrity')
                source=inject_once(source,'_PS.bind_program(out)','''
function out.test_edit()
 for index,spec in ipairs(mov_specs)do if spec[1]==2 then
  local tape=mov_objects[spec[2]].tape
  tape[spec[4]][2]=(tape[spec[4]][2]+1)%16
  local h=spec[6]
  for i=spec[4],spec[4]+spec[5]-1 do for j=1,6 do h=add(h,tape[i][j])end end
  spec[7]=h;return
 end end
 error('missing MOV tape region')
end''',before=True)
                return inject_once(source,program_integrity.initialization_source(version,'mov'),f'''
_ENV_NATIVE.CONSUMPTION_EDIT=_PG.test_edit
_ENV_NATIVE.CONSUMPTION_GUARD=function()return _PS_GUARD(false)end
_ENV_NATIVE.CONSUMPTION_LIMIT={profile['periodic_regions']*127}
''')
            _,source=build(version,'mov',transform,guest='return function()return 991 end')
            result=run(version,source,call=b'''
local f=assert((loadstring or load)(source))();assert(f()==991);CONSUMPTION_EDIT()
local detected
for i=1,CONSUMPTION_LIMIT do if not pcall(CONSUMPTION_GUARD)then detected=i;break end end
return detected~=nil,detected and detected<=CONSUMPTION_LIMIT''')
            self.assertEqual((True,True),result,version)

    def test_bare_cached_value_failure_survives_shared_failed_reset(self):
        def template(source):
            return inject_once(source,'for name,value in next0,S do', '''
N.CONSUMPTION_BAD=function()
 for index,c in next0,cache do if c[1]=='bounded-token' then c[1]='changed' end end
end
N.CONSUMPTION_RESTORE=function()
 failed=false
 for index,c in next0,cache do if c[1]=='changed' then c[1]='bounded-token' end end
end''',before=True)
        for version in ('5.1','5.3'):
            _,source=build(version,'bare',guest="return function()return 'bounded-token' end",bare_template=template)
            result=run(version,source,call=b'''
local f=assert((loadstring or load)(source))();assert(f()=='bounded-token')
CONSUMPTION_BAD();local first=pcall(f)
CONSUMPTION_RESTORE();local again=pcall(f);return first,again''')
            self.assertEqual((False,False),result,version)

    def test_cached_string_identity_inputs_checked_even_if_common_guard_bypassed(self):
        for version in ('5.1','5.3'):
            for backend in ('classic','karity','mov'):
                for field in ('script','line'):
                    def transform(source,layout,context):
                        return inject_once(source,program_integrity.initialization_source(version,backend),f'''
_ENV_NATIVE.CONSUMPTION_EDIT=function()
 _PS_GUARD=function()end;_IT.{field}=(_IT.{field}+1)%4294967296
end''')
                    _,source=build(version,backend,transform,guest="return function()return 'bounded-token' end")
                    result=run(version,source,call=b'''
local f=assert((loadstring or load)(source))();assert(f()=='bounded-token')
CONSUMPTION_EDIT();return (pcall(f))''')
                    self.assertFalse(result,(version,backend,field))


if __name__=='__main__':unittest.main()
