"""Actual IR verdicts, private entry routing and pre-guest evidence rejection."""
from pathlib import Path
from unittest.mock import patch
import random
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'test')]
from lupa.lua51 import LuaRuntime as Lua51
from lupa.lua53 import LuaRuntime as Lua53
from obfuscator.vm import VMPass,runtime_probes
from obfuscator.vm.runtime_probes import new_plan,bootstrap_source,verifier_source
from obfuscator.vm.targets.profile import TargetProfile
from run_vm_backend_regression import options
from run_source_protection_regression import run


def build(version,backend,mutation=None,export=False):
    original=runtime_probes.bootstrap_source
    seen=[]
    def observe(namespace,**kwargs):
        source=original(namespace,**kwargs)
        if not kwargs.get('protected'):raise AssertionError('production used native-only validation')
        plan=kwargs['plan'];seen.append(plan)
        additions=[]
        if export:
            worker=plan.observation_slots[7]
            additions.append('''native.RUNTIME_TEST_STATE=function()return pending_evidence,failed end
native.RUNTIME_TEST_GUARD=S.guard
native.RUNTIME_TEST_CLEAN=function()local h,m,c=Q.hook(thread);return h==nil and m=='' and c==0 end
native.RUNTIME_TEST_WEAK=setmetatable({thread,observations[WORKER]},{__mode='v'})
'''.replace('WORKER',str(worker)))
        if mutation:additions.append(mutation(plan))
        marker='pending_evidence=observations'
        assert source.count(marker)==1
        return source.replace(marker,'\n'.join(additions)+'\n'+marker)
    random.seed(7719)
    vm=VMPass(target=TargetProfile(version,backend),vm_options=options(backend),
        vm_output_passes=['strip_info','rename_obf','minify'])
    with patch.object(runtime_probes,'bootstrap_source',observe):
        source=vm.run('MARKER=1;local function user(a)return a+2 end;return user(5)')
    assert len(seen)==1
    return vm,source,seen[0]


def corrupt(plan,case):
    slot=lambda logical:plan.observation_slots[logical-1]
    value=lambda field:2*(plan.info_fields.index(field)+1)+1
    if case=='metadata':return f'observations[{slot(2)}][1][3][{value("source")}]=-987654'
    if case=='identity':return f'observations[{slot(7)}][{value("func")}]=Q.pcall'
    if case=='quiet-value':return f'observations[{slot(19)}][4]=observations[{slot(19)}][4]+1'
    if case=='quiet-event':
        return (f'local events=observations[{slot(24)}];events[#events+1]='+
            '{'+str(plan.modes[3])+",'string','line','thread',thread,1}")
    if case=='malformed':return f'observations[{slot(2)}][1]=false'
    raise AssertionError(case)


class RuntimeValidationTests(unittest.TestCase):
    def test_missing_private_program_contract_fails_closed(self):
        from obfuscator.vm.runtime_security import prepare
        for args in ({},{'probe_plan':new_plan('5.3')},{'validation_entry':'code'}):
            with self.assertRaisesRegex(ValueError,'both a plan and a private entry'):
                prepare('',backend='karity',native_unpack='table.unpack',globals_name='_ENV',
                        native_table_pack=True,**args)

    def test_public_metadata_integrality_keeps_numeric_edge_semantics(self):
        # Coerce public counts to native floating arithmetic before modulo, so
        # Karity need not run an integer divider circuit to validate a count.
        # This retains fraction/NaN/infinity/int64 rejection/acceptance behavior.
        for runtime_type in (Lua51,Lua53):
            lua=runtime_type()
            self.assertTrue(lua.execute('''local xs={0,-0,1,-1,1.5,-1.5,math.huge,-math.huge,0/0,
4503599627370495.5,4503599627370496,9007199254740991}
if math.maxinteger then xs[#xs+1]=math.maxinteger;xs[#xs+1]=math.mininteger end
for _,x in ipairs(xs)do assert((x%1~=0)==((x/1)%1~=0))end
return true'''))

    def test_collector_is_not_a_native_verdict_and_layout_varies(self):
        saved=random.getstate()
        try:
            slots=set();fields=set()
            for seed in range(12):
                random.seed(seed);plan=new_plan('5.3')
                source=bootstrap_source('native',plan=plan,protected=True)
                self.assertNotIn('check_info',source)
                self.assertNotIn('return false',source)
                self.assertNotIn("event=='line'",source)
                self.assertNotIn('function(o,kind)',source)
                self.assertEqual(24,len(set(plan.observation_slots)))
                self.assertTrue(all(31<=s<4096 for s in plan.observation_slots))
                slots.add(plan.observation_slots);fields.add(plan.info_fields)
            self.assertEqual(12,len(slots));self.assertGreater(len(fields),1)
        finally:random.setstate(saved)

    def test_source_text_uses_exact_canonical_ids(self):
        for version,runtime_type in (('5.1',Lua51),('5.3',Lua53)):
            lua=runtime_type(unpack_returned_tuples=True)
            plan=new_plan(version)
            source='''local native=_G
local kind,raw,same=type,rawget,rawequal
local A={info=debug.getinfo,hook=debug.gethook};local periodic,binding_owners={},{}
local pending_evidence;local function fail()error('bootstrap failure',0)end
BODY
return pending_evidence,type
'''.replace('BODY',bootstrap_source('native',plan=plan,protected=True))
            evidence,kind=lua.execute(source)
            index=2*(plan.info_fields.index('source')+1)+1
            sample=evidence[plan.observation_slots[4]][index]
            worker=evidence[plan.observation_slots[8]][index]
            anchor=evidence[plan.observation_slots[0]][index]
            self.assertIsInstance(sample,(int,float));self.assertEqual(sample,worker)
            self.assertNotEqual(anchor,sample)
            verify=lua.eval(verifier_source(plan))
            self.assertTrue(verify(evidence,kind))

    def test_decisions_are_real_ir_on_every_target_and_guest_interface_survives(self):
        for version in ('5.1','5.3'):
            for backend in ('bare','classic','karity','mov'):
                with self.subTest(version=version,backend=backend):
                    vm,source,plan=build(version,backend)
                    functions=[f for f in vm.last_semantic_ir.functions()
                               if f.debug_metadata.get('security_subsystem')=='runtime_validation']
                    self.assertEqual(1,len(functions));function=functions[0]
                    instructions=[i for b in function.blocks for i in b.instructions]
                    self.assertTrue({'EQUAL','GET_TABLE','JUMP'} <= {i.operation for i in instructions})
                    self.assertGreater(sum(i.operation in ('EQUAL','TEST','LESS_THAN') for i in instructions),20)
                    self.assertEqual(2,function.params);self.assertFalse(function.upvalue_bindings)
                    self.assertTrue(all(i.metadata.get('protection_origin')=='runtime_integrity' for i in instructions))
                    if backend=='bare':
                        package=vm.last_lowered_ir.backend_data['source_protection']
                        self.assertEqual(function.id,package.validation_id)
                        self.assertTrue(function.debug_metadata['security_optimization_safe'])
                        self.assertTrue(all(not f.debug_metadata.get('security_optimization_safe') for f in
                            vm.last_semantic_ir.functions() if f.debug_metadata.get('security_owned') and f is not function))
                        plans=[p for p in vm.last_lowered_ir.backend_data['bare_flow_plans'] if p['function']==function.id]
                        self.assertEqual(1,len(plans));flow=plans[0]
                        covered=sorted(s for group in flow['groups'] for s in group['sources'])
                        self.assertEqual(list(range(flow['segments_before'])),covered)
                    else:
                        self.assertEqual(function.id,vm.last_lowered_ir.backend_data['runtime_validation']['function'])
                        children=vm.last_lowered_ir.backend_data['layout'].functions.children
                        self.assertEqual(1,sum(c.source.id==function.id for c in children))
                        self.assertEqual(1,len(vm.last_source_ir.root.children))
                        self.assertEqual(2,len(vm.last_semantic_ir.root.children))
                    self.assertEqual((7,1),run(version,source,b'MARKER=0',
                        call=b'local answer=assert((loadstring or load)(source))();return answer,MARKER'))

    def test_real_evidence_tampering_is_rejected_before_guest_and_cleans_state(self):
        for case in ('metadata','identity','quiet-value','quiet-event','malformed'):
            for version in ('5.1','5.3'):
                for backend in ('bare','classic','karity','mov'):
                    with self.subTest(case=case,version=version,backend=backend):
                        _,source,_=build(version,backend,lambda p:corrupt(p,case),export=True)
                        result=run(version,source,b'MARKER=0',call=b'''
local ok=pcall(assert((loadstring or load)(source)))
local evidence,failed=RUNTIME_TEST_STATE()
local clean=RUNTIME_TEST_CLEAN();RUNTIME_TEST_CLEAN=nil
local again=pcall(RUNTIME_TEST_GUARD,true)
collectgarbage('collect');collectgarbage('collect')
return ok,failed,evidence==nil,clean,again,MARKER==0,
 RUNTIME_TEST_WEAK[1]==nil and RUNTIME_TEST_WEAK[2]==nil
''')
                        self.assertEqual((False,True,True,True,False,True,True),result)

    def test_success_consumes_evidence_once_and_releases_private_workers(self):
        for version in ('5.1','5.3'):
            for backend in ('bare','classic','karity','mov'):
                with self.subTest(version=version,backend=backend):
                    _,source,_=build(version,backend,export=True)
                    result=run(version,source,b'MARKER=0',call=b'''
local answer=assert((loadstring or load)(source))()
local evidence,failed=RUNTIME_TEST_STATE()
local clean=RUNTIME_TEST_CLEAN();RUNTIME_TEST_CLEAN=nil
collectgarbage('collect');collectgarbage('collect')
return answer,evidence==nil,failed,clean,
 RUNTIME_TEST_WEAK[1]==nil and RUNTIME_TEST_WEAK[2]==nil
''')
                    self.assertEqual((7,True,False,True,True),result)


if __name__=='__main__':unittest.main()
