"""Native oracles across combined protection options and large prototype trees."""
from pathlib import Path
import random
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'test')]
from obfuscator.vm import VMPass
from obfuscator.vm.targets.profile import TargetProfile
from obfuscator.passes.packer import PackerPass
from run_vm_backend_regression import options
from run_cross_backend_generated_regression import generated_source,execute


def combined_source():
    source=generated_source(811)+'''
local co=coroutine.create(function(x)
 local y=coroutine.yield(x,nil,false);return y*2,nil
end)
local a=packet(coroutine.resume(co,9))
assert(a.n==4 and a[1] and a[2]==9 and a[3]==nil and a[4]==false)
local b=packet(coroutine.resume(co,6))
assert(b.n==3 and b[1] and b[2]==12 and b[3]==nil)
local ok,reason=pcall(function()error('expected-guest-error')end)
assert(not ok and string.find(reason,'expected-guest-error',1,true))
print(a.n,b.n,coroutine.status(co),select('#',...),...)
'''
    return 'local function guest(...)\n'+source+'\nend\nguest(7,nil,false,nil)'


def configured(version,backend,form):
    config=options(backend)
    config.update(vm_count=1 if backend=='bare' else 3,blob_form=form,
                  integrity_constants=True,integrity_constant_rate=1.0)
    if backend=='classic':config['dispatcher_type']='mixed'
    if backend=='karity':
        config.update(graph_execution_rate=0.4,cross_instruction_rate=0.6,
            runtime_polymorphism_rate=0.5,semantic_state_threading=True,
            argument_virtualization=True,upvalue_virtualization=True,
            table_virtualization=True,branch_virtualization=True)
    return config


class IntegrityIntegrationTests(unittest.TestCase):
    def test_combined_options_preserve_native_boundaries_and_packing(self):
        source=combined_source()
        for version in ('5.1','5.3'):
            expected=execute(version,source)
            for backend in ('bare','classic','karity','mov'):
                forms=('string',) if backend=='bare' else ('string','table','numeric')
                for index,form in enumerate(forms):
                    with self.subTest(version=version,backend=backend,form=form):
                        random.seed(1103+index)
                        vm=VMPass(target=TargetProfile(version,backend),
                            vm_options=configured(version,backend,form),
                            vm_output_passes=['strip_info','rename_obf','minify'])
                        output=vm.run(source)
                        self.assertEqual(expected,execute(version,output))
                        if version=='5.3':
                            packed=PackerPass(['minify']).run(output)
                            self.assertEqual(expected,execute(version,packed))
                        print('integrity-combined-ok',version,backend,form,flush=True)

    def test_initialization_crosses_period_with_large_child_policy(self):
        # More than127 prototypes exercises admission during an initialization
        # checkpoint and the literal policy branch for more than eight children.
        count=132
        source='local fs={}\n'+'\n'.join(
            f'fs[{i}]=function()return {i} end' for i in range(1,count+1))
        source+=f'\nprint(fs[1](),fs[{count}]())'
        for version in ('5.1','5.3'):
            expected=execute(version,source)
            for backend in ('bare','classic','karity','mov'):
                with self.subTest(version=version,backend=backend):
                    config=options(backend)
                    config['vm_count']=1 if backend=='bare' else 3
                    random.seed(31337)
                    vm=VMPass(target=TargetProfile(version,backend),vm_options=config,
                        vm_output_passes=['strip_info','rename_obf','minify'])
                    output=vm.run(source)
                    profile=next(r for r in vm.last_profile if r['phase']=='program_integrity')
                    self.assertGreater(profile['functions'],127)
                    self.assertEqual(expected,execute(version,output))
                    print('integrity-large-tree-ok',version,backend,profile['functions'],flush=True)


if __name__=='__main__':unittest.main()
