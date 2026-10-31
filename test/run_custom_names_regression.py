"""Bounded custom naming across scopes, integrity boundaries and nested outputs."""
from pathlib import Path
from unittest.mock import patch
import random
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT/'test')]
from obfuscator import Pipeline, build_pipeline_from_config
from obfuscator import custom_names
from obfuscator.names import RENAME_OPTIONS
from obfuscator.passes.rename_obfuscation import RenameObfuscationPass
from obfuscator.passes.packer import PackerPass
from obfuscator.passes.rename_ts import resolve_bindings
from obfuscator.passes.rename_ts import rename_script_ts
from obfuscator.passes.ts_utils import parse
from obfuscator.vm import VMPass
from obfuscator.vm.targets.profile import TargetProfile
from run_cross_backend_generated_regression import execute
from run_source_protection_regression import run
from run_vm_backend_regression import options

POOL = ['customAlpha', 'customBeta', 'customGamma']
SOURCE = '''local held=2
local function make(n)return function(...)held=held+1;return n+held,... end end
local f=make(3);local a,b,c=f(nil,false);print(a,b,c)
local object={value=4};function object:add(n)return self.value+n end
print(object:add(7),held)'''


@patch.object(custom_names, 'CUSTOM_NAMES', POOL)
@patch.object(custom_names, 'CUSTOM_NAME_COUNT', 2)
class CustomNameTests(unittest.TestCase):
    def check_count(self, output, expected=2):
        bindings = resolve_bindings(parse(output), collect_literals=False)[0]
        selected = [b.original for b in bindings if b.original in POOL]
        self.assertEqual(expected, len(selected))
        self.assertEqual(expected, len(set(selected)))

    def test_source_scopes_seed_and_shortage(self):
        pipeline = build_pipeline_from_config({'passes':['rename_obf','minify'],
            'rename_obf_options':{'seed':519},'signature':{'mode':'none'}}, Pipeline)
        first = pipeline.run(SOURCE);self.check_count(first)
        self.assertEqual(first, pipeline.run(SOURCE))
        for version in ('5.1','5.3'):
            self.assertEqual(execute(version,SOURCE), execute(version,first))
        one = pipeline.run('local value=3;print(value)')
        self.check_count(one,1)
        self.assertEqual('insufficient eligible bindings', pipeline.last_custom_names['reason'])
        self.check_count(pipeline.run('print(7)'),0)
        self.assertIsNone(custom_names.ACTIVE.get())

    def test_counts_and_captured_binding(self):
        for count in (1,2,3):
            with patch.object(custom_names,'CUSTOM_NAME_COUNT',count):
                result=Pipeline(show_header=False).add(RenameObfuscationPass()).run(SOURCE)
                self.check_count(result,count)
        with patch.object(custom_names,'CUSTOM_NAME_COUNT',1):
            result=Pipeline(show_header=False).add(RenameObfuscationPass()).run('local held=2;return function()return held end')
            self.check_count(result,1)
            self.assertEqual(2,run('5.1',result));self.assertEqual(2,run('5.3',result))

    def test_invalid_names_collisions_and_disabled_mode(self):
        for pool,count in ((['for'],1),(['a-b'],1),(['_ENV'],1),(['self'],1),(['only'],2),(['same','same'],2),(['a'],True)):
            with patch.object(custom_names,'CUSTOM_NAMES',pool), patch.object(custom_names,'CUSTOM_NAME_COUNT',count):
                with self.assertRaises(ValueError):
                    Pipeline(show_header=False).add(RenameObfuscationPass()).run(SOURCE)
                self.assertIsNone(custom_names.ACTIVE.get())
        with patch.object(custom_names,'CUSTOM_NAMES',['customAlpha','customBeta']):
            with self.assertRaisesRegex(ValueError,'collision-free'):
                Pipeline(show_header=False).add(RenameObfuscationPass()).run('local x=1;local y=2;print(x,y,customAlpha,customBeta)')
        with patch.object(custom_names,'CUSTOM_NAME_COUNT',0):
            result=Pipeline(show_header=False).add(RenameObfuscationPass()).run(SOURCE)
            self.check_count(result,0)
            self.assertEqual(rename_script_ts(SOURCE),result)
        plain=Pipeline(show_header=False).run(SOURCE)
        self.assertEqual(SOURCE,plain)
        readable=Pipeline(show_header=False).add(RenameObfuscationPass(readable=True)).run(SOURCE)
        self.check_count(readable,0);self.assertIn('_held_',readable)

    def test_exclusions_and_identifier_syntax_only(self):
        source='''--@NO_OBF_START
local untouched=7
--@NO_OBF_END
local a=2;local b=3;local t={customAlpha="customBeta"};print(untouched+a+b,t.customAlpha)'''
        pipeline=build_pipeline_from_config({'passes':['rename_obf'],'signature':{'mode':'none'}},Pipeline)
        result=pipeline.run(source)
        self.assertIn('local untouched=7',result)
        self.assertIn('customAlpha="customBeta"',result)
        self.assertEqual(execute('5.3',source),execute('5.3',result))

    def test_all_vm_backends_before_hash_and_late_helpers(self):
        for version in ('5.1','5.3'):
            for backend in ('classic','karity','mov','bare'):
                with self.subTest(version=version,backend=backend):
                    random.seed(519)
                    vm=VMPass(target=TargetProfile(version,backend),vm_options=options(backend),
                        vm_output_passes=['strip_info','rename_obf','string_encode','minify'])
                    output=vm.run(SOURCE);self.check_count(output)
                    self.assertEqual(execute(version,SOURCE),execute(version,output))
                    self.assertEqual(2,vm.last_custom_names['applied'])
        vm=VMPass(target=TargetProfile('5.3','bare'),vm_options=options('bare'),
                  vm_output_passes=['rename_obf','minify'])
        output=vm.run('hook();return 7')
        with self.assertRaises(Exception):run('5.3',output,b'hook=function()string.byte=function()return 0 end end')

    def test_packer_and_nested_source_vm_outputs_get_one_quota(self):
        packed=PackerPass(['rename_obf','minify']).run(SOURCE)
        self.check_count(packed);self.assertEqual(execute('5.3',SOURCE),execute('5.3',packed))
        for backend in ('classic','karity','mov','bare'):
            with self.subTest(backend=backend):
                pipeline=build_pipeline_from_config({'passes':['rename_obf','vm','pack'],
                    'vm_options':options(backend),'vm_output_passes':['strip_info','rename_obf','minify'],
                    'packer_output_passes':['rename_obf','minify'],'signature':{'mode':'none'}},Pipeline)
                output=pipeline.run(SOURCE);self.check_count(output)
                self.assertEqual(execute('5.3',SOURCE),execute('5.3',output))
                self.assertEqual(2,pipeline.last_custom_names['applied'])

    def test_selective_vm_counts_across_capsules(self):
        source='''local held=3
--@VM_START
held=held+2
--@VM_END
--@VM_START
held=held*3
--@VM_END
print(held)'''
        pipeline=build_pipeline_from_config({'passes':['rename_obf','vm'],
            'vm_options':options('bare'),'vm_output_passes':['rename_obf','minify'],
            'selection_modes':{'vm':'marked'},'signature':{'mode':'none'}},Pipeline)
        output=pipeline.run(source);self.check_count(output)
        self.assertEqual(execute('5.3',source),execute('5.3',output))

    def test_fully_no_vm_source_still_gets_source_renaming(self):
        source='--@NO_VM_START\nlocal hp,hp2 = 123\n\nprint(hp, hp2)\n--@NO_VM_END'
        for version in ('5.1','5.3'):
            for backend in ('classic','karity','mov','bare'):
                with self.subTest(version=version,backend=backend):
                    config={'passes':['strip_info','rename_obf','minify','vm'],
                        'target':{'lua_version':version},'vm_options':options(backend),
                        'vm_output_passes':['rename_obf','minify'],'signature':{'mode':'none'}}
                    pipeline=build_pipeline_from_config(config,Pipeline)
                    output=pipeline.run(source);self.check_count(output)
                    self.assertEqual(execute(version,source),execute(version,output))
                    self.assertEqual(2,pipeline.last_custom_names['applied'])
        for passes in (['strip_info','minify','vm'],['rename_obf','minify','vm']):
            config={'passes':passes,'vm_options':options('bare'),
                    'vm_output_passes':['rename_obf','minify'],'signature':{'mode':'none'}}
            pipeline=build_pipeline_from_config(config,Pipeline)
            output=pipeline.run(source)
            self.check_count(output,0 if 'rename_obf' not in passes else 2)

    def test_late_helpers_and_wrapper_native_names(self):
        pool=['select','getfenv','setfenv','_native_api','math','lateAlpha','lateBeta']
        observe=b'local f=assert((loadstring or load)(source));return f(7,nil,false,nil)'
        with patch.object(custom_names,'CUSTOM_NAMES',pool):
            for version in ('5.1','5.3'):
                for backend in ('classic','bare'):
                    with self.subTest(version=version,backend=backend):
                        vm=VMPass(target=TargetProfile(version,backend),vm_options=options(backend),
                            vm_output_passes=['rename_obf','minify'])
                        output=vm.run('return ...')
                        self.assertEqual((7,None,False,None),run(version,output,call=observe))
                        self.assertEqual(2,vm.last_custom_names['applied'])
                        self.assertFalse(set(vm.last_custom_names['names']) & {'select','getfenv','setfenv'})
            packer=PackerPass(['rename_obf','minify'])
            output=packer.run('return ...')
            self.assertEqual((7,None,False,None),run('5.3',output,call=observe))

    def test_bbeb_is_reproducible_as_anti_decompile_truthy_data(self):
        from obfuscator.passes.anti_decompile import _truthy_literal, AntiDecompilePass
        letters=iter('bbeb')
        with patch('obfuscator.passes.anti_decompile.random.choice',
                   side_effect=lambda values: next(letters) if values=='abcdef' else values[-1]):
            self.assertEqual('"bbeb"',_truthy_literal())
        with patch('obfuscator.passes.anti_decompile._truthy_literal', return_value='"bbeb"'):
            source=Pipeline(show_header=False).add(AntiDecompilePass()).run('return 7')
        vm=VMPass(target=TargetProfile('5.3','classic'),vm_options=options('classic'))
        self.assertEqual(7,run('5.3',vm.run(source)))
        self.assertIn(b'bbeb',[v.literal for v in vm.last_source_ir.root.values if v.kind=='constant'])


if __name__ == '__main__':unittest.main()
