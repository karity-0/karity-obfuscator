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
from obfuscator.passes.strip_info import StripInfoPass
from obfuscator.passes.minify import MinifyPass
from obfuscator.passes.rename_ts import resolve_bindings
from obfuscator.passes.rename_ts import rename_script_ts
from obfuscator.passes.binding_kinds import classify_bindings
from obfuscator.passes.ts_utils import parse
from obfuscator.vm import VMPass
from obfuscator.vm.targets.profile import TargetProfile
from run_cross_backend_generated_regression import execute
from run_source_protection_regression import run
from run_vm_backend_regression import options

POOL = ['customAlpha', 'customBeta', 'customGamma']


def catalog(names):
    return {kind: [f'{kind}_{name}' if kind != 'default' else name for name in names]
            for kind in ('function','string','integer','default')}


def single_category(names, kind='default'):
    return {category: list(names) if category == kind else []
            for category in ('function','string','integer','default')}


SOURCE = '''local held=2
local function make(n)return function(...)held=held+1;return n+held,... end end
local f=make(3);local a,b,c=f(nil,false);print(a,b,c)
local object={value=4};function object:add(n)return self.value+n end
print(object:add(7),held)'''


@patch.object(custom_names, 'CUSTOM_NAMES', catalog(POOL))
@patch.object(custom_names, 'CUSTOM_NAME_COUNT', 2)
class CustomNameTests(unittest.TestCase):
    def check_count(self, output, expected=2):
        ctx = parse(output)
        bindings = resolve_bindings(ctx, collect_literals=False)[0]
        names = {name for pool in custom_names.CUSTOM_NAMES.values() for name in pool}
        selected = [b.original for b in bindings if b.original in names]
        self.assertEqual(expected, len(selected))
        self.assertEqual(expected, len(set(selected)))
        kinds = classify_bindings(ctx, bindings)
        for binding in bindings:
            if binding.original in names:
                self.assertIn(binding.original, custom_names.CUSTOM_NAMES[kinds[id(binding)]])

    def test_binding_category_proofs(self):
        cases = [
            ('local function f()end; local s="s"; local n=12; local x={}',
             [('f','function'),('s','string'),('n','integer'),('x','default')]),
            ('local n=-0x2a;local a=(n);local s="a";local b=s..n;local size=#s',
             [('n','integer'),('a','integer'),('s','string'),('b','string'),('size','integer')]),
            ('local n=1.0;local e=1e2;local huge=9007199254740993;local h=0x1p4',
             [('n','default'),('e','default'),('huge','default'),('h','default')]),
            ('local x="s";local alias=x;x=1', [('x','default'),('alias','default')]),
            ('local x="s";local function change()x=1 end', [('x','default'),('change','function')]),
            ('local function f(x,...)x=1;local y=x;local z=... end',
             [('f','function'),('x','default'),('y','default'),('z','default')]),
            ('local x; x=1;local y=nil;y="s"', [('x','default'),('y','default')]),
            ('local a,b=1,2;a,b=b,a;a=a', [('a','integer'),('b','integer')]),
            ('local a,b,c=1,unknown(); local d,e=("s")',
             [('a','integer'),('b','default'),('c','default'),('d','string'),('e','default')]),
            ('local a,b = --[[ comment ]] 1, --[[ comment ]] "s"', [('a','integer'),('b','string')]),
            ('local a<const>,b,c=1,"s",3', [('a','integer'),('b','string'),('c','integer')]),
            ('local t={};local x="s";t.value,x=1,"t"', [('t','default'),('x','string')]),
            ('local t={};function t.f()end;local x=t.f;local u=t;u.value=1',
             [('t','default'),('x','default'),('u','default')]),
            ('local function f()f=1 end;local g=function()end;local h=g',
             [('f','default'),('g','function'),('h','function')]),
            ('local x=1;do local x="s";x="t" end;x=2',
             [('x','integer'),('x','string')]),
            ('local n=1;n=n+1;local s=globalValue;local b=true;local f=unknown()',
             [('n','default'),('s','default'),('b','default'),('f','default')]),
            ('for i=1,3 do end;for k,v in pairs({}) do end',
             [('i','default'),('k','default'),('v','default')]),
        ]
        for source,expected in cases:
            with self.subTest(source=source):
                ctx=parse(source);bindings=resolve_bindings(ctx,collect_literals=False)[0]
                kinds=classify_bindings(ctx,bindings)
                self.assertEqual(expected,[(b.original,kinds[id(b)]) for b in bindings])
        source='local n0=1;'+''.join(f'local n{i}=n{i-1};' for i in range(1,1000))
        ctx=parse(source);bindings=resolve_bindings(ctx,collect_literals=False)[0]
        self.assertEqual({'integer'},set(classify_bindings(ctx,bindings).values()))

    def test_category_selection_and_shortages(self):
        source='local function f()return "ok" end;local s="s";local n=1;print(f(),s,n)'
        with patch.object(custom_names,'CUSTOM_NAME_COUNT',3):
            pipeline=Pipeline(show_header=False).add(RenameObfuscationPass())
            output=pipeline.run(source);self.check_count(output,3)
            self.assertEqual({'function','string','integer'},set(pipeline.last_custom_names['categories'].values()))
            for version in ('5.1','5.3'):
                self.assertEqual(execute(version,source),execute(version,output))
        with patch.object(custom_names,'CUSTOM_NAMES',single_category(POOL)), patch.object(custom_names,'CUSTOM_NAME_COUNT',1):
            for source in ('local s="s";print(s)','local n=1;print(n)','local function f()end;f()'):
                pipeline=Pipeline(show_header=False).add(RenameObfuscationPass())
                output=pipeline.run(source);self.check_count(output,0)
                self.assertEqual('insufficient category candidates',pipeline.last_custom_names['reason'])
            pipeline=Pipeline(show_header=False).add(RenameObfuscationPass())
            self.check_count(pipeline.run('local x="s";x=1;print(x)'),1)
            self.assertEqual({'default'},set(pipeline.last_custom_names['categories'].values()))
        pools=single_category(['genericOne','genericTwo'])
        pools['integer']=['integerOnly']
        with patch.object(custom_names,'CUSTOM_NAMES',pools),patch.object(custom_names,'CUSTOM_NAME_COUNT',3):
            pipeline=Pipeline(show_header=False).add(RenameObfuscationPass())
            self.check_count(pipeline.run('local a,b,c=1,2,true;print(a,b,c)'),2)
            self.assertEqual({'integer','default'},set(pipeline.last_custom_names['categories'].values()))
            self.assertEqual('insufficient category candidates',pipeline.last_custom_names['reason'])
        bad=catalog(POOL);bad['string'].append(bad['function'][0])
        for pools in (POOL,{'default':POOL},bad,{**catalog(POOL),'string':'invalid'}):
            with patch.object(custom_names,'CUSTOM_NAMES',pools):
                with self.assertRaises(ValueError):
                    Pipeline(show_header=False).add(RenameObfuscationPass()).run(source)

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
            with patch.object(custom_names,'CUSTOM_NAMES',single_category(pool)), patch.object(custom_names,'CUSTOM_NAME_COUNT',count):
                with self.assertRaises(ValueError):
                    Pipeline(show_header=False).add(RenameObfuscationPass()).run(SOURCE)
                self.assertIsNone(custom_names.ACTIVE.get())
        with patch.object(custom_names,'CUSTOM_NAMES',single_category(['customAlpha','customBeta'],'integer')):
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
        for passes in (['minify','vm'],['strip_info','minify','vm'],['rename_obf','minify','vm']):
            config={'passes':passes,'vm_options':options('bare'),
                    'vm_output_passes':['rename_obf','minify'],'signature':{'mode':'none'}}
            pipeline=build_pipeline_from_config(config,Pipeline)
            output=pipeline.run(source)
            self.check_count(output,2 if {'rename_obf','strip_info'} & set(passes) else 0)

    def test_strip_info_source_naming_and_disabled_paths(self):
        source='local hp,hp2=123;print(hp,hp2)'
        excluded='--@NO_VM_START\n'+source+'\n--@NO_VM_END'
        for passes,text in ((['strip_info','minify'],source),(['strip_info','minify','vm'],excluded),
                            (['strip_info','rename_obf','minify'],source)):
            pipeline=build_pipeline_from_config({'passes':passes,'vm_options':options('bare'),
                'signature':{'mode':'none'}},Pipeline)
            output=pipeline.run(text);self.check_count(output)
            for version in ('5.1','5.3'):
                self.assertEqual(execute(version,text),execute(version,output))
            self.assertEqual(2,pipeline.last_custom_names['applied'])
        for pipeline in (Pipeline(show_header=False).add(MinifyPass()),
                         Pipeline(show_header=False).add(StripInfoPass(rename_locals=False))):
            output=pipeline.run(source);self.check_count(output,0)
            self.assertIn('hp',output)
        protected='--@NO_OBF_START\nlocal hp=123\n--@NO_OBF_END\nlocal hp2=2;print(hp,hp2)'
        pipeline=Pipeline(show_header=False).add(StripInfoPass())
        output=pipeline.run(protected);self.check_count(output,0)
        self.assertIn('local hp=123',output);self.assertIn('local hp2=2',output)
        token=RENAME_OPTIONS.set({'readable':True})
        try:
            self.check_count(Pipeline(show_header=False).add(StripInfoPass()).run(source))
            self.check_count(PackerPass(['strip_info','minify']).run(source))
        finally:RENAME_OPTIONS.reset(token)
        pipeline=build_pipeline_from_config({'passes':['strip_info','vm'],'vm_options':options('bare'),
            'vm_output_passes':[],'signature':{'mode':'none'}},Pipeline)
        output=pipeline.run(SOURCE);self.check_count(output)
        self.assertEqual(execute('5.3',SOURCE),execute('5.3',output))

    def test_strip_info_output_naming_without_rename_pass(self):
        for version in ('5.1','5.3'):
            for backend in ('classic','karity','mov','bare'):
                with self.subTest(version=version,backend=backend):
                    vm=VMPass(target=TargetProfile(version,backend),vm_options=options(backend),
                              vm_output_passes=['strip_info','minify'])
                    output=vm.run(SOURCE);self.check_count(output)
                    self.assertEqual(execute(version,SOURCE),execute(version,output))
        for passes in (['pack'],['vm','pack']):
            pipeline=build_pipeline_from_config({'passes':passes,'vm_options':options('bare'),
                'packer_output_passes':['strip_info','minify'],'signature':{'mode':'none'}},Pipeline)
            output=pipeline.run(SOURCE);self.check_count(output)
            self.assertEqual(execute('5.3',SOURCE),execute('5.3',output))
            self.assertEqual(2,pipeline.last_custom_names['applied'])
    def test_late_helpers_and_wrapper_native_names(self):
        pool=['select','getfenv','setfenv','_native_api','math','lateAlpha','lateBeta']
        observe=b'local f=assert((loadstring or load)(source));return f(7,nil,false,nil)'
        with patch.object(custom_names,'CUSTOM_NAMES',catalog(pool)):
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
