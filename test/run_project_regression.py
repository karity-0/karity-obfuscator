"""Project plans, transactional output and native multi-module semantics."""
from pathlib import Path
from unittest.mock import patch
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT),str(ROOT/'test')]
from obfuscator.project import ProjectError, create_plan, discover_project, matches, relative_path
from obfuscator.project_build import ProjectBuildError, build_project
from obfuscator.toolchain import LuaToolchain
from run_vm_backend_regression import options


class ProjectTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='karity-project-test-')
        self.base = Path(self.temp.name);self.root = self.base/'src';self.root.mkdir()
        self.write('main.lua','local m=require("lib.math");print(m.value)')
        self.write('lib/math.lua','return {value=7}')
        self.document = {'project':{'root':'src','output':'out'},'passes':['minify'],'signature':{'mode':'none'}}

    def tearDown(self):self.temp.cleanup()

    def write(self,path,source):
        file = self.root/path;file.parent.mkdir(parents=True,exist_ok=True)
        file.write_text(source,encoding='utf8');return file

    def plan(self):return create_plan(self.document,self.base)

    def test_directory_build_and_rebuild_preserve_input(self):
        original = {p.relative_to(self.root).as_posix():p.read_bytes() for p in self.root.rglob('*.lua')}
        plan = self.plan()
        self.assertTrue(plan.valid)
        self.assertEqual('internal',next(m for m in plan.modules if m.file.path=='main.lua').analysis['requires'][0]['status'])
        with patch('obfuscator.project._choose',side_effect=AssertionError('build rerolled selection')):
            report = build_project(plan)
            self.assertTrue(report['published'])
            self.assertTrue(build_project(plan)['published'])
        self.assertEqual(original,{p.relative_to(self.root).as_posix():p.read_bytes() for p in self.root.rglob('*.lua')})
        self.assertTrue(all(m['backend'] is None and not m['vm_applied'] for m in report['modules']))

    def test_module_only_folders_do_not_need_an_entry(self):
        (self.root/'main.lua').unlink()
        for entry in (None,''):
            with self.subTest(entry=entry):
                self.document['project']['entry'] = entry
                plan = self.plan();self.assertIsNone(plan.entry)
                report = build_project(plan);self.assertTrue(report['published']);self.assertIsNone(report['entry'])
                self.assertTrue((plan.output/'lib/math.lua').is_file())
        self.document['project']['entry'] = 'missing.lua'
        with self.assertRaises(ProjectError):self.plan()
        self.document['project'].pop('entry')
        self.assertIsNone(self.plan().entry)
        (self.root/'lib/math.lua').unlink()
        with self.assertRaisesRegex(ProjectError,'No Lua files'):self.plan()

    def test_file_discovery_does_not_wait_for_valid_build_settings_or_read_sources(self):
        self.document['project'].pop('output')
        self.document['project'].update(entry='missing.lua',backend_selection={'mode':'weighted','weights':{'bare':0}})
        with patch.object(Path,'read_bytes',side_effect=AssertionError('discovery read source')):
            found = discover_project(self.document,self.base)
        self.assertEqual(['lib/math.lua','main.lua'],[row['path'] for row in found['modules']])
        self.assertTrue(found['discovery_only']);self.assertIsNone(found['output'])
        self.assertTrue(all(row['status']=='discovered' and 'backend' not in row for row in found['modules']))
        with self.assertRaises(ProjectError):self.plan()
        self.document['project']['output'] = 'src/main.lua'
        found = discover_project(self.document,self.base)
        self.assertEqual(2,len(found['modules']))
        with self.assertRaises(ProjectError):self.plan()

    def test_shared_settings_are_validated_once_without_sharing_module_mutations(self):
        from obfuscator.project import _config
        with patch('obfuscator.project._config',wraps=_config) as configured:
            plan = self.plan()
        self.assertEqual(1,configured.call_count)
        plan.modules[0].config['passes'].append('remove_comment')
        self.assertEqual(['minify'],plan.modules[1].config['passes'])

    def test_empty_source_passes_are_warned_and_signature_only_is_reported(self):
        self.document.update(passes=[],vm_output_passes=['minify'],signature={'mode':'default'})
        self.document['project']['backend_selection'] = {'mode':'fixed','value':'bare'}
        plan = self.plan()
        self.assertTrue(all(m.vm_requested is False and m.transforms_requested is False for m in plan.modules))
        self.assertTrue(all(any('No transformation passes' in w for w in m.warnings) for m in plan.modules))
        report = build_project(plan)
        self.assertTrue(report['warnings'])
        self.assertTrue(all(m['protection_status']=='signature_only' and m['backend'] is None for m in report['modules']))
        self.document['signature'] = {'mode':'none'}
        report = build_project(self.plan())
        self.assertTrue(all(m['protection_status']=='unchanged' for m in report['modules']))
        self.document['project']['preset_selection'] = {'mode':'fixed','value':'builtin:fast'}
        self.assertTrue(all(m.vm_requested and 'vm' in m.config['passes'] for m in self.plan().modules))

    def test_marker_requested_vm_is_not_misreported_as_signature_only(self):
        self.document.update(passes=[],vm_options=options('bare'),vm_output_passes=['minify'])
        self.write('main.lua','--@VM_START\nlocal n=3;print(n)\n--@VM_END')
        plan = self.plan();main = next(m for m in plan.modules if m.file.path=='main.lua')
        self.assertTrue(main.vm_requested);self.assertTrue(main.transforms_requested)
        self.assertFalse(any('No transformation passes' in warning for warning in main.warnings))
        report = build_project(plan)
        main = next(m for m in report['modules'] if m['path']=='main.lua')
        self.assertEqual(('bare','processed'),(main['backend'],main['protection_status']))

    def test_weighted_choices_are_path_stable_and_overrides_are_independent(self):
        self.document['project'].update(seed=37,preset_selection={'mode':'weighted','weights':{'builtin:fast':1,'builtin:balanced':3}},
            backend_selection={'mode':'weighted','weights':{'bare':3,'classic':2,'mov':1,'karity':4}})
        before = self.plan()
        self.write('added.lua','return 9')
        after = self.plan()
        first = {m.file.path:(m.preset,m.backend) for m in before.modules}
        self.assertEqual(first,{m.file.path:(m.preset,m.backend) for m in after.modules if m.file.path in first})
        self.document['project']['module_overrides'] = {'main.lua':{'backend':'bare','preset':'builtin:fast'}}
        overridden = self.plan()
        main = next(m for m in overridden.modules if m.file.path=='main.lua')
        self.assertEqual(('bare','builtin:fast'),(main.backend,main.preset))
        self.assertEqual({'backend':'override','preset':'override'},main.selection)
        self.assertEqual(first['lib/math.lua'],next((m.preset,m.backend) for m in overridden.modules if m.file.path=='lib/math.lua'))
        self.document['project']['module_overrides'] = {}
        self.assertEqual([(m.file.path,m.preset,m.backend) for m in after.modules],
                         [(m.file.path,m.preset,m.backend) for m in self.plan().modules])

    def test_invalid_policies_and_paths_are_rejected(self):
        for policy in ({'mode':'weighted','weights':{'bare':0}}, {'mode':'weighted','weights':{'bare':-1}},
                       {'mode':'weighted','weights':{'unknown':1}}, {'mode':'fixed','value':'unknown'}):
            with self.subTest(policy=policy):
                doc = copy.deepcopy(self.document);doc['project']['backend_selection'] = policy
                with self.assertRaises(ProjectError):create_plan(doc,self.base)
        for key,value in (('entry','../main.lua'),('output','src'),('output','.'),('entry','missing.lua')):
            doc = copy.deepcopy(self.document);doc['project'][key] = value
            with self.subTest(key=key,value=value),self.assertRaises(ProjectError):create_plan(doc,self.base)

    def test_stale_or_modified_plan_fails_before_writes(self):
        plan = self.plan();self.write('new.lua','return 3')
        with self.assertRaises(ProjectBuildError):build_project(plan)
        self.assertFalse((self.base/'out').exists())
        plan = self.plan();plan.modules[0].config['passes'] = []
        with self.assertRaises(ProjectBuildError):build_project(plan)
        self.assertFalse((self.base/'out').exists())

    def test_failure_never_publishes_partial_output(self):
        plan = self.plan();build_project(plan)
        old = {p.name:p.read_bytes() for p in (self.base/'out').rglob('*') if p.is_file()}
        from obfuscator.project_build import build_pipeline_from_config
        count = 0
        def fail(*args):
            nonlocal count
            count += 1
            if count==2:raise RuntimeError('injected module failure')
            return build_pipeline_from_config(*args)
        with patch('obfuscator.project_build.build_pipeline_from_config',fail),self.assertRaises(ProjectBuildError) as error:
            build_project(plan)
        self.assertFalse(error.exception.report['published'])
        self.assertEqual('failed',error.exception.report['modules'][1]['status'])
        self.assertEqual(old,{p.name:p.read_bytes() for p in (self.base/'out').rglob('*') if p.is_file()})
        self.assertFalse(list(self.base.glob('.karity-stage-*')))

    def test_publication_failure_rolls_back_and_reports_a_retained_backup(self):
        plan = self.plan();build_project(plan)
        output = self.base/'out'
        snapshot = lambda folder: {p.relative_to(folder).as_posix():p.read_bytes() for p in folder.rglob('*') if p.is_file()}
        original = snapshot(output)
        replace = os.replace
        def fail_publication(source,destination):
            if Path(source).name.startswith('.karity-stage-'):raise OSError('injected publication failure')
            return replace(source,destination)
        with patch('obfuscator.project_build.os.replace',fail_publication),self.assertRaises(ProjectBuildError):
            build_project(plan)
        self.assertEqual(original,snapshot(output))
        self.assertFalse(list(self.base.glob('.karity-stage-*')))
        self.assertFalse(list(self.base.glob('.karity-backup-*')))
        def fail_rollback(source,destination):
            if Path(source).name.startswith(('.karity-stage-','.karity-backup-')):raise OSError('injected rename failure')
            return replace(source,destination)
        with patch('obfuscator.project_build.os.replace',fail_rollback),self.assertRaises(ProjectBuildError) as error:
            build_project(plan)
        backup, = self.base.glob('.karity-backup-*')
        self.assertIn(str(backup),str(error.exception))
        self.assertEqual(original,snapshot(backup))
        self.assertFalse(output.exists())
        self.assertFalse(list(self.base.glob('.karity-stage-*')))

    def test_unowned_and_edited_outputs_are_preserved(self):
        output = self.base/'out';output.mkdir();(output/'user.txt').write_text('keep')
        with self.assertRaises(ProjectBuildError):build_project(self.plan())
        self.assertEqual('keep',(output/'user.txt').read_text())
        (output/'user.txt').unlink();build_project(self.plan())
        (output/'main.lua').write_text('user edit')
        with self.assertRaises(ProjectBuildError):build_project(self.plan())
        self.assertEqual('user edit',(output/'main.lua').read_text())

    def test_resources_patterns_and_output_inside_root(self):
        self.write('assets/settings.json','{"value":7}');self.write('tests/ignored.lua','error("excluded")')
        self.document['project'].update(output='src/dist',copy_resources=True,exclude=['**/tests/**'])
        plan = self.plan();report = build_project(plan)
        self.assertEqual('copied',report['resources'][0]['status'])
        self.assertEqual((self.root/'assets/settings.json').read_bytes(),(self.root/'dist/assets/settings.json').read_bytes())
        self.assertEqual(plan.id,self.plan().id)
        self.assertFalse((self.root/'dist/tests').exists())
        self.assertTrue(matches('main.lua','**/*.lua'));self.assertTrue(matches('tests','**/tests/**'))
        self.assertFalse(matches('lib/main.lua','*.lua'))

    def test_dependency_classification_and_shadowing(self):
        self.write('pkg/init.lua','return 1');self.write('pkg.lua','return 2')
        self.write('cycle/a.lua','return require("cycle.b")');self.write('cycle/b.lua','return require("cycle.a")')
        self.write('excluded.lua','return 0')
        self.document['project']['exclude'] = ['excluded.lua']
        self.write('main.lua','''require("lib.math");require "pkg";require("external");require(name);require("excluded")
do local require=function()end;require("shadowed")end''')
        plan = self.plan();main = next(m for m in plan.modules if m.file.path=='main.lua')
        self.assertEqual({'internal','ambiguous','external','dynamic','unresolved'},set(r['status'] for r in main.analysis['requires']))
        self.assertFalse(any(r['module']=='shadowed' for r in main.analysis['requires']))
        self.assertIn(('cycle/a.lua','cycle/b.lua'),plan.cycles)
        self.assertTrue(any('unresolved' in warning for warning in main.warnings))
        self.assertTrue(any('ambiguous' in warning for warning in main.warnings))

    def test_dependency_paths_follow_host_case_resolution(self):
        self.write('main.lua','return require("LIB.MATH")')
        main = next(m for m in self.plan().modules if m.file.path=='main.lua')
        reference, = main.analysis['requires']
        if (self.root/'LIB/MATH.lua').is_file():
            self.assertEqual(('internal','lib/math.lua'),(reference['status'],reference['path']))
        else:self.assertEqual('external',reference['status'])

    def test_capabilities_errors_and_unsupported_options_are_visible(self):
        self.document.update(passes=['vm'],vm_options={**options('bare'),'requirements':{'dispatcher_cff':'required'}})
        plan = self.plan()
        self.assertFalse(plan.valid)
        with self.assertRaises(ProjectBuildError):build_project(plan)
        self.document['vm_options'] = {**options('bare'),'semantic_state_threading':True}
        plan = self.plan()
        self.assertTrue(plan.valid)
        self.assertTrue(all(m.warnings for m in plan.modules))
        self.assertTrue(plan.modules[0].config['vm_options']['semantic_state_threading'])

    def test_links_and_portable_collisions_are_rejected(self):
        target = self.base/'outside.lua';target.write_text('return 0')
        link = self.root/'escape.lua'
        try:link.symlink_to(target)
        except OSError:self.skipTest('Host does not allow symlink creation')
        with self.assertRaises(ProjectError):self.plan()
        link.unlink()

    def test_portable_path_validation(self):
        for path in ('lib/CON.lua','/outside.lua','../outside.lua','C:/outside.lua','lib/a:stream.lua','lib/trailing. /x.lua'):
            with self.subTest(path=path),self.assertRaises(ProjectError):relative_path(path)

    def test_modules_share_the_entry_runtime_and_custom_preserves_snapshots(self):
        self.document['project']['entry'] = 'main.lua'
        self.document['profiles'] = {'lua51':{'passes':['minify'],'target':{'lua_version':'5.1'}}}
        self.document['project']['preset_selection'] = {'mode':'fixed','value':'custom'}
        self.document['project']['module_overrides'] = {'lib/math.lua':{'preset':'lua51'}}
        plan = self.plan();self.assertFalse(plan.valid)
        self.assertIn('differs',next(m for m in plan.modules if m.file.path=='lib/math.lua').error)
        self.document['_profile'] = 'builtin:balanced'
        self.document['project']['module_overrides'] = {}
        self.document['project']['preset_selection'] = {'mode':'fixed','value':'custom'}
        self.assertTrue(all(m.preset=='custom' for m in self.plan().modules))

    def test_reserved_report_directory_collision_is_rejected(self):
        self.write('karity-project-report.json/part.lua','return 0')
        with self.assertRaises(ProjectError):self.plan()

    def test_cli_dry_run_and_build_share_choices(self):
        self.document['project'].update(seed=17,backend_selection={'mode':'weighted','weights':{'bare':2,'classic':1}})
        path = self.base/'project.json';path.write_text(json.dumps(self.document))
        args = [sys.executable,str(ROOT/'main.py'),'--project',str(path)]
        dry = subprocess.run([*args,'--dry-run'],capture_output=True,text=True,check=True)
        preview = json.loads(dry.stdout)
        self.assertFalse((self.base/'out').exists())
        result = subprocess.run([*args,'--project-report','-'],capture_output=True,text=True,check=True)
        built = json.loads(result.stdout)
        self.assertEqual(preview['plan_id'],built['plan_id'])
        self.assertEqual([(m['preset'],m['backend']) for m in preview['modules']],
                         [(m['planned_preset'],m['planned_backend']) for m in built['modules']])
        self.assertTrue(built['published'])

    def test_cli_report_cannot_overwrite_configuration(self):
        path = self.base/'project.json';text = json.dumps(self.document);path.write_text(text)
        result = subprocess.run([sys.executable,str(ROOT/'main.py'),'--project',str(path),
            '--dry-run','--project-report',str(path)],capture_output=True,text=True)
        self.assertEqual(1,result.returncode)
        self.assertIn('cannot overwrite',result.stderr)
        self.assertEqual(text,path.read_text())
        self.assertFalse((self.base/'out').exists())

    def execute(self,root,version):
        if version=='5.3':
            command = [LuaToolchain().lua(),'main.lua','inputarg']
        else:
            command = [sys.executable,'-c',
                "from lupa.lua51 import LuaRuntime;LuaRuntime(encoding=None).execute(b\"assert(loadfile('main.lua'))('inputarg')\")"]
        result = subprocess.run(command,cwd=root,capture_output=True,timeout=120)
        self.assertEqual(0,result.returncode,result.stderr.decode(errors='replace'))
        return result.stdout.replace(b'\r\n',b'\n')

    def test_all_backends_preserve_module_values_closures_and_coroutines(self):
        self.write('lib/math.lua','''local M={};function M.make(n)
 local value=n;return function(...)value=value+select(1,...);return value,nil,select('#',...)end end
function M.co()coroutine.yield(7,nil,9);return 11 end
return M''')
        self.write('main.lua','''local m=require('lib.math');assert(m==require('lib.math'))
local f=m.make(3);print(...);print(f(4,nil,9));print(f(2))
local co=coroutine.create(m.co);print(coroutine.resume(co));print(coroutine.resume(co))''')
        for version in ('5.1','5.3'):
            expected = self.execute(self.root,version)
            for backend in ('karity','classic','mov','bare'):
                with self.subTest(version=version,backend=backend):
                    self.document.update(passes=['vm'],vm_options=options(backend),
                        target={'lua_version':version},vm_output_passes=['minify'])
                    self.document['project']['output'] = f'out-{version}-{backend}'
                    plan = self.plan();report = build_project(plan)
                    self.assertEqual(expected,self.execute(plan.output,version))
                    self.assertTrue(all(m['backend']==backend for m in report['modules']))

    def test_loaded_project_modules_keep_runtime_integrity_boundaries(self):
        self.write('lib/math.lua','return function()MARKER=1;return 17 end')
        self.write('main.lua','''--@NO_VM_START
local f=require('lib.math');MARKER=0
local original=string.byte;string.byte=function()return 0 end
local ok=pcall(f);string.byte=original
assert(not ok and MARKER==0);print('tamper-blocked')
--@NO_VM_END''')
        for version in ('5.1','5.3'):
            for backend in ('karity','classic','mov','bare'):
                with self.subTest(version=version,backend=backend):
                    self.document.update(passes=['vm'],vm_options={**options(backend),
                        'integrity_constants':True,'integrity_constant_rate':1.0},
                        target={'lua_version':version},vm_output_passes=['minify'])
                    self.document['project']['output'] = f'guard-{version}-{backend}'
                    plan = self.plan();report = build_project(plan)
                    self.assertEqual(b'tamper-blocked\n',self.execute(plan.output,version))
                    self.assertIsNone(next(m for m in report['modules'] if m['path']=='main.lua')['backend'])

    def test_mixed_project_preserves_loading_and_resource_semantics(self):
        self.write('pkg/init.lua','return setmetatable({value=8},{__call=function(t,n)return t.value+n end})')
        self.write('cycle/a.lua','local M={};package.loaded[...]=M;M.b=require("cycle.b");return M')
        self.write('cycle/b.lua','return {a=require("cycle.a")}')
        self.write('side.lua','SIDE=(SIDE or 0)+1;return "side",nil,5')
        self.write('multi.lua','return ...')
        self.write('native.lua','--@NO_VM_START\nreturn 23\n--@NO_VM_END')
        self.write('assets/data.txt','asset-data')
        self.write('main.lua','''package.path='./?.lua;./?/init.lua;'..package.path
local mathlib=require('lib.math');assert(mathlib==require('lib.math'))
local name='pkg';local pkg=require(name);print(pkg(3),mathlib.value)
local a=require('cycle.a');print(a.b.a==a)
package.preload.external=function(name)return {name=name}end;print(require('external').name)
print(dofile('side.lua'));print(SIDE)
local load=assert(loadfile('multi.lua'));print(load('tag',nil,7));print(require('native'))
local f=assert(io.open('assets/data.txt','rb'));print(f:read('*a'));f:close()''')
        names = sorted(p.relative_to(self.root).as_posix() for p in self.root.rglob('*.lua'))
        backends = ('karity','classic','mov','bare')
        overrides = {name:{'backend':backends[i%4]} for i,name in enumerate(names)}
        for version in ('5.1','5.3'):
            with self.subTest(version=version):
                self.document.update(passes=['vm'],vm_options=options('bare'),target={'lua_version':version},vm_output_passes=['minify'])
                self.document['project'].update(output=f'mixed-{version}',copy_resources=True,module_overrides=overrides)
                expected = self.execute(self.root,version)
                plan = self.plan();report = build_project(plan)
                self.assertEqual(expected,self.execute(plan.output,version))
                actual = {m['path']:m for m in report['modules']}
                self.assertIsNone(actual['native.lua']['backend'])
                self.assertFalse(actual['native.lua']['vm_applied'])
                self.assertEqual(set(backends),set(m['backend'] for m in report['modules'] if m['backend']))


if __name__=='__main__':unittest.main()
