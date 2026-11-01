"""Shared desktop plan/build identity, events, output access and dialogs."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import copy
import json
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'test')]
import obfuscator_gui
from obfuscator_gui import Api
from run_vm_backend_regression import options


class ProjectGuiTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='karity-project-gui-');self.base=Path(self.temp.name).resolve()
        self.root=self.base/'src';(self.root/'lib').mkdir(parents=True)
        (self.root/'main.lua').write_text('local m=require("lib.math");return m.x')
        (self.root/'lib/math.lua').write_text('return {x=7}')
        self.document={'project':{'root':'src','output':'out'},'passes':['minify'],'signature':{'mode':'none'}}
        self.api=Api()

    def tearDown(self):
        self.api._builds.close();self.api._execution.close();self.temp.cleanup()

    def preview(self):
        result=self.api.preview_project({'document':self.document,'base':str(self.base)})
        self.assertTrue(result['ok'],result);return result['plan']

    def wait(self,identity):
        deadline=time.monotonic()+60;events=[];cursor=0
        while time.monotonic()<deadline:
            value=self.api.poll_build(identity,cursor);self.assertTrue(value['ok'],value)
            events.extend(value['events']);cursor=value['cursor']
            if value['done']:return self.api.get_build_result(identity),events
            time.sleep(.01)
        self.fail('Project GUI build timed out')

    def start(self,plan):
        value=self.api.start_build({'mode':'project','plan_id':plan['plan_id'],'document':copy.deepcopy(self.document)})
        self.assertTrue(value['ok'],value);return self.wait(value['id'])

    def test_preview_plan_is_the_actual_streaming_build_plan(self):
        self.document['project'].update(seed=4,backend_selection={'mode':'weighted','weights':{'bare':1,'classic':2}})
        plan=self.preview();result,events=self.start(plan)
        self.assertTrue(result['ok'],result);report=result['report']
        self.assertEqual(plan['plan_id'],report['plan_id'])
        self.assertEqual([(r['path'],r['preset'],r['backend']) for r in plan['modules']],
                         [(r['path'],r['planned_preset'],r['planned_backend']) for r in report['modules']])
        module_events=[e for e in events if e['phase'].startswith('project:') and e['phase']!='project:publish']
        self.assertEqual(2,sum(e['status']=='running' for e in module_events))
        self.assertEqual(2,sum(e['status']=='success' for e in module_events))
        output=self.api.read_project_output({'plan_id':plan['plan_id'],'path':'main.lua'})
        self.assertTrue(output['ok'],output);self.assertIn('require',output['content'])

    def test_discovery_works_before_output_and_invalid_entry_are_resolved(self):
        self.document['project'].pop('output');self.document['project']['entry']='missing.lua'
        found=self.api.discover_project({'document':self.document,'base':str(self.base)})
        self.assertTrue(found['ok'],found);self.assertEqual(2,len(found['files']['modules']))
        self.assertFalse(self.api.preview_project({'document':self.document,'base':str(self.base)})['ok'])
        self.assertFalse(self.api._project_plans)
        self.document['project'].update(output='out',entry='')
        (self.root/'main.lua').unlink()
        plan=self.preview();result,_=self.start(plan)
        self.assertTrue(result['ok'],result);self.assertIsNone(result['report']['entry'])

    def test_settings_sources_and_output_tampering_are_rejected(self):
        plan=self.preview();self.document['project']['backend_selection']={'mode':'fixed','value':'bare'}
        result,_=self.start(plan);self.assertFalse(result['ok']);self.assertFalse((self.base/'out').exists())
        plan=self.preview();(self.root/'extra.lua').write_text('return 0')
        result,_=self.start(plan);self.assertFalse(result['ok']);self.assertIn('changed',result['error'])
        plan=self.preview();result,_=self.start(plan);self.assertTrue(result['ok'],result)
        (self.base/'out/main.lua').write_text('changed output')
        self.assertFalse(self.api.read_project_output({'plan_id':plan['plan_id'],'path':'main.lua'})['ok'])
        self.assertFalse(self.api.read_project_output({'plan_id':plan['plan_id'],'path':'../src/main.lua'})['ok'])
        self.assertFalse(self.api.read_project_output({'plan_id':'unknown','path':'main.lua'})['ok'])

    def test_failure_report_is_available_without_publishing(self):
        plan=self.preview()
        with patch('obfuscator.project_build.build_pipeline_from_config',side_effect=ValueError('intentional failure')):
            result,events=self.start(plan)
        self.assertFalse(result['ok']);self.assertFalse(result['report']['published'])
        self.assertEqual('failed',result['report']['modules'][0]['status'])
        self.assertTrue(any(e['phase'].startswith('project:') and e['status']=='error' for e in events))
        self.assertFalse((self.base/'out').exists())

    def test_no_vm_modules_report_actual_native_status(self):
        self.document.update(passes=['vm'],vm_options=options('bare'),vm_output_passes=['minify'])
        (self.root/'main.lua').write_text('--@NO_VM_START\nreturn 7\n--@NO_VM_END')
        plan=self.preview();result,_=self.start(plan);self.assertTrue(result['ok'],result)
        main=next(r for r in result['report']['modules'] if r['path']=='main.lua')
        self.assertEqual('bare',main['planned_backend']);self.assertIsNone(main['backend']);self.assertFalse(main['vm_applied'])

    def test_copied_empty_passes_are_not_replaced_with_vm_and_results_are_explicit(self):
        self.document.update(passes=[],vm_output_passes=['minify'],signature={'mode':'default'})
        self.document['project'].update(preset_selection={'mode':'fixed','value':'custom'},backend_selection={'mode':'fixed','value':'bare'})
        plan=self.preview()
        self.assertTrue(all(row['vm_requested'] is False and row['transforms_requested'] is False for row in plan['modules']))
        self.assertTrue(all(row['effective_config']['passes']==[] for row in plan['modules']))
        result,_=self.start(plan);self.assertTrue(result['ok'],result)
        self.assertTrue(result['report']['warnings'])
        self.assertTrue(all(row['protection_status']=='signature_only' and row['backend'] is None for row in result['report']['modules']))

    def test_config_dialog_roundtrip_rebases_relative_paths(self):
        source=self.base/'project.json';source.write_text(json.dumps(self.document))
        destination=self.base/'config/saved.json';destination.parent.mkdir()
        window=SimpleNamespace(create_file_dialog=lambda *args,**kwargs:[str(source)])
        with patch.object(obfuscator_gui.webview,'windows',[window]):
            loaded=self.api.load_project();self.assertTrue(loaded['ok'],loaded)
            window.create_file_dialog=lambda *args,**kwargs:[str(destination)]
            saved=self.api.save_project({'document':loaded['document'],'base':loaded['base']})
            self.assertTrue(saved['ok'],saved)
            self.assertEqual(self.root,(Path(saved['base'])/saved['document']['project']['root']).resolve())
            self.assertEqual(saved['document'],json.loads(destination.read_text()))
            window.create_file_dialog=lambda *args,**kwargs:None
            self.assertIsNone(self.api.load_project());self.assertIsNone(self.api.save_project({'document':self.document}))

    def test_tree_and_actual_backend_labels(self):
        node=shutil.which('node')
        if not node:self.skipTest('Node not installed; browser helper checks are optional')
        code='''const assert=require('assert');const p=require(process.argv[1]);
const tree=p.rowsToTree([{path:'main.lua'},{path:'lib/math.lua'},{path:'assets/data.json',kind:'resource'}]);
assert.equal(tree.children.get('lib').children.get('math.lua').row.path,'lib/math.lua');
assert.equal(p.backendLabel({backend:'bare'},false),'Bare');
assert.equal(p.backendLabel({status:'discovered'},false),'Not checked');
assert.equal(p.backendLabel({status:'pending',backend:'bare',vm_requested:false},false),'No VM');
assert(p.backendMatches({backend:'bare',vm_requested:false},'none',false));
assert(!p.backendMatches({backend:'bare',vm_requested:false},'bare',false));
assert(p.backendMatches({backend:null,planned_backend:'bare',vm_applied:false,actual_backends:[]},'none',true));
assert(!p.backendMatches({backend:null,planned_backend:'bare',vm_applied:false,actual_backends:[]},'bare',true));
assert(p.backendMatches({backend:'mixed',vm_applied:true,actual_backends:['bare','classic']},'bare',true));
assert.equal(p.backendLabel({status:'success',backend:null,planned_backend:'bare',vm_applied:false},true),'No VM');
assert.equal(p.backendLabel({status:'failed',backend:null,planned_backend:'bare'},true),'Not Applied');
assert.equal(p.backendLabel({kind:'resource',status:'copied'},true),'Copied');'''
        subprocess.run([node,'-e',code,str(ROOT/'gui/web/project.js')],check=True)


if __name__=='__main__':unittest.main()
