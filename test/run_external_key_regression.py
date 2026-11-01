"""External keys must affect decryption without entering guest arguments/reports."""
from pathlib import Path
from unittest.mock import patch
import copy
import json
import random
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from obfuscator import Pipeline, build_pipeline_from_config
from obfuscator.gui_execution import json_lua_string
from obfuscator.passes.packer import PackerPass
from obfuscator.project import ProjectError, create_plan, validate_plan
from obfuscator.project_build import build_project
from obfuscator.registry import ConfigError, redact_config, resolve_config_profile, validate_config
from obfuscator.toolchain import LuaToolchain
from run_vm_backend_regression import options

KEY = 'external-test-secret/한글/"\\\0/end '
GUEST = '''
assert(select('#',...)==4)
local a,b,c,d=...
assert(a==17 and b==nil and c=='guest' and d==nil)
local counter=0
local function callback(v) counter=counter+v;return counter,nil end
print('guest-executed')
return callback,nil,'tail',nil
'''


class ExternalKeyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='karity-key-test-')
        self.base = Path(self.temp.name)
        self.lua = LuaToolchain().lua()

    def tearDown(self):self.temp.cleanup()

    def config(self, backend=None, key=KEY):
        config = {'passes': ['vm','pack'] if backend else ['pack'],
                  'vm_output_passes': ['minify'], 'packer_output_passes': ['minify'],
                  'signature': {'mode':'custom','custom':'key test\nsecond line'}}
        if backend:config['vm_options'] = options(backend)
        if key is not None:config['packer_options'] = {'external_key':key}
        return config

    def build(self, source=GUEST, backend=None, key=KEY, transforms=None):
        config = self.config(backend,key)
        if transforms is not None:config['packer_output_passes'] = transforms
        packed = build_pipeline_from_config(config,Pipeline).run(source)
        self.assertNotIn(KEY,packed)
        path = self.base/'protected.lua';path.write_text(packed,encoding='utf8')
        return path

    def run_lua(self, source):
        path = self.base/'driver.lua';path.write_text(source,encoding='utf8')
        return subprocess.run([self.lua,str(path)],capture_output=True,timeout=20,cwd=self.base)

    def assert_hidden(self, value):
        self.assertNotIn(json.dumps(KEY,ensure_ascii=False)[1:-1],json.dumps(value,ensure_ascii=False))

    def invocation(self, path, key=KEY):
        return f'assert(loadfile({json_lua_string(str(path))}))({json_lua_string(key)},17,nil,"guest",nil)'

    def assert_success(self, path):
        result = self.run_lua('local r=table.pack('+self.invocation(path)+''');
assert(r.n==4 and type(r[1])=='function' and r[2]==nil and r[3]=='tail' and r[4]==nil)
assert(r[1](2)==2);assert(r[1](3)==5);collectgarbage('collect');assert(r[1](4)==9)
print('return-ok')''')
        self.assertEqual(0,result.returncode,result.stderr.decode(errors='replace'))
        self.assertEqual(['guest-executed','return-ok'],result.stdout.decode().split())

    def test_source_and_all_backends_preserve_arguments_returns_and_callbacks(self):
        for backend in (None,'classic','karity','mov','bare'):
            with self.subTest(backend=backend):
                path = self.build(backend=backend)
                self.assert_success(path)
                wrong = self.run_lua(self.invocation(path,'wrong-secret'))
                self.assertNotEqual(0,wrong.returncode)
                self.assertNotIn(b'guest-executed',wrong.stdout)

    def test_invalid_keys_never_enter_guest(self):
        path = self.build('print("guest-executed");return 42')
        for arguments in ('','nil','false','123','{}','""','"wrong-secret"'):
            with self.subTest(arguments=arguments):
                result = self.run_lua(f'assert(loadfile({json_lua_string(str(path))}))({arguments})')
                self.assertNotEqual(0,result.returncode)
                self.assertNotIn(b'guest-executed',result.stdout)
        good = self.run_lua('print('+self.invocation(path)+')')
        self.assertEqual(0,good.returncode,good.stderr)
        self.assertIn(b'42',good.stdout)

    def test_loader_transformations_and_native_cli_arguments(self):
        # The key is a chunk argument, not another loader in the emitted output.
        for transforms in ([],['rename_obf','string_encode','minify']):
            with self.subTest(transforms=transforms):
                self.assert_success(self.build(transforms=transforms))
        key = 'cli-test-key'
        path = self.build('assert(select("#",...)==0);print("cli-ok")',key=key)
        result = subprocess.run([self.lua,str(path),key],capture_output=True,timeout=20)
        self.assertEqual(0,result.returncode,result.stderr)
        self.assertEqual(b'cli-ok',result.stdout.strip())

    def test_existing_unkeyed_builds_preserve_the_first_argument(self):
        path = self.build(key=None)
        result = self.run_lua('local r=table.pack(assert(loadfile('+json_lua_string(str(path))+
                              '))(17,nil,"guest",nil));assert(r.n==4)')
        self.assertEqual(0,result.returncode,result.stderr)
        path = self.build(key=None,source='assert(select("#",...)==0);print("no-key-ok")')
        result = subprocess.run([self.lua,str(path)],capture_output=True,timeout=20)
        self.assertEqual(0,result.returncode,result.stderr)

    def test_selective_vm_and_custom_environment_keep_the_key_private(self):
        source = '''
local a,b,c,d=...
assert(select('#',...)==4 and a==17 and b==nil and c=='guest' and d==nil)
--@VM_START
local n=2;assert(n+string.byte('A')==67)
--@VM_END
return a,b,c,d
'''
        config = self.config('classic');config['selection_modes'] = {'vm':'marked'}
        output = build_pipeline_from_config(config,Pipeline).run(source)
        path = self.base/'selective.lua';path.write_text(output,encoding='utf8')
        result = self.run_lua('local env=setmetatable({},{__index=_G});local r=table.pack('
            'assert(loadfile('+json_lua_string(str(path))+',"t",env))('+json_lua_string(KEY)+
            ',17,nil,"guest",nil));assert(r.n==4 and r[1]==17 and r[2]==nil and r[3]=="guest" and r[4]==nil)')
        self.assertEqual(0,result.returncode,result.stderr)

    def test_key_changes_ciphertext_and_existing_loader_integrity_remains(self):
        source = 'print("guest-executed");return 42'
        # Freeze build randomness: changing just the key must change the payload,
        # while the finalized loader contains no embedded key/check value.
        random.seed(412)
        with patch('obfuscator.passes.packer.secrets.randbits',return_value=1234567), \
             patch('obfuscator.passes.packer._distinct_slots',side_effect=lambda n:list(range(100,100+n))):
            first = PackerPass(external_key='secret-A').run(source)
        random.seed(412)
        with patch('obfuscator.passes.packer.secrets.randbits',return_value=1234567), \
             patch('obfuscator.passes.packer._distinct_slots',side_effect=lambda n:list(range(100,100+n))):
            second = PackerPass(external_key='secret-B').run(source)
        self.assertEqual(first.split('local _D=')[0],second.split('local _D=')[0])
        self.assertNotEqual(first,second)
        path = self.base/'protected.lua'
        path.write_text(first.replace('0x811C9DC5','0x811C9DC4',1),encoding='utf8')
        result = self.run_lua(self.invocation(path,'secret-A'))
        self.assertNotEqual(0,result.returncode)
        self.assertNotIn(b'guest-executed',result.stdout)

    def test_configuration_requires_packer_and_reports_hide_keys(self):
        for key in ('',False,1,[],{},'\ud800'):
            with self.subTest(key=repr(key)):
                with self.assertRaises(ConfigError):validate_config(self.config(key=key))
        config = self.config();config['passes'] = ['vm']
        with self.assertRaisesRegex(ConfigError,'requires pack'):validate_config(config)
        config = self.config();config['passes'] = ['pack','pack']
        with self.assertRaisesRegex(ConfigError,'exactly one pack'):validate_config(config)
        config = self.config();config['target'] = {'lua_version':'5.1'}
        with self.assertRaises(ConfigError):validate_config(config)
        config = self.config()
        self.assertEqual(KEY,resolve_config_profile(config,'builtin:maximum')['packer_options']['external_key'])
        saved = copy.deepcopy(config)
        public = redact_config({'profiles':{'nested':config}})
        self.assert_hidden(public)
        self.assertEqual(saved,config)
        file = self.base/'config.json';file.write_text(json.dumps(config),encoding='utf8')
        result = subprocess.run([sys.executable,str(ROOT/'main.py'),'-c',str(file),'--print-config'],
                                cwd=ROOT,capture_output=True,timeout=20)
        self.assertEqual(0,result.returncode,result.stderr)
        self.assertEqual('<redacted>',json.loads(result.stdout)['packer_options']['external_key'])

    def test_project_outputs_redact_keys_and_keep_private_plan_sealed(self):
        root = self.base/'src';root.mkdir()
        (root/'main.lua').write_text('assert(select("#",...)==0);return 42',encoding='utf8')
        document = {**self.config(),'project':{'root':'src','output':'out'}}
        plan = create_plan(document,self.base)
        self.assertTrue(plan.valid)
        self.assertTrue(any('require/dofile' in w for w in plan.modules[0].warnings))
        self.assert_hidden(plan.as_dict())
        report = build_project(plan)
        self.assertTrue(report['published'])
        self.assert_hidden(report)
        result = self.run_lua('assert(assert(loadfile('+json_lua_string(str(plan.output/'main.lua'))+
                              '))('+json_lua_string(KEY)+')==42)')
        self.assertEqual(0,result.returncode,result.stderr)
        plan.modules[0].config['packer_options']['external_key'] = 'changed'
        with self.assertRaisesRegex(ProjectError,'modified'):validate_plan(plan)

    def test_gui_build_and_execution_forward_key_only_to_output(self):
        import obfuscator_gui as gui
        with patch.object(gui,'CONFIG_PATH',self.base/'gui.json'),patch.object(gui,'PREFERENCES_PATH',self.base/'prefs.json'):
            api = gui.Api()
            try:
                config = self.config()
                source = 'assert(select("#",...)==0);print("gui-key-ok")'
                built = api.run_obfuscation({'script':source,'config':config})
                self.assertTrue(built['ok'],built.get('error'))
                self.assert_hidden(built)
                for target,script in (('source',source),('output',built['output'])):
                    started = api.start_execution({'script':script,'target':target,'config':config})
                    self.assertTrue(started['ok'],started)
                    deadline = time.monotonic()+20
                    while time.monotonic()<deadline:
                        result = api.poll_execution(started['id'])
                        if result['done']:break
                        time.sleep(0.02)
                    self.assertTrue(result['done'])
                    self.assertEqual(0,result['exit_code'],result)
                    self.assertIn('gui-key-ok',''.join(e['text'] for e in result['events']))
            finally:
                api._builds.close();api._execution.close()


if __name__=='__main__':unittest.main()
