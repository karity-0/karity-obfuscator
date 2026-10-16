"""GUI build events and result data must not change protected programs."""
from pathlib import Path
import hashlib
import json
import random
import subprocess
import sys
import threading
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT/'tools'))
from obfuscator_gui import Api, _normalize_preferences, _vm_option_meta
from obfuscator.gui_build import GuiBuild
from obfuscator.profiling import observe_build, phase_scope
from obfuscator.vm.backends.base import VMBackend
from profile_vm_runtime import execute


def wait(builds, identity):
    deadline = time.monotonic()+30
    cursor, events = 0, []
    while time.monotonic() < deadline:
        status = builds.poll(identity, cursor)
        assert status['ok'], status
        events.extend(status['events'])
        cursor = status['cursor']
        if status['done']:
            assert not builds.poll(identity, cursor)['events']
            return builds.result(identity), events
        time.sleep(0.01)
    raise AssertionError('GUI build did not finish')


def lifecycle_checks():
    entered, release = threading.Event(), threading.Event()
    received = []
    def build(payload):
        received.append(payload)
        with phase_scope('outer'):
            entered.set(); assert release.wait(5)
            with phase_scope('inner'):
                if payload.get('fail'): raise ValueError('intentional failure')
        return {'ok': True, 'output': payload['script']}
    runner = GuiBuild(build)
    payload = {'script': 'original'}
    start = runner.start(payload); assert start['ok']; assert entered.wait(5)
    payload['script'] = 'modified'
    assert not runner.start(payload)['ok']
    live = runner.poll(start['id']); assert not live['done']
    assert live['events'][0]['status'] == 'running'
    assert not runner.result(start['id'])['ok']
    release.set()
    result, events = wait(runner, start['id'])
    assert result['output'] == 'original' and received[0]['script'] == 'original'
    assert [e['status'] for e in events] == ['running','running','success','success']
    assert events[1]['parent'] == events[0]['id']
    failure = runner.start({'fail': True})
    result, events = wait(runner, failure['id'])
    assert not result['ok'] and result['failed_phase'] == 'inner'
    assert 'intentional failure' in result['error']
    assert not runner.poll(start['id'])['ok']
    runner.close(); assert not runner.start({})['ok']
    assert not runner.result(failure['id'])['ok']
    # Broken UI observers cannot fail a pipeline; context is cleared afterwards.
    with observe_build(lambda _: (_ for _ in ()).throw(ValueError('display failure'))):
        with phase_scope('safe'): pass
    with phase_scope('unobserved'): pass
    events = []
    with observe_build(events.append):
        with phase_scope('output:transforms'):
            with phase_scope('source:StringObfuscationPass'): pass
    assert events[1]['phase'] == 'output:StringObfuscationPass'


def marker_checks(api):
    assert 'quick_vm_change' not in _normalize_preferences({'quick_vm_change': True})
    for kind in ('VM','VM_START','FUNCTION_OBF','FUNCTION_OBF_START'):
        assert api.validate_marker_options({'kind':kind,'options':'','config':{}})['ok']
    function = api.validate_marker_options({'kind':'FUNCTION_OBF','options':'cff=true, junk=false','config':{}})
    assert function['options'] == {'cff':True,'junk':False}
    split = api.validate_marker_options({'kind':'FUNCTION_OBF','options':'split','config':{}})
    assert split['options']['cff'] and split['options']['boundary_mode'] == 'split'
    for options in ('junk_rate=0.1','max_pass_instructions=1000','cff=1','split,cff=false','cff=true\njunk=false'):
        assert not api.validate_marker_options({'kind':'FUNCTION_OBF','options':options,'config':{}})['ok'], options
    assert not api.validate_marker_options({'kind':'NO_VM','options':'junk=true'})['ok']
    config = {'_selection_profiles': {'custom': {'vm_options': {'backend':'mov','vm_count':2}}}}
    vm = api.validate_marker_options({'kind':'VM_START','options':'profile="custom",junk_rate=0.1','config':config})
    assert vm['ok'] and vm['effective']['backend'] == 'mov' and vm['effective']['vm_count'] == 2
    for field in _vm_option_meta():
        if 'max' in field: assert field['min'] <= field['max'], field
    schema = api.marker_fields()
    for field in schema['function_obf']:
        value = True if field['kind']=='boolean' else field['choices'][0] if field['kind']=='enum' else field['min']
        assert api.validate_marker_options({'kind':'FUNCTION_OBF','options':f"{field['name']}={json.dumps(value)}"})['ok'], field
    for field in schema['vm']:
        assert field['kind'] in ('boolean','enum','integer','number'), field


def pipeline_checks(api):
    payload = {'script':'print("한글🌸")','preset':'builtin:fast',
               'config': {'passes':['minify'],'signature':{'mode':'none'}}}
    baseline = api.run_obfuscation(payload)
    started = api.start_build(payload)
    result, events = wait(api._builds, started['id'])
    assert result['ok'] and result['output'] == baseline['output']
    m = result['metadata']
    assert m['source_bytes'] == len(payload['script'].encode('utf-8'))
    assert m['output_bytes'] == len(result['output'].encode('utf-8'))
    assert m['output_characters'] == len(result['output']) and m['size_ratio'] == 1
    assert m['source_hash'] == hashlib.sha256(payload['script'].encode()).hexdigest()
    assert result['build_elapsed'] >= result['profile']['total_elapsed']
    assert 'vm:generation' not in {e['phase'] for e in events}
    failed = api.start_build({'script':'print(1)','config':{'passes':['unknown']}})
    failure, events = wait(api._builds, failed['id'])
    assert not failure['ok'] and failure['failed_phase'] == 'configuration'
    # Observer effects are compared before runtime-dependent integrity/encryption.
    blobs = []
    serialize = VMBackend.serialize_program
    def capture(*args, **kwargs):
        blob = serialize(*args, **kwargs); blobs.append(blob); return blob
    payload = {'script':'local function f(x) return x+1,nil,3 end; print(f(4))',
               'config':{'passes':['vm'],'vm_output_passes':[], 'vm_options':{'backend':'karity'}, 'signature':{'mode':'none'}}}
    outputs, observed = [], []
    with patch.object(VMBackend, 'serialize_program', capture):
        random.seed(8471); outputs.append(api.run_obfuscation(payload))
        random.seed(8471)
        with observe_build(observed.append): outputs.append(api.run_obfuscation(payload))
    assert all(r['ok'] for r in outputs), outputs
    assert len(blobs)==2 and blobs[0]==blobs[1]
    assert execute(outputs[0]['output'])[0] == execute(outputs[1]['output'])[0] == b'5\tnil\t3'
    phases = {e['phase'] for e in observed}
    assert {'vm:compile','vm:ir','vm:serialization','vm:graphs','output:transforms','vm:integrity'} <= phases
    starts = {e['id'] for e in observed if e['status']=='running'}
    finishes = {e['id'] for e in observed if e['status'] in ('success','error')}
    assert starts==finishes
    # Selective macros add real stages even when their source pass is disabled.
    markers = api.start_build({'script':'print(STRING_OBF("hello"))','config':{'passes':[]}})
    result, events = wait(api._builds, markers['id'])
    assert result['ok'], result
    assert any('StringObfuscationPass' in e['phase'] for e in events)


def javascript_checks():
    script = r'''
const assert=require('node:assert/strict');
const m=require('./gui/web/experience.js');
const source='local x=1\nprint(x)\nprint("tail")\n';
const edit=m.markerEdit(source,0,19,'VM_START','profile="fast-vm", junk_rate=0.05');
assert.equal(edit.replacement,'--@VM_START(profile="fast-vm", junk_rate=0.05)\nlocal x=1\nprint(x)\n--@VM_END\n');
assert.equal(source.slice(edit.end),'print("tail")\n');
assert.equal(m.markerEdit('print("🌸")',6,10,'STRING_OBF').replacement,'STRING_OBF("🌸")');
assert.throws(()=>m.markerEdit('print(1)',0,0,'VM_START'));
assert.equal(m.markerEdit('print(1)',3,3,'VM').start,0);
assert.deepEqual(m.configChanges({a:{b:1},x:[1,2]},{x:[1,2],a:{b:2}}),[{path:'a.b',before:1,after:2}]);
const a={source_hash:'a',config_hash:'b',preset:'fast',backend:'mov',checks:{release:false}};
assert(m.sameBuild(a,{...a})); assert(!m.sameBuild(a,{...a,source_hash:'different'}));
assert.equal(m.serializeOptions({cff:true,junk:false}),'cff=true, junk=false');
const fs=require('node:fs'), vm=require('node:vm');
const editor={window:{}};
vm.runInNewContext(fs.readFileSync('./gui/web/editor.js','utf8'),editor);
const tokens=editor.window.LuaCodeEditor.tokenize;
assert.equal(tokens('--@NO_VM_START\nx=true\n--@NO_VM_END')[0].kind,'marker-start');
assert.equal(tokens('--@NO_VM_START\nx=true\n--@NO_VM_END').at(-1).kind,'marker-end');
assert.equal(tokens('--@VM')[0].kind,'marker');
assert.equal(tokens('--@VM(profile="NAME_START")')[0].kind,'marker');
assert.equal(tokens('--@NO_VM_END -- comment_START')[0].kind,'marker-end');
assert.equal(tokens('-- @NO_VM_START')[0].kind,'comment');
assert(!tokens('@NO_VM_END').some(t=>t.kind.startsWith('marker')));
assert.equal(tokens('local text="--@NO_VM_START"').at(-1).kind,'string');
assert(!tokens('--@NO_OBF').some(t=>t.kind.startsWith('marker')));
assert.equal(tokens('continue')[0].kind,'keyword');
assert.equal(tokens('KARITY_PANIC()')[0].kind,'builtin');
assert.equal(tokens('0b10_10')[0].kind,'number');
assert.equal(tokens('x ??= 1')[0].kind,'operator');
assert.equal(tokens('x?.name')[0].kind,'operator');
assert.equal(tokens('s ..= "tail"')[0].kind,'operator');
assert.equal(tokens('.1_0')[0].kind,'number');
'''
    subprocess.run(['node','-e',script],cwd=ROOT,check=True)


def main():
    lifecycle_checks(); javascript_checks()
    api=Api()
    try:
        marker_checks(api); pipeline_checks(api)
    finally:
        api._builds.close(); api._execution.close()
    print('gui-experience-regression-ok lifecycle, markers, bytes, provenance, unchanged blob/execution')

if __name__=='__main__': main()
