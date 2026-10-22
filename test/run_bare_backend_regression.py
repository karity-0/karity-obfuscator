"""Bare lowering compared with native Lua, including lifetime and output passes."""
from pathlib import Path
import json
import random
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from obfuscator import Pipeline, build_pipeline_from_config
from obfuscator.registry import ConfigError, validate_config, resolve_config_profile
from obfuscator.vm import VMPass
from obfuscator.vm.targets.profile import TargetProfile
from run_cross_backend_generated_regression import execute, generated_source
from run_vm_backend_regression import options


def build(source, version, passes=(), extra=None, expected=None):
    random.seed(7719)
    vm = VMPass(target=TargetProfile(version, 'bare'),
                vm_options={**options('bare'), **(extra or {})}, vm_output_passes=list(passes))
    output = vm.run(source)
    assert vm.last_lowered_ir.backend == 'bare'
    assert 'layout' not in vm.last_lowered_ir.backend_data
    assert any(p['phase'] == 'bare_codegen' for p in vm.last_profile)
    assert next(p for p in vm.last_profile if p['phase']=='bare_codegen')['block_dispatcher'] is True
    assert not any(p['phase'] == 'serialize_blob' for p in vm.last_profile)
    assert execute(version, output) == (execute(version, source) if expected is None else expected.rstrip(b'\r\n')), (version, passes, source[:120])
    return output


def main():
    for version in ('5.1', '5.3'):
        flow = 'local n=0;while n<4 do n=n+1 end;if n%2==0 then print(n) else print(-n) end'
        dispatched = build(flow, version)
        assert 'while _Bposition do' in dispatched
        assert 'read_proto' not in dispatched and 'goto ' not in dispatched
        for fixture in ('vm_unexpected.lua', 'opcode_edges.lua', 'opcode_numeric_matrix.lua'):
            build((ROOT / 'test/fixtures' / fixture).read_text(encoding='utf8'), version)
        for seed in range(4):
            build(generated_source(seed), version)
        # Closing cells per iteration, empty loops, open results, nils and spills.
        source = '''
local cells={};for i=1,4 do local v=i;cells[i]=function() return v end end
for i=1,3 do end
local function values(...) return ... end
local function packet(...) return {n=select('#',...),...} end
local p=packet(values(1,nil,false,nil));assert(p.n==4 and p[3]==false)
print(cells[1](),cells[4](),p.n,p[1],p[2],p[3],p[4])
'''
        literal_passes = ('string_obf','number_obf','meme_strings','minify') if version == '5.3' else ('string_encode','minify')
        for passes in ((), ('strip_info','rename_obf','minify'), literal_passes,
                       ('function_obf','rename_obf','minify')):
            build(source, version, passes)
        build(generated_source(19), version, extra={
            'junk_instructions': True, 'junk_rate': 0.2,
            'ir_test_set_rate': 1.0, 'ir_tail_duplication_rate': 1.0})
        # Many prototypes must not exhaust the native local-variable limit.
        many = 'local f={}\n' + '\n'.join(f'f[{i}]=function() return {i} end' for i in range(1, 221)) + '\nprint(f[1](),f[220]())'
        build(many, version)
        parameters = ','.join('p' + str(i) for i in range(200))
        arguments = ','.join(str(i) for i in range(200))
        build('local function wide(' + parameters + ') return p0+p199 end\nprint(wide(' + arguments + '))', version)
        parameters = ','.join('p' + str(i) for i in range(190))
        arguments = ','.join(str(i) for i in range(190))
        build('local function wide(' + parameters + ',...) local n=0;for i=1,3 do n=n+i end;local function f() return p189 end;return p0+f()+n,... end\nprint(wide(' + arguments + ',nil,false,nil))', version)
        destinations = ','.join('v' + str(i) for i in range(150))
        build('local function values() return 1,nil,false,4 end\nlocal ' + destinations + '=values()\nprint(v0,v1,v2,v3,v149)', version)
        # Bare participates in the real preset and selective-protection paths.
        config = resolve_config_profile(json.loads((ROOT / 'config.example.json').read_text()), 'fast')
        config['target'] = {'lua_version': version}
        config['vm_options']['backend'] = 'bare'
        config['signature'] = {'mode': 'none'}
        if version == '5.1':
            config['passes'] = ['vm']
            config['vm_output_passes'] = ['strip_info', 'rename_obf', 'minify']
            config['packer_output_passes'] = []
        pipeline = build_pipeline_from_config(config, Pipeline)
        assert execute(version, pipeline.run('print("hi")')) == execute(version, 'print("hi")')
        selective = 'local n=2\n--@VM_START\nn=n+5\n--@VM_END\nprint(n)'
        pipeline = build_pipeline_from_config({'passes': [], 'vm_options': options('bare'),
            'target': {'lua_version': version}, 'signature': {'mode': 'none'}}, Pipeline)
        if version == '5.3':
            assert execute(version, pipeline.run(selective)) == execute(version, selective)
        else:
            from obfuscator.selection import SelectionError
            try:
                pipeline.run(selective)
            except SelectionError:
                pass
            else:
                raise AssertionError('Lua 5.1 unexpectedly accepted selective VM boundaries')
        small = build('print("hi")', version, ('strip_info','rename_obf','minify'))
        assert len(small.encode()) < 20000
        assert all(marker not in small for marker in ('KARITY/', 'read_proto', '_ksm', 'unknown op'))
        # Getter values identify this backend's semantic representation.
        build('''local h=KARITY_GET_SCRIPT_HASH();local l=KARITY_GET_LAYOUT_HASH()
assert(h>=0 and h<4294967296 and l>=0 and l<4294967296)
assert(KARITY_GET_VM_COUNT()==1 and KARITY_GET_VM_ID()==0)
assert(KARITY_GET_CODE_LENGTH()>0)
assert(select('#',KARITY_GET_VM_COUNT())==1)
local a,b=KARITY_GET_VM_COUNT();assert(a==1 and b==nil)
assert(select('#',KARITY_ASSERT(true))==0)
print('intrinsics-ok')''', version, expected=b'intrinsics-ok\n')
        build('''local function bad() KARITY_ABORT() end
assert(not pcall(bad));KARITY_ASSERT(true)
assert(not pcall(function() KARITY_ASSERT(false) end))
local old=error;error=function() return 'ignored' end
local ok=pcall(bad);error=old;assert(not ok)
print('abort-ok')''', version, expected=b'abort-ok\n')
        from tools.explore_vm_semantics import execute as execute_file
        with tempfile.TemporaryDirectory(prefix='bare-chunk-') as folder:
            work = Path(folder)
            for fixture in ('vm_chunk_interface', 'vm_embedded_interface'):
                source = (ROOT / 'test/fixtures' / (fixture + '.lua')).read_text(encoding='utf8')
                path, original = work / 'output.lua', work / 'original.lua'
                original.write_text(source, encoding='utf8')
                path.write_text(VMPass(target=TargetProfile(version, 'bare'), vm_options=options('bare')).run(source), encoding='utf8')
                harness = ROOT / 'test/fixtures' / (fixture + '_harness.lua')
                expected_result = execute_file(original, version, harness=harness)
                actual_result = execute_file(path, version, harness=harness)
                assert expected_result['returncode'] == actual_result['returncode'] == 0, actual_result
                assert expected_result['stdout'] == actual_result['stdout'], (fixture, version, actual_result)
            panic = '''return function()return 7 end,function()KARITY_PANIC() end,
function()pcall(function()KARITY_PANIC() end);return true end,
function()return coroutine.yield('paused') end,function(a,b)return a+b+b end'''
            path.write_text(VMPass(target=TargetProfile(version, 'bare'), vm_options=options('bare')).run(panic), encoding='utf8')
            observer = work / 'panic.lua'
            observer.write_text('''local function instance()return assert(loadfile(arg[1]))() end
local good,panic,caught,wait=instance()
local co=coroutine.create(wait);assert(coroutine.resume(co));assert(good()==7)
assert(not pcall(panic));assert(not pcall(good));assert(not coroutine.resume(co))
local fresh,_,inner=instance();assert(fresh()==7);assert(not pcall(inner));assert(not pcall(fresh))
local _,fail,_,_,apply=instance();local n=0;local object
object=setmetatable({}, {__add=function() n=n+1;if n==1 then pcall(fail) end;return object end})
assert(not pcall(apply,object,object));assert(n==1)
print('panic-ok')''', encoding='utf8')
            result = execute_file(path, version, harness=observer)
            assert result['returncode'] == 0 and result['stdout'] == 'panic-ok\n', (version, result)
    # Lua 5.1 environment changes remain attached to the actual emitted closure.
    build('''local f=function() return marker end
setfenv(f,{marker=42});print(f())''', '5.1')
    # Native source gotos become block transitions, including irreducible flow.
    jumped = build('''local n=0;if (...) then goto second end
::first:: n=n+1;if n>3 then goto finish end
::second:: n=n+1;if n<4 then goto first end
::finish:: for i='1','3','1' do n=n+i end;print(n)''', '5.3')
    assert 'goto ' not in jumped and 'while _Bposition do' in jumped
    try:
        validate_config({'vm_options': {'backend': 'bare', 'requirements': {'graph_execution':'required'}}})
    except ConfigError:
        pass
    else:
        raise AssertionError('Bare accepted a required runtime graph feature')
    from obfuscator_gui import _vm_option_meta
    choices = next(field['values'] for field in _vm_option_meta() if field['name']=='backend')
    assert next(item for item in choices if item['value']=='bare')['label']=='Bare'
    from obfuscator.vm.targets.pass_requirements import validate_pass_target
    try:
        validate_pass_target('vm', TargetProfile('5.3', 'bare', compatibility='portable',
                             disabled_capabilities=frozenset({'debug_library','function_dump'})))
    except ValueError:
        pass
    else:
        raise AssertionError('protected Bare accepted missing identity primitives')
    subprocess.run([sys.executable, 'tools/generate_config_docs.py', '--check'], cwd=ROOT, check=True)
    print('bare-backend-regression-ok Lua 5.1/5.3 native oracles, GC, loops, passes, presets, selective, chunk interfaces, intrinsics')


if __name__ == '__main__':
    main()
