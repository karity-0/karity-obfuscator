"""User/legacy resolution, runtime literal budgets and independent UI state."""
from pathlib import Path
import copy
import json
import random
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    from obfuscator.registry import resolve_config_profile, validate_config, build_pipeline_from_config, validate_deployment_config, validate_release_config, ReleaseCheckError
    from obfuscator.pipeline import Pipeline
    from obfuscator.presets import USER_PRESETS, PREFIX, REVISION
    from obfuscator.passes.literal_mosaic import LiteralMosaic, use_mosaic
    from obfuscator.passes.numeric_provenance import CodeText
    from obfuscator.passes.mosaic_metrics import expression_summary
    from obfuscator.vm.backends.runtime_emitter import _obfuscate_vm_output
    from obfuscator.vm.output_emitter import _parse_fragments, NumberLiteral
    from obfuscator.passes.ts_utils import parse
    from lupa.lua53 import LuaRuntime
    from types import SimpleNamespace
    from obfuscator.vm.backends.karity_state import _operation_accesses
    assert _operation_accesses(SimpleNamespace(operation='GET_UPVALUE_TABLE',a=4,b=8,c=325),8)==((),(4,))
    assert _operation_accesses(SimpleNamespace(operation='SET_UPVALUE_TABLE',a=10,b=1,c=3),4)==((1,3),())

    root = json.loads((ROOT/'config.example.json').read_text(encoding='utf-8'))
    before = copy.deepcopy(root)
    for name in ('dev','fast-vm','high','max'):
        resolved = resolve_config_profile(root, name)
        for key, value in root['profiles'][name].items():
            assert resolved[key] == value, (name,key)
    assert root == before
    collision = {'profiles': {'fast': {'passes': ['minify']}}, 'profile': 'fast'}
    assert resolve_config_profile(collision)['passes'] == ['minify']
    assert 'vm' in resolve_config_profile(collision, 'builtin:fast')['passes']
    assert resolve_config_profile({'passes': ['minify']})['passes'] == ['minify']

    for name in USER_PRESETS:
        config = resolve_config_profile({'vm_options': {'backend': 'mov'}}, name)
        assert config['vm_options']['backend'] == 'mov'
        assert 'string_encode' not in config['passes']
        assert 'function_obf' not in config['vm_output_passes']
        assert {'number_obf','meme_strings'} <= set(config['vm_output_passes'])
        assert config['vm_options']['opcode_synthesis'] is True
        assert config['vm_options']['synthesis_policy']=={'fast':'efficiency','balanced':'balanced','strong':'protection','maximum':'protection'}[name]
        validate_config(config)
        validate_deployment_config(config)
    try:
        validate_release_config(resolve_config_profile({}, 'fast'))
    except ReleaseCheckError:
        pass
    else:
        raise AssertionError('strict release policy changed for single VM')
    macro = resolve_config_profile({}, 'fast')
    macro['passes'] = []
    macro['signature'] = {'mode':'none'}
    source = '--@FUNCTION_OBF\nlocal function f(...) return STRING_FLOW_OBF("한글 hi"), NUMBER_OBF(42), ... end\nreturn f(nil,3,nil)'
    pipeline = build_pipeline_from_config(macro, Pipeline, show_header=False)
    random.seed(112)
    from obfuscator.profiling import Profiler
    profiler = Profiler()
    output = pipeline.run(source, profiler=profiler)
    lua = LuaRuntime(encoding=None, unpack_returned_tuples=True)
    assert lua.execute(output.encode()) == ('한글 hi'.encode(),42,None,3,None)
    assert 'STRING_FLOW_OBF' not in output and 'NUMBER_OBF' not in output
    assert any(record.name == 'FunctionObfuscationPass' for record in profiler.records)
    assert any(detail.get('cff_blocks',0) > 0
               for record in profiler.records for detail in record.details), 'StringObf reconstruction lost CFF'

    # Structural runtime provenance classifies nested callables/loops as hot;
    # the once-entered outer initialization is cold. Identifiers are arbitrary.
    code = 'return function(...) local initial=73; local function f() return 91 end; for i=1,3 do initial=initial+17 end; return initial,f() end'
    marked = CodeText(code, origins=[(0,len(code),'vm_entry')])
    parts, _ = _parse_fragments(marked, parse(marked), [], budgeted=True)
    tokens = {part.token: part for part in parts if isinstance(part,NumberLiteral)}
    assert not tokens['73'].hot and tokens['91'].hot and tokens['17'].hot
    unmarked, _ = _parse_fragments(code, parse(code), [], budgeted=True)
    assert all(part.hot for part in unmarked if isinstance(part,NumberLiteral))
    options = {'style':'exotic','cost':'high','max_operations':20,
               'output_cost': {'hot_operations':2,'cold_operations':6,'hot_meme_rate':0.2,'cold_meme_rate':0.4}}
    mosaic = LiteralMosaic(['number_obf','meme_strings'], options=options, phase='vm_output')
    for token in ('0','1','73','2147483647','9007199254740993','9223372036854775807',
                  '9223372036854775808','0xffffffffffffffff','0x8000000000000000',
                  '.25','0X1.Ap4','0.0','1e309','0x1p9999','9'*400):
        for seed in range(12):
            random.seed(seed)
            expression = mosaic.output_number(token, origin='vm_constant/hot', hot=True)
            assert expression_summary(expression)[2] <= 2, expression
            assert lua.eval(('function() local a='+token+'; local b='+expression+
                             '; return a==b and math.type(a)==math.type(b) end').encode())(), (token, expression)
    with use_mosaic(mosaic):
        random.seed(31)
        transformed, _ = _obfuscate_vm_output(marked, ['strip_info','rename_obf','meme_strings','number_obf','minify'])
    assert lua.execute(transformed.encode())() == (124,91)
    assert '#' in transformed  # visible memes survive final naming/minification

    notation_only = LiteralMosaic(['number_obf','meme_strings'],phase='vm_output',
        options={**options,'output_cost':{'hot_operations':0,'hot_meme_rate':0}})
    for token in ('42','0.0','1e309','0x1p9999'):
        expression=notation_only.output_number(token,origin='vm_constant/hot',hot=True)
        assert expression_summary(expression)[2]==0
        assert lua.eval(('function() local a='+token+';local b='+expression+
                         ';return a==b and math.type(a)==math.type(b) end').encode())()

    # Complete user policies use Lua 5.3 source/output passes. Retain explicit
    # rejection on Lua 5.1, rather than silently omitting unsupported layers.
    from obfuscator.registry import ConfigError
    from obfuscator.toolchain import LuaToolchain
    for backend in ('classic','karity','mov'):
        config=resolve_config_profile({'vm_options':{'backend':backend}}, 'fast')
        config['passes']=['vm'];config['signature']={'mode':'none'}
        random.seed(9301)
        output=build_pipeline_from_config(config, Pipeline, show_header=False).run(
            'local n=42;assert(n==42 and .25==1/4);_G.__preset_style="ok";print(_G.__preset_style)')
        # VM integrity binds the compiler's stripped dump. Execute through
        # that toolchain: Lupa's build produces a different dump fingerprint.
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'output.lua'
            path.write_text(output,encoding='utf-8')
            result=subprocess.run([LuaToolchain.from_config(config).lua(),str(path)],
                                  capture_output=True,timeout=30)
            assert result.returncode==0, (backend,result.stderr)
            assert result.stdout.strip()==b'ok', (backend,result.stdout)
        config['target']={'lua_version':'5.1'}
        config['packer_output_passes']=[]
        try:
            validate_config(config)
        except ConfigError as error:
            assert 'VM output pass meme_strings' in str(error), error
        else:
            raise AssertionError('Lua 5.1 output capability rejection was lost')

    # Exercise saved customized policies across backend and preset round trips.
    javascript = r'''
const assert = require('node:assert/strict');
const model = require('./gui/web/preset_state.js');
const base={preset:'builtin:fast',preset_revision:1,preset_custom:true,
  config:{passes:['vm'],vm_options:{backend:'mov',junk_rate:0.123},signature:{mode:'fake'}}};
const original=structuredClone(base);
let state=model.setBackend(base,'classic');
assert.equal(state.preset,base.preset); assert.equal(state.preset_custom,true);
assert.equal(state.config.vm_options.junk_rate,0.123); assert.deepEqual(base,original);
state=model.applyPreset(state,'builtin:strong',{passes:['string_obf','vm'],vm_options:{junk_rate:0.1}},2);
assert.equal(state.config.vm_options.backend,'classic'); assert.deepEqual(state.config.signature,base.config.signature);
state=model.applyPreset(JSON.parse(JSON.stringify(state)),'builtin:fast',{},999);
assert.equal(state.config.vm_options.junk_rate,0.123); assert.equal(state.preset_revision,1);
assert.equal(state.preset_custom,true); assert.equal(state.config.vm_options.backend,'classic');
'''
    subprocess.run(['node','-e',javascript], cwd=ROOT, check=True)
    from obfuscator_gui import Api
    import obfuscator_gui
    with tempfile.TemporaryDirectory() as folder:
        original_path=obfuscator_gui.CONFIG_PATH
        try:
            obfuscator_gui.CONFIG_PATH=Path(folder)/'settings.json'
            config=resolve_config_profile({},'balanced')
            config['vm_options']['backend']='classic'
            config['vm_options']['junk_rate']=0.123
            state={'preset':'builtin:balanced','preset_revision':REVISION,'preset_custom':True,
                   'config':config,'preset_snapshots':{'builtin:balanced':{'config':config,'revision':REVISION,'custom':True}}}
            assert Api().save_config(state)['ok']
            restored=Api().get_bootstrap()['state']
            assert restored['config']['vm_options']['backend']=='classic'
            assert restored['config']['vm_options']['junk_rate']==0.123
            assert restored['preset_custom'] and restored['preset_revision']==REVISION
            assert restored['preset_snapshots']==state['preset_snapshots']
            imported=resolve_config_profile(json.loads(obfuscator_gui.CONFIG_PATH.read_text(encoding='utf-8')))
            assert imported['vm_options']==restored['config']['vm_options']
        finally:
            obfuscator_gui.CONFIG_PATH=original_path
    print('user-presets-regression-ok legacy, scopes, types, budgets, independent backend and persistence')


if __name__ == '__main__':
    main()
