"""New controls share CLI/GUI definitions and preserve saved configurations."""
from pathlib import Path
import sys
import tempfile
import subprocess
import json
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from obfuscator.registry import validate_config,config_warnings,ConfigError,resolve_config_profile
from obfuscator.presets import USER_PRESETS,REVISION
from obfuscator_gui import _vm_option_meta


def main():
    for key,value in (('ir_mba_rate',1.1),('ir_morph_max_growth',0.9),
                      ('ir_morph_max_depth',0),('ir_morph_max_new_operations',13),
                      ('physical_block_permutation_max_jumps',-1)):
        try:validate_config({'passes':['vm'],'vm_options':{key:value}})
        except ConfigError:pass
        else:raise AssertionError((key,value))
    config={'passes':['vm'],'vm_options':{'backend':'mov','physical_block_permutation_rate':1}}
    assert any('physical_block_permutation' in w for w in config_warnings(config))
    config['vm_options']['requirements']={'physical_block_permutation':'required'}
    try:validate_config(config)
    except ConfigError as error:assert 'required' in str(error)
    else:raise AssertionError('MOV silently accepted required permutation')
    assert any('Lua 5.1' in w for w in config_warnings({'passes':['vm'],'target':{'lua_version':'5.1'},'vm_options':{'ir_mba_rate':1}}))
    meta={r['name']:r for r in _vm_option_meta()}
    assert meta['ir_mba_rate']['supported_lua_versions']==['5.3']
    assert meta['ir_rematerialization_rate']['supported_lua_versions']==['5.3']
    assert any('rematerialization unavailable' in w for w in config_warnings({'passes':['vm'],'target':{'lua_version':'5.1'},'vm_options':{'ir_rematerialization_rate':1}}))
    assert set(meta['physical_block_permutation_rate']['supported_backends'])=={'karity','classic'}
    for name in USER_PRESETS:
        profile=resolve_config_profile({'vm_options':{'backend':'classic'}},name)
        assert profile['vm_options']['backend']=='classic'
        assert profile['vm_options']['physical_block_permutation_rate']>0
        assert profile['vm_options']['ir_test_set_rate']>0
    subprocess.run(['node','-e',r'''
const a=require('node:assert/strict'),m=require('./gui/web/preset_state.js');
let old={preset:'builtin:fast',preset_revision:1,preset_custom:false,config:{vm_options:{backend:'mov',ir_mba_rate:0},target:{lua_version:'5.3'}}};
let n=m.applyPreset(old,'builtin:fast',{vm_options:{ir_mba_rate:0.1}},2);
a.equal(n.config.vm_options.ir_mba_rate,0.1);a.equal(n.config.vm_options.backend,'mov');a.equal(old.config.vm_options.ir_mba_rate,0);
old.preset_custom=true;old.config.vm_options.ir_mba_rate=0.123;
n=m.applyPreset(old,'builtin:fast',{vm_options:{ir_mba_rate:0.1}},2);
a.equal(n.config.vm_options.ir_mba_rate,0.123);a.equal(n.preset_revision,1);
'''],cwd=ROOT,check=True)
    with tempfile.TemporaryDirectory() as folder:
        source=Path(folder)/'input.lua';output=Path(folder)/'output.lua';dump=Path(folder)/'morphed.ir'
        source.write_text('local x=1;for i=1,9 do x=x~i end;print(x)',encoding='utf-8')
        result=subprocess.run([sys.executable,'main.py',str(source),'-o',str(output),
            '-c','config.example.json','--profile','dev','--passes','vm','--vm-output-passes','',
            '--vm-option','ir_mba_rate=1','--dump-morphed-ir',str(dump)],cwd=ROOT,capture_output=True,text=True,timeout=120)
        assert result.returncode==0,(result.stdout,result.stderr)
        assert ':m:ir_mba_rate:' in dump.read_text(encoding='utf-8')
    print('ir-options-regression-ok validation, target/backend notices, GUI metadata, snapshots, CLI dump')


if __name__=='__main__':main()
