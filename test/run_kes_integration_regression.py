"""KES selection, source/output passes, presets, packing and GUI integration."""
from pathlib import Path
import random
import sys
import tempfile
import time
import zlib
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'test'))
from obfuscator import Pipeline, build_pipeline_from_config
from obfuscator.kes import KESError, lower_source
from obfuscator.registry import resolve_config_profile
from tools.explore_vm_semantics import execute, settings
from obfuscator.vm.vm_pass import VMPass
from obfuscator.vm.targets.profile import TargetProfile


def main():
    with tempfile.TemporaryDirectory(prefix='kes-integration-') as folder:
        work=Path(folder)
        def build(source,version='5.3',backend='classic',passes=None,mode='minimal',**extra):
            random.seed(124)
            config={'passes': ['vm'] if passes is None else passes,
                    'signature':{'mode':'none'},'target':{'lua_version':version},
                    'vm_options':settings(backend,mode,124),**extra}
            return build_pipeline_from_config(config,Pipeline,show_header=False).run(source)
        def run(output,version='5.3',timeout=60):
            path=work/'output.lua';path.write_text(output,encoding='utf-8')
            result=execute(path,version,timeout=timeout)
            assert result['returncode']==0,result
            return result['stdout']
        # Compare every getter with actual serialized/runtime state, not a
        # guessed numeric literal or merely a type/range check.
        getters='KARITY_GET_SCRIPT_HASH(),KARITY_GET_VM_COUNT(),KARITY_GET_VM_ID(),KARITY_GET_LAYOUT_HASH(),KARITY_GET_CODE_LENGTH()'
        contract='return {'+getters+'},function()return {'+getters+'} end'
        for version in ('5.1','5.3'):
            for backend in ('classic','karity','mov'):
                random.seed(124)
                vm=VMPass(vm_options=settings(backend,'protected',124),target=TargetProfile(lua_version=version,backend=backend))
                target=vm._backend.target
                dump=target.dump_function;bind=target.bind_lines;observed={}
                def capture_dump(*args):
                    value=dump(*args);observed['dump']=value;return value
                def capture_lines(*args):
                    value=bind(*args);observed['line']=value[1];return value
                with patch.object(target,'dump_function',capture_dump),patch.object(target,'bind_lines',capture_lines):
                    output=vm.run(contract)
                layout=vm.last_lowered_ir.backend_data['layout']
                from obfuscator.vm.backends.handler_codec import _layout_hash
                script_hash=(zlib.crc32(observed['dump'])^observed['line'])&0xffffffff
                def expected(function):return [script_hash,layout.vm_count,function.vm_id,_layout_hash(layout.instruction_layout),len(function.code)]
                root,child=expected(layout.functions),expected(layout.functions.children[0])
                harness=work/'getters-harness.lua'
                harness.write_text('local a,f=assert(loadfile(arg[1]))();local b=f();local x={'+','.join(map(str,root))+'};local y={'+','.join(map(str,child))+'};for i=1,5 do assert(a[i]==x[i],"root getter "..i);assert(b[i]==y[i],"child getter "..i) end;print("state-ok")',encoding='utf-8')
                path=work/'state.lua';path.write_text(output,encoding='utf-8')
                result=execute(path,version,harness=harness)
                assert result['returncode']==0 and result['stdout']=='state-ok\n',(version,backend,result,root,child)
                print('kes-state-contract-ok',version,backend,flush=True)
        for version in ('5.1','5.3'):
            for backend in ('classic','karity','mov'):
                source='''local outside=5
--@VM_START
local function selected(value)
  value ??= outside
  KARITY_ASSERT(value==5)
  return KARITY_GET_VM_COUNT()>=1 ? false : true
end
--@VM_END
assert(selected(nil)==false);print('selected-ok')
'''
                if version=='5.1':
                    try:build(source,version,backend,passes=[])
                    except ValueError as error:assert 'require Lua 5.3' in str(error)
                    else:raise AssertionError('unsupported Lua 5.1 selective boundary accepted')
                    source='--@VM\n'+source.replace('--@VM_START','').replace('--@VM_END','')
                assert run(build(source,version,backend,passes=[]),version)=='selected-ok\n'
                source='''local n=0
--@VM_START
n += 3
KARITY_ASSERT(n==3)
local id=KARITY_GET_VM_ID()
--@VM_END
assert(n==3 and id>=0);print('region-ok')
'''
                if version=='5.3':assert run(build(source,version,backend,selection_modes={'vm':'marked'}),version)=='region-ok\n'
                for marker in ('NO_VM','NO_OBF'):
                    source=f'--@{marker}_START\nKARITY_ABORT()\n--@{marker}_END\nprint(1)'
                    try:build(source,version,backend)
                    except (KESError,ValueError) as error:assert 'intrinsic' in str(error).lower() or 'VM' in str(error)
                    else:raise AssertionError((marker,'native intrinsic accepted'))
                print('kes-selection-ok',version,backend,flush=True)
            # Macros and generated expression helpers survive ordinary source passes.
            source='local n=NUMBER_OBF(0b1_010);local v=nil ?? false;n+=2;print(n,v,STRING_OBF("kes"))'
            passes=['remove_comment','number_obf','string_obf','function_obf','rename_obf']
            if version=='5.1':
                source='local n=0b1_010;local v=nil ?? false;n+=2;print(n,v,"kes")'
                passes=['remove_comment','function_obf','rename_obf']
            output=build(source,version,passes=passes)
            assert run(output,version)=='12\tfalse\tkes\n'
            print('kes-source-passes-ok',version,flush=True)
        source='local n=nil ?? 4;n+=2;KARITY_ASSERT(n==6);print(n,KARITY_GET_VM_COUNT()>=1)'
        from obfuscator_gui import Api, _resolved_profiles, _load_profile_root
        api=Api()
        try:
            assert api.validate_kes({'script':'local a=1\na +=','lua_version':'5.3'})['errors'][0]['line']==2
            assert api.validate_kes({'script':source})['ok']
            result=api.start_execution({'script':'local n=0b1_0;n+=3;print(nil ?? n)','config':{},'target':'source'})
            assert result['ok'],result
            deadline=time.monotonic()+15
            while time.monotonic()<deadline:
                done=api.poll_execution(result['id'])
                if done['done']:break
                time.sleep(.02)
            assert done['done'] and done['exit_code']==0,done
            assert ''.join(e['text'] for e in done['events']).strip()=='5',done
            assert not api.start_execution({'script':'KARITY_ABORT()','config':{},'target':'source'})['ok']
            root,_=_load_profile_root();profiles=_resolved_profiles(root)
            for backend in ('classic','karity','mov'):
                for preset in ('fast','balanced','strong','maximum'):
                    config=profiles['builtin:'+preset]
                    config={**config,'vm_options':{**config['vm_options'],'backend':backend},'signature':{'mode':'none'}}
                    # Fast/balanced select marked functions. Mark this whole file
                    # explicitly so an intrinsic never changes selection itself.
                    marked='--@VM_START\n'+source+'\n--@VM_END\n'
                    random.seed(124)
                    output=build_pipeline_from_config(config,Pipeline,show_header=False).run(marked)
                    assert run(output)=='6\ttrue\n',(backend,preset)
                    print('kes-preset-ok',backend,preset,flush=True)
            for backend in ('classic','karity','mov'):
                output=build(source,backend=backend,passes=['vm','pack'],mode='protected',
                             vm_output_passes=['function_obf','rename_obf','minify'],
                             packer_output_passes=['function_obf','rename_obf','minify'])
                # Explicit CFF on both the VM and the loader can spend over
                # two minutes hashing its large generated function dumps.
                assert run(output,timeout=300)=='6\ttrue\n'
                print('kes-packed-cff-ok',backend,flush=True)
            assert run(build('print(nil ?? 8)',passes=['pack']))=='8\n'
        finally:api._execution.close();api._builds.close()
    print('kes-integration-regression-ok')
    return 0


if __name__=='__main__':raise SystemExit(main())
