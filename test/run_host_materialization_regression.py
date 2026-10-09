"""Exercise host constants through actual target configuration and all backends."""
import sys
from pathlib import Path
import random
import hashlib
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from run_image_resolver_regression import fixture
from obfuscator.vm.targets.image_resolver import CEBinaryResolver
from obfuscator.vm.targets.profile import TargetProfile
from obfuscator.vm.vm_pass import VMPass
from run_vm_output_emitter_regression import run_source


def main():
    versions = ['5.3']
    try:
        from lupa.lua51 import LuaRuntime
        versions.append('5.1')
    except ImportError:
        print('host backend Lua 5.1 execution skipped: Lupa unavailable')
    data, _, _ = fixture(4)
    image = CEBinaryResolver().parse(bytes(data), 'host.dll')
    setup = ("function getCheatEngineProcessID() return 7 end;"
             "function enumModules(pid) assert(pid==7);return {{Name='HOST.DLL',Address=4096,PathToFile='host.dll',Is64Bit=false}} end;"
             "function readBytesLocal(address,count,asTable) assert(address==8240 and count==8 and asTable);return {string.byte('constant',1,8)} end;"
             f"function md5file(path) return '{image.image_md5}' end;"
             f"function stringToMD5String(value) return '{hashlib.md5(b'constant').hexdigest()}' end;")
    folder = tempfile.TemporaryDirectory()
    image_path=Path(folder.name) / 'host.dll'
    image_path.write_bytes(data)
    for version, backend in ((v, b) for v in versions for b in ('classic', 'karity', 'mov')):
        random.seed(123)
        profile=TargetProfile(version, backend, environment='cheatengine',
                              compatibility='binary_specific', host_images=(str(image_path),))
        vm=VMPass(target=profile, vm_output_passes=['rename_obf', 'localize_globals', 'minify'] if version=='5.3' else [],
                  vm_options={'backend': backend, 'fake_handlers': False,
                                            'vm_count': 2, 'integrity_constants': True,
                                            'integrity_constant_rate': 1.0,
                                            'mutate_handlers': False, 'junk_instructions': False})
        output=vm.run('local function f() print("constant") end;f();print("constant")')
        plan=vm.last_lowered_ir.backend_data['materialization']
        assert len(plan.references)==2
        assert 'materialization-plan v1' in vm.last_lowered_ir.dump()
        assert b'constant' in vm.last_lowered_ir.program.constants
        assert b'constant' not in plan.functions.source.constants
        assert any(p['phase']=='resolve_host_images' for p in vm.last_profile)
        if version == '5.3':
            actual = run_source(setup + output)
        else:
            lua=LuaRuntime(encoding=None)
            values=[]
            lua.globals()[b'print']=lambda value: values.append(value)
            lua.execute((setup + output).encode())
            actual=(0,b'\n'.join(values)+b'\n',b'')
        assert actual == (0, b'constant\nconstant\n', b''), (backend, actual)
        print('host-backend-ok', version, backend, flush=True)
    folder.cleanup()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
