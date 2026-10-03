"""Optional real Lua 5.1 executable/compiler/DLL integration tests."""
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from obfuscator.toolchain import LuaToolchain
from obfuscator.vm.targets.profile import TargetProfile
from obfuscator.vm.targets.lua51 import Lua51Target
from obfuscator.vm.vm_pass import VMPass


def main():
    folder = os.environ.get('KARITY_LUA51_TEST_TOOLS')
    if not folder:
        print('lua51-external-toolchain skipped: set KARITY_LUA51_TEST_TOOLS')
        return 0
    folder = Path(folder)
    exe, compiler, library = (folder / name for name in ('lua51.exe', 'luac51.exe', 'lua51.dll'))
    assert all(path.is_file() for path in (exe, compiler, library))
    configurations = (
        LuaToolchain(lua_executable=str(exe)),
        LuaToolchain(lua_executable=str(exe), luac_executable=str(compiler)),
        LuaToolchain(lua_library=str(library), lua_executable='missing-lua', luac_executable='missing-luac'),
    )
    source = 'local x=17;local function f(a)return x+a end;assert(f(25)==42);assert(1/(-#"")==-math.huge)'
    for index, toolchain in enumerate(configurations):
        random.seed(123)
        vm = VMPass(target=TargetProfile('5.1','classic'),toolchain=toolchain,
                    vm_options={'fake_handlers':False,'mutate_handlers':False,'junk_instructions':False})
        output=vm.run(source)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'output.lua';path.write_text(output,encoding='utf-8')
            result=subprocess.run([str(exe),str(path)],capture_output=True,timeout=120)
            assert result.returncode==0, result.stderr
        LuaToolchain(lua_library=str(library)).run_library(output,lua_version='5.1')
        try:
            from lupa.lua51 import LuaRuntime
        except ImportError:
            pass
        else:
            LuaRuntime(encoding=None).execute(output.encode())
        print('lua51-external-toolchain-ok',index,flush=True)
    try:
        Lua51Target().compile('return 1',LuaToolchain(luac_executable=str(ROOT/'bin/luac53.exe')))
    except ValueError as error:
        assert 'Lua 5.1' in str(error)
    else:
        raise AssertionError('wrong compiler version accepted')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
