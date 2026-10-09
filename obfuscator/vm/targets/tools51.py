"""Lua 5.1 compilation/dump boundaries for explicit tools and the Lupa fallback."""
from pathlib import Path
import subprocess
import tempfile
from ...toolchain import _executable


def _resolve(value, key):
    return _executable(value, key, '', (), lua_version='5.1')


def run(script, operation, toolchain=None):
    if operation not in {'compile', 'dump'}:
        raise ValueError('unsupported Lua 5.1 build operation')
    if toolchain and toolchain.lua_library:
        return toolchain.run_library(script, operation, lua_version='5.1')
    external = toolchain and (toolchain.lua_executable or (operation == 'compile' and toolchain.luac_executable))
    if not external:
        from lupa.lua51 import LuaRuntime
        runtime = LuaRuntime(encoding=None)
        expression = (b'function(s) local fn=assert(loadstring(s,"=KarityVM51"));' +
                      (b'fn=fn();' if operation == 'dump' else b'') +
                      b'return string.dump(fn) end')
        return runtime.eval(expression)(script.encode('utf-8'))
    with tempfile.TemporaryDirectory(prefix='karity-lua51-build-') as folder:
        source = Path(folder) / 'source.lua'
        output = Path(folder) / 'chunk.bin'
        source.write_text(script, encoding='utf-8')
        if operation == 'compile' and toolchain and toolchain.luac_executable:
            command = [_resolve(toolchain.luac_executable, 'luac_executable'), '-o', str(output), str(source)]
        elif toolchain and toolchain.lua_executable:
            wrapper = Path(folder) / 'build.lua'
            wrapper.write_text(
                'local input=assert(io.open(arg[1],"rb"));local source=input:read("*a");input:close();'
                'local fn=assert(loadstring(source,"=KarityVM51"));'
                + ('fn=fn();' if operation == 'dump' else '') +
                'assert(type(fn)=="function","dump wrapper did not return a function");'
                'local output=assert(io.open(arg[2],"wb"));output:write(string.dump(fn));output:close()',
                encoding='utf-8')
            command = [_resolve(toolchain.lua_executable, 'lua_executable'), str(wrapper), str(source), str(output)]
        result = subprocess.run(command, capture_output=True, timeout=120)
        if result.returncode or not output.is_file():
            raise RuntimeError(f'Lua 5.1 {operation} failed: ' + result.stderr.decode('utf-8', errors='replace'))
        data = output.read_bytes()
        if data[:6] != b'\x1bLua\x51\0':
            raise ValueError('configured tool must produce standard Lua 5.1 bytecode')
        return data
