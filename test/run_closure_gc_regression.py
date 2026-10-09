"""VM closure registries must preserve live metadata without retaining cycles."""
from pathlib import Path
from lua_runtime import lua_executable
import random
import sys
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from obfuscator.vm.targets.profile import TargetProfile
from obfuscator.vm.vm_pass import VMPass

SOURCE = '''
gc_factory=function(value)
    local self
    self=function(n)
        if n==0 then return value end
        return self(n-1)
    end
    return self
end
'''
CHECK = '''function(factory)
    local weak=setmetatable({}, {__mode='v'})
    local live=factory(42)
    for i=1,100 do weak[i]=factory(i) end
    collectgarbage('collect');collectgarbage('collect')
    assert(next(weak)==nil, 'unreachable VM closures retained')
    -- Repeated collections must not discard the descriptor of a live closure.
    assert(live(2000)==42)
    live=nil
    collectgarbage('collect');collectgarbage('collect')
end'''


def main():
    for version in ('5.1', '5.3'):
        if version == '5.1':
            try:
                from lupa.lua51 import LuaRuntime
            except ImportError:
                print('closure-gc skipped: Lupa', version)
                continue
            runtime = LuaRuntime(encoding=None)
            check = runtime.eval(CHECK.encode())

        def execute(source):
            if version == '5.1':
                runtime.execute(source.encode())
                check(runtime.globals()[b'gc_factory'])
                return
            # The 5.3 integrity dump ABI must match its build toolchain.
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / 'output.lua'
                harness = Path(folder) / 'check.lua'
                path.write_text(source, encoding='utf-8')
                harness.write_text('assert(loadfile(arg[1]))(); (' + CHECK +
                                   ')(gc_factory)', encoding='utf-8')
                result = subprocess.run([lua_executable(), str(harness), str(path)],
                                        capture_output=True, timeout=120)
                assert result.returncode == 0, result.stderr

        execute(SOURCE)
        for backend in ('classic', 'karity', 'mov'):
            random.seed(124)
            vm = VMPass(target=TargetProfile(version, backend), vm_options={
                'fake_handlers': False, 'mutate_handlers': False,
                'junk_instructions': False})
            output = vm.run(SOURCE)
            execute(output)
            print('closure-gc-ok', version, backend, flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
