"""Native arithmetic, guarded fallback and explicit CE allocation lifetime."""
import ctypes
import os
from pathlib import Path
import random
import sys
from dataclasses import replace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from obfuscator.vm.targets.profile import TargetProfile
from obfuscator.vm.targets.lua53 import Lua53Target
from obfuscator.vm.backends.native import CENativeBackend, NativeBackendContext, NativeInstruction, NativeOperand, encode_x64
from obfuscator.vm.backends import get_domain_backend, backend_names
from obfuscator.vm.protection import ProtectionPlanner, protect
from obfuscator.toolchain import LuaToolchain


def executable(code, params):
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.VirtualAlloc.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong)
    kernel.VirtualAlloc.restype = ctypes.c_void_p
    kernel.VirtualProtect.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong))
    kernel.VirtualFree.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong)
    kernel.FlushInstructionCache.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t)
    address = kernel.VirtualAlloc(None, len(code), 0x3000, 0x04)
    if not address:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        ctypes.memmove(address, code, len(code))
        previous = ctypes.c_ulong()
        if not kernel.VirtualProtect(address, len(code), 0x20, ctypes.byref(previous)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not kernel.FlushInstructionCache(ctypes.c_void_p(-1), address, len(code)):
            raise ctypes.WinError(ctypes.get_last_error())
    except BaseException:
        kernel.VirtualFree(address, 0, 0x8000)
        raise
    function = ctypes.WINFUNCTYPE(ctypes.c_int64, *([ctypes.c_int64] * params))(address)
    return function, lambda: kernel.VirtualFree(address, 0, 0x8000)


def main():
    adapter = Lua53Target()
    backend = CENativeBackend()
    profile = TargetProfile(environment='cheatengine', runtime_abi='windows-x64')
    assert get_domain_backend('native', 'ce_native').name == 'ce_native'
    assert get_domain_backend('vm', 'classic').domain.value == 'vm'
    assert 'ce_native' not in backend_names()
    wrap = lambda x: (x + (1 << 63)) % (1 << 64) - (1 << 63)
    cases = [
        ('return (a+b)*b-a', lambda a,b: wrap((a+b)*b-a)),
        ('return ~(a ~ b)', lambda a,b: wrap(~(a ^ b))),
        ('return (a & b) | a', lambda a,b: wrap((a & b) | a)),
        ('return -a+b+0x7fffffffffffffff', lambda a,b: wrap(-a+b+(1<<63)-1)),
    ]
    rng = random.Random(6107)
    native_available = os.name == 'nt' and ctypes.sizeof(ctypes.c_void_p) == 8
    try:
        from lupa.lua53 import LuaRuntime
    except ImportError:
        LuaRuntime = None
    for body, expected in cases:
        ir = adapter.build_ir(adapter.compile('return function(a,b) ' + body + ' end', LuaToolchain()))
        protected = protect(ir, ProtectionPlanner({}).build(ir))
        program = backend.optimize(backend.lower(protected, NativeBackendContext(profile)))
        assert len(program.functions) == 1, program.dump()
        assert backend.optimize(program) == program
        function = program.functions[0]
        dead = NativeInstruction('MOVE', 3, (NativeOperand('constant', 7),), 'dead-test')
        redundant = replace(program, functions=(replace(function, instructions=function.instructions + (dead,)),))
        assert backend.optimize(redundant) == program
        code = encode_x64(function)
        if native_available:
            native, close = executable(code, function.params)
            try:
                pairs = [(-(1<<63), -1), ((1<<63)-1, 1), (0, 0), (-1, -1)]
                pairs += [(rng.randrange(-(1<<63), 1<<63), rng.randrange(-(1<<63), 1<<63)) for _ in range(100)]
                for a,b in pairs:
                    assert native(a,b) == expected(a,b), (body,a,b)
                if LuaRuntime:
                    lua = LuaRuntime(encoding=None)
                    lua.globals()[b'executeCodeLocalEx'] = lambda address,*args: native(*args)
                    lua.globals()[b'EXPECTED'] = expected(4,2)
                    lua.execute(b'''
                        function getOperatingSystem() return 0 end
                        function cheatEngineIs64Bit() return true end
                        function getABI() return 0 end
                        allocated,freed,fallbackCalls=0,0,0
                        function autoAssemble(script,self,disable)
                            assert(self==true and script:find('db '))
                            if disable then freed=freed+1;return true end
                            allocated=allocated+1;return true,{}
                        end
                        function getAddress(name,self) assert(self);return 1234 end
                    ''')
                    lua.globals()[b'factory'] = lua.execute(backend.emit(program).encode())
                    lua.execute(b'''
                        local module=factory({['f0.0']=function(...)
                            fallbackCalls=fallbackCalls+1;return 'fallback',select('#',...)
                        end})
                        local f=module.functions['f0.0']
                        assert(f(2.5,2)=='fallback')
                        local tag,count=f(nil,2,3);assert(tag=='fallback' and count==3)
                        assert(allocated==0 and fallbackCalls==2)
                        assert(f(4,2)==EXPECTED and f(4,2)==EXPECTED)
                        assert(allocated==1)
                        module.close();module.close();assert(freed==1)
                        local ok,message=pcall(f,4,2);assert(not ok and message:find('closed'))
                    ''')
            finally:
                close()
        print('native-integer-ok', body, 'bytes=',len(code), flush=True)
    for source, arguments, expected in (
        ('return function(a,b,c,d) return c end', (1,2,-(1<<63),4), -(1<<63)),
        ('return function(a,b,c,d) return d end', (1,2,3,(1<<63)-1), (1<<63)-1),
        ('return function() return 0x8000000000000000 end', (), -(1<<63)),
    ):
        ir=adapter.build_ir(adapter.compile(source,LuaToolchain()))
        program=backend.lower(protect(ir,ProtectionPlanner({}).build(ir)),NativeBackendContext(profile))
        assert len(program.functions)==1
        if native_available:
            function,close=executable(encode_x64(program.functions[0]),len(arguments))
            try:
                assert function(*arguments)==expected
            finally:
                close()
    for body in ('if a then return b end;return 1', 'return a+0.5',
                 'return a(b)', 'return a/b', 'return a,b'):
        ir=adapter.build_ir(adapter.compile('return function(a,b) '+body+' end',LuaToolchain()))
        protected=protect(ir,ProtectionPlanner({}).build(ir))
        rejected=backend.lower(protected,NativeBackendContext(profile))
        assert not rejected.functions and len(rejected.rejected)==2,body
    for invalid in (TargetProfile(), TargetProfile(environment='cheatengine'),
                    TargetProfile(environment='cheatengine',compatibility='portable',runtime_abi='windows-x64'),
                    TargetProfile('5.1',environment='cheatengine',runtime_abi='windows-x64')):
        try:
            backend.lower(protected,NativeBackendContext(invalid))
        except ValueError:
            pass
        else:
            raise AssertionError('native target requirements bypassed')
    if not native_available:
        print('native machine execution skipped: Windows x64 host required')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
