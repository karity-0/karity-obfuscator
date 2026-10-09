"""Compare Lua 5.1 environment, error, and coroutine edges across backends."""
from __future__ import annotations

import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lupa.lua51 import LuaRuntime

from obfuscator.vm import VMPass
from obfuscator.vm.targets.profile import TargetProfile


CASES = {
    'pcall_xpcall': '''
        local ok,e=pcall(function() error('sentinel',0) end)
        assert(not ok and e=='sentinel')
        local x,h=xpcall(function() error('boom',0) end,
                         function(v) return 'handled:'..v end)
        assert(not x and h=='handled:boom')
    ''',
    'coroutine_yield': '''
        local co=coroutine.create(function(a)
            local x=coroutine.yield(a,false,nil)
            return x,3
        end)
        local ok,a,b,c=coroutine.resume(co,12)
        assert(ok and a==12 and b==false and c==nil)
        local ok2,v,n=coroutine.resume(co,21)
        assert(ok2 and v==21 and n==3)
    ''',
    'pcall_yield_rejection': '''
        local co=coroutine.create(function()
            local ok,e=pcall(function() coroutine.yield('x') end)
            assert(not ok and type(e)=='string')
            return 'caught'
        end)
        local ok,v=coroutine.resume(co)
        assert(ok and v=='caught')
    ''',
    'function_environment': '''
        local gf,sf=getfenv,setfenv
        local f=function() return value end
        sf(f,{value=17})
        assert(f()==17 and gf(f).value==17)
    ''',
    'thread_environment_zero': '''
        local gf,sf=getfenv,setfenv
        local old=gf(0)
        local new=setmetatable({marker=17},{__index=old})
        sf(0,new)
        assert(gf(0)==new)
        sf(0,old)
        assert(gf(0)==old)
    ''',
    'environment_level_two': '''
        local function inner() return getfenv(2),getfenv(1) end
        local function outer()
            local a,b=inner()
            return a,b
        end
        local a,b=outer()
        assert(a==_G and b==_G)
    ''',
    'set_own_environment': '''
        local sf,gf=setfenv,getfenv
        local function f()
            local env=setmetatable({value=19},{__index=_G})
            sf(1,env)
            return value,gf(1)==env
        end
        local v,ok=f()
        assert(v==19 and ok and gf(f).value==19)
    ''',
    'set_caller_environment': '''
        local sf,gf=setfenv,getfenv
        local function inner(env) sf(2,env) end
        local function outer()
            local env=setmetatable({marker=23},{__index=_G})
            inner(env)
            return gf(1)==env
        end
        assert(outer() and gf(outer).marker==23)
    ''',
    'thread_argument_rejection': '''
        local c=coroutine.create(function() end)
        local ok1,e1=pcall(getfenv,c)
        local ok2,e2=pcall(setfenv,c,{})
        assert(not ok1 and type(e1)=='string')
        assert(not ok2 and type(e2)=='string')
    ''',
}


def main() -> int:
    builds = 0
    for case_index, (name, source) in enumerate(CASES.items()):
        # Native Lua 5.1 is the oracle, including invalid thread arguments
        # and the non-yieldable pcall boundary. Each run gets a fresh thread
        # environment because setfenv(0) changes that runtime's global state.
        LuaRuntime(encoding=None).execute(source.encode())
        for backend_index, backend in enumerate(('classic', 'karity', 'mov')):
            random.seed(13600 + 100 * case_index + backend_index)
            vm = VMPass(
                target=TargetProfile('5.1', backend),
                vm_options={
                    'vm_count': 1, 'blob_form': 'string',
                    'fake_handlers': False, 'mutate_handlers': False,
                    'junk_instructions': False, 'graph_execution_rate': 0.0,
                    'cross_instruction_rate': 0.0,
                },
            )
            output = vm.run(source)
            LuaRuntime(encoding=None).execute(output.encode())
            builds += 1
            print('lua51-semantics-ok', name, backend, flush=True)
    combined = '\n'.join(CASES[name] for name in (
        'pcall_xpcall', 'coroutine_yield', 'function_environment',
        'set_caller_environment',
    ))
    LuaRuntime(encoding=None).execute(combined.encode())
    for backend_index, backend in enumerate(('classic', 'karity', 'mov')):
        # MOV has no fake/mutated-handler capability; retain its supported
        # multi-VM and integrity settings instead of silently weakening the
        # Classic/Karity protected variants.
        options = {
            'vm_count': 2, 'blob_form': 'numeric',
            'integrity_constants': True,
            'fake_handlers': backend != 'mov',
            'mutate_handlers': backend != 'mov',
            'junk_instructions': backend != 'mov',
            'junk_rate': 0.2, 'dispatcher_type': 'mixed',
            'dispatcher_target_hiding': backend != 'mov',
        }
        if backend == 'karity':
            options.update(
                graph_execution_rate=0.4,
                cross_instruction_rate=0.5,
                semantic_state_threading=True,
            )
        random.seed(15800 + backend_index)
        output = VMPass(
            target=TargetProfile('5.1', backend), vm_options=options,
            vm_output_passes=['minify'],
        ).run(combined)
        LuaRuntime(encoding=None).execute(output.encode())
        builds += 1
        print('lua51-semantics-hardened-ok', backend, flush=True)
    print(f'lua51-semantic-matrix-ok cases={len(CASES)} builds={builds}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
