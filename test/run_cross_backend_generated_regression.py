"""Seeded generated Lua programs compared with each version's native oracle."""
from __future__ import annotations

from pathlib import Path
from lua_runtime import lua_executable
import random
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lupa.lua51 import LuaRuntime
from obfuscator.vm import VMPass
from obfuscator.vm.targets.profile import TargetProfile


def generated_source(seed: int) -> str:
    rng = random.Random(seed)
    initial = rng.randrange(1, 20)
    bias = rng.choice((0.25, 1.5, 2.75))
    lines = [f'local initial={initial}; local bias={bias}; local trace={{}}']
    lines.append('''
local function packet(...) return {n=select('#',...),...} end
local function counter(start)
    local value=start
    return function(delta) value=value+delta; return value end
end
local bump=counter(initial)
local function result(value) return bump(value),false,nil,'tail' end
local function tail(value) return result(value) end
local total=initial
''')
    for _ in range(10):
        operator = rng.choice(('+', '-', '*'))
        operand = rng.randrange(1, 8)
        lines.append(f'total=(total{operator}{operand})%997')
        if rng.choice((False, True)):
            lines.append(f'if total%3==0 then total=total+bump({operand}) end')
    outer, inner = rng.randrange(2, 5), rng.randrange(3, 6)
    stop = rng.randrange(2, inner + 1)
    lines.append(f'''for i=1,{outer} do for j=1,{inner} do
        if i%2==0 and j=={stop} then break end
        total=total+bump(j)
    end end''')
    lines.append('''
local proxy=setmetatable({value=bias},{
    __add=function(a,b) trace[#trace+1]='add';return a.value+b end,
    __index=function(t,k) trace[#trace+1]='get:'..k;return initial end,
    __newindex=function(t,k,v) trace[#trace+1]='set:'..k;rawset(t,k,v) end,
    __concat=function(a,b) trace[#trace+1]='concat';return 'meta:'..b end,
})
local sum=proxy+total
local missing=proxy.missing
proxy.assigned=false
local text=proxy..'suffix'
local values=packet(tail(sum))
assert(values.n==4 and values[2]==false and values[3]==nil and values[4]=='tail')
print(values[1],missing,proxy.assigned,text,table.concat(trace,','),total)
''')
    return '\n'.join(lines)


def execute(version: str, source: str) -> bytes:
    if version == '5.1':
        runtime = LuaRuntime(encoding=None)
        runtime.execute(b'''_observed={};print=function(...)
            local parts={}
            for i=1,select('#',...) do local value=select(i,...);parts[i]=tostring(value) end
            _observed[#_observed+1]=table.concat(parts,'\t')
        end''')
        runtime.execute(source.encode())
        return runtime.eval(b"table.concat(_observed,'\\n')")
    result = subprocess.run([lua_executable(), '-'], input=source.encode(),
                            capture_output=True, timeout=120)
    if result.returncode:
        raise AssertionError(result.stderr.decode('utf-8', errors='replace'))
    return result.stdout.rstrip(b'\r\n')


def main() -> int:
    seeds = (271, 811, 1543, 3301)
    builds = 0
    sources = tuple(generated_source(seed) for seed in seeds)
    assert len(set(sources)) == len(seeds)
    assert sources == tuple(generated_source(seed) for seed in seeds)
    for version in ('5.1', '5.3'):
        for source_index, (seed, source) in enumerate(zip(seeds, sources)):
            expected = execute(version, source)
            for backend_index, backend in enumerate(('classic', 'karity', 'mov')):
                random.seed(seed * 10 + backend_index)
                options = {
                    'vm_count': 2, 'blob_form': ('string', 'table', 'numeric')[source_index % 3],
                    'integrity_constants': True,
                    'fake_handlers': backend != 'mov', 'mutate_handlers': backend != 'mov',
                    'junk_instructions': backend != 'mov', 'junk_rate': 0.2,
                    'dispatcher_type': 'mixed',
                }
                if backend == 'karity':
                    options.update(
                        graph_execution_rate=0.4, cross_instruction_rate=0.6,
                        runtime_polymorphism_rate=0.5, semantic_state_threading=True,
                        argument_virtualization=True, upvalue_virtualization=True,
                        table_virtualization=True, branch_virtualization=True,
                    )
                output = VMPass(target=TargetProfile(version, backend), vm_options=options,
                                vm_output_passes=['minify']).run(source)
                actual = execute(version, output)
                assert actual == expected, (version, backend, seed, actual, expected)
                builds += 1
                print('generated-backend-ok', version, backend, seed, flush=True)
    print(f'cross-backend-generated-ok programs={len(seeds)} builds={builds}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
