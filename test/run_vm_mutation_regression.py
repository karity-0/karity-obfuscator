from __future__ import annotations

import random
import subprocess
import sys
import tempfile
from pathlib import Path
from lua_runtime import lua_executable


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from obfuscator.vm.vm_mutation import mutate_handler_body



def main() -> int:
    assigned_body = """local r,n=make_values(A,B)
local entry={empty={},r=r,n=n}
local joined='x'..tostring(entry.n)
return consume(entry.r,entry.n)+#joined-2"""
    declared_body = """local r,n
r,n=make_values(A,B)
local entry={empty={},r=r,n=n}
local joined='x'..tostring(entry.n)
return consume(entry.r,entry.n)+#joined-2"""

    for seed in range(100):
        random.seed(seed)
        assigned = mutate_handler_body(assigned_body, [0])
        declared = mutate_handler_body(declared_body, [0])
        source = f"""
local A,B,Bx,C,sBx,pc,regs=3,7,0,0,0,1,{{}}
local function make_values(a,b) return {{a,b}},2 end
local function consume(values,count) return values[1]+values[2]+count end
local function rset() end
local function _source_value(value) return value end
local function run_assigned()
{assigned}
end
local function run_declared()
{declared}
end
assert(run_assigned()==12, "assigned multi-local handler mutation lost values")
assert(run_declared()==12, "declared multi-local handler mutation lost values")
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".lua", encoding="utf-8", delete=False
        ) as handle:
            handle.write(source)
            path = Path(handle.name)
        try:
            result = subprocess.run(
                [lua_executable(), str(path)],
                capture_output=True,
                text=True,
                timeout=10,
            )
        finally:
            path.unlink(missing_ok=True)
        if result.returncode != 0:
            print(f"seed {seed} failed", file=sys.stderr)
            print(result.stdout, file=sys.stderr)
            print(result.stderr, file=sys.stderr)
            return result.returncode or 1

    # The Lua 5.1 Classic executor keeps its handler mutation CFF inside a
    # target-native region. Exercise the same randomized generator directly
    # against a 5.1 parser/runtime rather than relying on the generic source
    # compatibility lowerer to repair generated Lua 5.3 bit syntax.
    from lupa.lua51 import LuaRuntime
    native_prelude = '''
local function _c_u32(v) return v%4294967296 end
local function _c_bit(a,b,mode)
  a=_c_u32(a); b=_c_u32(b); local out,p=0,1
  while a>0 or b>0 do
    local x=a%2; local y=b%2
    if (mode==0 and x~=y) or (mode==1 and x==1 and y==1) or (mode==2 and (x==1 or y==1)) then out=out+p end
    a=math.floor(a/2); b=math.floor(b/2); p=p*2
  end
  return out
end
local function _c_xor(a,b) return _c_bit(a,b,0) end
local function _c_and(a,b) return _c_bit(a,b,1) end
local function _c_or(a,b) return _c_bit(a,b,2) end
local _MJ={}
_MJ._c_u32=_c_u32;_MJ._c_xor=_c_xor;_MJ._c_and=_c_and;_MJ._c_or=_c_or
'''
    for seed in range(100):
        random.seed(seed)
        assigned = mutate_handler_body(assigned_body, [0], native_state=True)
        declared = mutate_handler_body(declared_body, [0], native_state=True)
        if any(token in assigned + declared for token in ('<<', '>>', '//', '&', '|')):
            raise AssertionError(f"native mutation emitted Lua 5.3 syntax for seed {seed}")
        native_source = native_prelude + f'''
local A,B,Bx,C,sBx,pc,regs=3,7,0,0,0,1,{{}}
local function make_values(a,b) return {{a,b}},2 end
local function consume(values,count) return values[1]+values[2]+count end
local function rset() end
local function _source_value(value) return value end
local function run_assigned()
{assigned}
end
local function run_declared()
{declared}
end
assert(run_assigned()==12, "native assigned mutation lost values")
assert(run_declared()==12, "native declared mutation lost values")
'''
        LuaRuntime(encoding=None).execute(native_source.encode())

    print("vm mutation regression passed native-lua51-seeds=100")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
