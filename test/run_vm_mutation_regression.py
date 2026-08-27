from __future__ import annotations

import random
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from obfuscator.vm.vm_mutation import mutate_handler_body


def _lua_command() -> list[str]:
    bundled = ROOT / "bin" / "lua.exe"
    if bundled.exists():
        return [str(bundled)]
    system = shutil.which("lua")
    if system:
        return [system]
    raise RuntimeError("Lua interpreter not found")


def main() -> int:
    assigned_body = """local r,n=make_values(A,B)
return consume(r,n)"""
    declared_body = """local r,n
r,n=make_values(A,B)
return consume(r,n)"""

    for seed in range(100):
        random.seed(seed)
        assigned = mutate_handler_body(assigned_body, [0])
        declared = mutate_handler_body(declared_body, [0])
        source = f"""
local A,B,Bx,C,sBx,pc,regs=3,7,0,0,0,1,{{}}
local function make_values(a,b) return {{a,b}},2 end
local function consume(values,count) return values[1]+values[2]+count end
local function rset() end
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
                [*_lua_command(), str(path)],
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

    print("vm mutation regression passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
