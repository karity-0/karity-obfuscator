from __future__ import annotations

import os
import random
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from obfuscator.pipeline import Pipeline
from obfuscator.passes.function_obfuscation import FunctionObfuscationPass


def lua_executable() -> str:
    bundled = ROOT / "bin" / ("lua.exe" if os.name == "nt" else "lua")
    if bundled.exists():
        return str(bundled)
    return shutil.which("lua5.3") or shutil.which("lua53") or shutil.which("lua") or "lua"


def run_lua(source: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [lua_executable(), "-"], input=source.encode(), capture_output=True, timeout=120
    )


SOURCE = r'''
local function static_loops()
    local a = 0
    for i = 1, 3 do
        a = a + i
    end
    local b = 0
    for i = 5, 1, -2 do
        b = b + i
    end
    return a, b
end

local function dynamic_loop(n)
    local x = 0
    for i = 1, n do
        x = x + i
        x = x ~ 0
    end
    return x
end

local function gcd(a, b)
    if a == 0 then return b end
    return gcd(b % a, a)
end

local function phi(n)
    local count = 1
    for i = 2, n do
        if gcd(i, n) == 1 then
            count = count + 1
        end
    end
    return count
end

local function test_while_repeat()
    local x = 0
    while x < 10 do
        x = x + 1
    end
    local y = 0
    repeat
        y = y + 2
    until y >= 10
    return x, y
end

local function test_break()
    local x = 0
    for i = 1, 10 do
        if i == 4 then break end
        x = x + i
    end
    return x
end

local function test_repeat_local_scope()
    local x = 0
    repeat
        local y = x + 1
        x = y
    until y >= 3
    return x
end

local function test_capture()
    local funcs = {}
    for i = 1, 3 do
        funcs[i] = function()
            return i
        end
    end
    return funcs[1](), funcs[2](), funcs[3]()
end

local function test_generic(t)
    local sum = 0
    for _, v in pairs(t) do
        sum = sum + v
    end
    return sum
end

local function test_nested()
    local x = 0
    for i = 1, 3 do
        for j = 1, 3 do
            x = x + i * j
        end
    end
    return x
end

local function test_loop_inline()
    local function one()
        return 1
    end
    local x = 0
    for i = 1, 3 do
        x = x + one()
    end
    return x
end

print(static_loops())
print(dynamic_loop(6), phi(10))
print(test_while_repeat())
print(test_break())
print(test_repeat_local_scope())
print(test_capture())
print(test_generic({a=3,b=4,c=5}), test_nested(), test_loop_inline())
'''


def transform(seed: int) -> tuple[str, FunctionObfuscationPass]:
    random.seed(seed)
    function_pass = FunctionObfuscationPass(
        boundary_mode="split",
        loop_split=True,
        loop_unroll=True,
        loop_unroll_rate=1.0,
        loop_unroll_max_iterations=4,
        loop_max_generated_blocks=96,
        loop_max_expansion_ratio=128.0,
        loop_max_depth=3,
    )
    pipeline = Pipeline(show_header=False)
    pipeline.add(function_pass)
    return pipeline.run(SOURCE), function_pass


def main() -> int:
    transformed, function_pass = transform(31031)
    repeated, _ = transform(31031)
    if transformed != repeated:
        raise AssertionError("loop transform is not seed-reproducible")

    original = run_lua(SOURCE)
    changed = run_lua(transformed)
    if (original.returncode, original.stdout, original.stderr) != (
        changed.returncode, changed.stdout, changed.stderr
    ):
        raise AssertionError(
            "loop transform changed Lua semantics\n"
            f"original={original.returncode}/{original.stdout!r}/{original.stderr!r}\n"
            f"changed={changed.returncode}/{changed.stdout!r}/{changed.stderr!r}"
        )

    if function_pass.last_loop_unrolled_count < 2:
        raise AssertionError("small positive/negative numeric loops were not unrolled")
    if function_pass.last_loop_unrolled_iteration_count < 6:
        raise AssertionError("unrolled iteration accounting is incomplete")
    if function_pass.last_loop_split_body_count < 3:
        raise AssertionError("dynamic/generic loop bodies were not split")
    if function_pass.last_loop_lowered_count < 2:
        raise AssertionError("while/repeat were not lowered into explicit CFG states")
    if function_pass.last_loop_unsafe_skip_count < 2:
        raise AssertionError(
            "break/repeat-local unsafe loops were not conservatively skipped"
        )
    if function_pass.last_inlined_function_count < 1:
        raise AssertionError("safe helper call inside loop was not inlined")
    if len(transformed) > 1_500_000:
        raise AssertionError(f"loop transformation exploded: {len(transformed)} bytes")

    for island in (
        "for i = 2, n do\n        if gcd(i, n) == 1 then",
        "while x < 10 do\n        x = x + 1",
        "repeat\n        y = y + 2\n    until y >= 10",
    ):
        if island in transformed:
            raise AssertionError(f"compound semantic island remained: {island!r}")

    print(
        "function loop regression: OK "
        f"unrolled={function_pass.last_loop_unrolled_count}/"
        f"{function_pass.last_loop_unrolled_iteration_count} "
        f"split={function_pass.last_loop_split_body_count} "
        f"lowered={function_pass.last_loop_lowered_count} "
        f"unsafe={function_pass.last_loop_unsafe_skip_count} "
        f"budget={function_pass.last_loop_budget_fallback_count} "
        f"bytes={len(transformed)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
