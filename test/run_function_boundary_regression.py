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
        [lua_executable(), "-"],
        input=source.encode("utf-8"),
        capture_output=True,
        timeout=120,
    )


SOURCE = r'''
local top_value = 4
local function top_inline()
    return top_value + 1
end

local function target(x)
    local function bump()
        return x + 1
    end

    local y = bump()
    y = y * 2
    if y > 4 then
        y = y + 3
    else
        y = y - 1
    end
    return bump(), nil, y
end

local function keep_as_value(x)
    local function helper()
        return x + 10
    end
    local ref = helper
    return ref()
end

local function keep_multret()
    local function helper()
        return string.byte("AZ", 1, 2)
    end
    return helper()
end

local function capture(...)
    print(select("#", ...), ...)
end

capture(target(2))
print(top_inline())
print(keep_as_value(5), keep_multret())
'''


def main() -> int:
    random.seed(71337)
    function_pass = FunctionObfuscationPass(boundary_mode="split")
    pipeline = Pipeline(show_header=False)
    pipeline.add(function_pass)
    transformed = pipeline.run(SOURCE)

    original_run = run_lua(SOURCE)
    transformed_run = run_lua(transformed)
    if original_run.returncode != 0:
        raise AssertionError(original_run.stderr.decode("utf-8", errors="replace"))
    if transformed_run.returncode != 0:
        raise AssertionError(transformed_run.stderr.decode("utf-8", errors="replace"))
    if (
        original_run.returncode,
        original_run.stdout,
        original_run.stderr,
    ) != (
        transformed_run.returncode,
        transformed_run.stdout,
        transformed_run.stderr,
    ):
        raise AssertionError(
            "function boundary transform changed runtime output\n"
            f"original={original_run.stdout!r}/{original_run.stderr!r}\n"
            f"changed={transformed_run.stdout!r}/{transformed_run.stderr!r}"
        )

    if function_pass.last_split_helper_count < 2:
        raise AssertionError(
            "forced split mode did not emit multiple helper closures: "
            f"{function_pass.last_split_helper_count}"
        )
    if function_pass.last_inlined_function_count != 2:
        raise AssertionError(
            "the safe chunk and nested zero-arg helpers should inline: "
            f"{function_pass.last_inlined_function_count}"
        )
    if "local function bump" in transformed or "top_inline" in transformed:
        raise AssertionError("an eligible helper remained after inlining")

    print(
        "function boundary regression: OK "
        f"helpers={function_pass.last_split_helper_count} "
        f"inlined={function_pass.last_inlined_function_count}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
