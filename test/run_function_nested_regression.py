from __future__ import annotations

import os
import random
import re
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from obfuscator.pipeline import Pipeline
from obfuscator.passes.function_obfuscation import FunctionObfuscationPass
from obfuscator.passes.ts_utils import parse


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
local function simple_nested(x)
    local function add_one(y)
        return y + 1
    end
    return add_one(x)
end

local function anonymous_nested(x)
    local twice = function(y)
        return y * 2
    end
    return twice(x)
end

local function recursive_nested(n)
    local function fact(x)
        if x <= 1 then
            return 1
        end
        return x * fact(x - 1)
    end
    return fact(n)
end

local function closure_nested(x)
    local k = 10
    local function add_k(y)
        return y + k
    end
    return add_k(x)
end

local function deep_nested(x)
    local function middle(y)
        local function inner(z)
            local q = z + 1
            return q
        end
        return inner(y)
    end
    return middle(x)
end

local function mutual_nested(n)
    local even, odd
    even = function(x)
        if x == 0 then return true end
        return odd(x - 1)
    end
    odd = function(x)
        if x == 0 then return false end
        return even(x - 1)
    end
    return even(n), odd(n)
end

local function escaped_nested(x)
    local function value()
        local y = x + 3
        return y
    end
    return value
end

local function return_semantics(x)
    local function relay(...)
        return ...
    end
    local function multi(y)
        return y, nil, y + 1
    end
    return relay(multi(x))
end

local function merge_sort(values)
    local function less(a, b)
        return a < b
    end

    local function merge(lo, mid, hi)
        local tmp = {}
        local i, j = lo, mid + 1
        while i <= mid and j <= hi do
            if less(values[i], values[j]) then
                tmp[#tmp + 1] = values[i]
                i = i + 1
            else
                tmp[#tmp + 1] = values[j]
                j = j + 1
            end
        end
        while i <= mid do
            tmp[#tmp + 1] = values[i]
            i = i + 1
        end
        while j <= hi do
            tmp[#tmp + 1] = values[j]
            j = j + 1
        end
        for k = 1, #tmp do
            values[lo + k - 1] = tmp[k]
        end
    end

    local function sort(lo, hi)
        if lo >= hi then return end
        local mid = (lo + hi) // 2
        sort(lo, mid)
        sort(mid + 1, hi)
        merge(lo, mid, hi)
    end

    sort(1, #values)
    return table.concat(values, ",")
end

print(simple_nested(4), anonymous_nested(5))
print(recursive_nested(6), closure_nested(7), deep_nested(8))
print(mutual_nested(8))
print(escaped_nested(9)())
local a, b, c = return_semantics(20)
print(a, b == nil, c)
print(merge_sort({9, 3, 7, 1, 8, 2, 6, 5, 4}))
'''

DEPTH_LIMIT_SOURCE = r'''
local function level0(x)
    local function level1(y)
        local function level2(z)
            return z + 1
        end
        return level2(y)
    end
    return level1(x)
end
print(level0(10))
'''


def transform(seed: int) -> tuple[str, FunctionObfuscationPass]:
    random.seed(seed)
    function_pass = FunctionObfuscationPass(
        boundary_mode="split",
        nested=True,
        nested_max_depth=4,
    )
    pipeline = Pipeline(show_header=False)
    pipeline.add(function_pass)
    return pipeline.run(SOURCE), function_pass


def main() -> int:
    source_function_count = sum(
        1 for node in parse(SOURCE).walk()
        if node.type in ("function_declaration", "function_definition")
    )

    transformed, function_pass = transform(92017)
    repeated, repeated_pass = transform(92017)
    if transformed != repeated:
        raise AssertionError("same seed did not reproduce nested function output")

    original_run = run_lua(SOURCE)
    transformed_run = run_lua(transformed)
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
            "nested function transform changed Lua semantics\n"
            f"original={original_run.returncode}/{original_run.stdout!r}/{original_run.stderr!r}\n"
            f"changed={transformed_run.returncode}/{transformed_run.stdout!r}/{transformed_run.stderr!r}"
        )

    if function_pass.last_processed_source_count != source_function_count:
        raise AssertionError(
            "initial SOURCE provenance was not processed exactly once: "
            f"processed={function_pass.last_processed_source_count} "
            f"source={source_function_count}"
        )
    if function_pass.last_nested_transformed_count < 10:
        raise AssertionError(
            "too few nested semantic functions were transformed: "
            f"{function_pass.last_nested_transformed_count}"
        )
    if function_pass.last_depth_limited_count != 0:
        raise AssertionError("depth-2 fixture unexpectedly hit the nesting limit")
    if function_pass.last_split_helper_count < 4:
        raise AssertionError("nested CFF did not produce split helper closures")

    # Generated helper/junk functions may be numerous in output, but recursive input
    # accounting must remain exactly the initial AST SOURCE set. A second same-seed
    # build must consume the same count and produce byte-identical text.
    if repeated_pass.last_processed_source_count != source_function_count:
        raise AssertionError("generated functions leaked into recursive provenance")
    if len(transformed) > 2_500_000:
        raise AssertionError(
            f"nested transform output exploded unexpectedly: {len(transformed)} bytes"
        )

    random.seed(92018)
    limited_pass = FunctionObfuscationPass(
        boundary_mode="split",
        nested=True,
        nested_max_depth=1,
    )
    limited_pipeline = Pipeline(show_header=False)
    limited_pipeline.add(limited_pass)
    limited_output = limited_pipeline.run(DEPTH_LIMIT_SOURCE)
    if run_lua(DEPTH_LIMIT_SOURCE).stdout != run_lua(limited_output).stdout:
        raise AssertionError("nested depth limit changed runtime semantics")
    if limited_pass.last_processed_source_count != 2:
        raise AssertionError(
            "nested_max_depth=1 did not stop before depth 2: "
            f"{limited_pass.last_processed_source_count}"
        )
    if limited_pass.last_depth_limited_count < 1:
        raise AssertionError("depth-limited SOURCE function was not reported")

    # Original semantic helper names and full recursive body must not survive as a
    # directly extractable island after lexical rewrite + independent nested CFF.
    for leaked in (
        r"\blocal\s+function\s+merge\s*\(",
        r"\blocal\s+function\s+sort\s*\(",
        r"\bx\s*\*\s*fact\s*\(\s*x\s*-\s*1\s*\)",
    ):
        if re.search(leaked, transformed):
            raise AssertionError(f"plain nested semantic island remained: {leaked!r}")

    print(
        "function nested regression: OK "
        f"source={source_function_count} "
        f"processed={function_pass.last_processed_source_count} "
        f"nested={function_pass.last_nested_transformed_count} "
        f"helpers={function_pass.last_split_helper_count} "
        f"bytes={len(transformed)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
