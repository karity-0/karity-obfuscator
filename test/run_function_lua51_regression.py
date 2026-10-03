"""Common-syntax function protection: native 5.1/5.3 differential execution."""
from __future__ import annotations

import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lupa.lua51 import LuaRuntime as Lua51
from lupa.lua53 import LuaRuntime as Lua53
from obfuscator import Pipeline, build_pipeline_from_config
from obfuscator.passes.function_obfuscation import (
    _Affine, _int_true_forms, _int_false_forms, _zero_from, _one_from,
    _obf_int, _JUNK_SEGS, _last_zv,
)
from run_function_boundary_regression import SOURCE as BOUNDARIES
from run_function_nested_regression import SOURCE as NESTED
from run_function_loop_regression import SOURCE as LOOPS


PARAMETERS = '''
local calls = 0
local hostile = setmetatable({}, {
  __add=function() calls=calls+1; error("injected arithmetic") end,
  __mod=function() calls=calls+1; error("injected arithmetic") end
})
local function identity(value)
  local x = value
  if value == nil then x = false end
  return x, nil, false
end
for _, value in ipairs({false, 3.5, 2^60, 1/0, -1/0, hostile, "text"}) do
  local x,y,z=identity(value)
  assert(x==value and y==nil and z==false)
end
local nan=0/0
local x=identity(nan)
assert(x~=x and identity(nil)==false and calls==0)
'''


def execute(runtime, source):
    lua = runtime()
    rows = []
    lua.globals().capture = rows.append
    lua.execute('print=function(...) local t={} for i=1,select("#",...) do '
                't[i]=tostring(select(i,...)) end capture(table.concat(t,"\\t")) end')
    lua.execute(source)
    return rows


def main():
    builds = 0
    for version, runtime in (("5.1", Lua51), ("5.3", Lua53)):
        # Internal integer predicates never multiply unbounded junk values.
        lua = runtime()
        for value in (-16777216, -1, 0, 1, 100129, 16777216, 16777216*9999):
            for expr in _int_true_forms(str(value)):
                assert lua.eval(expr)
            for expr in _int_false_forms(str(value)):
                assert not lua.eval(expr)
            assert lua.eval(_zero_from(str(value))) == 0
            assert lua.eval(_one_from(str(value))) == 1
        for seed in range(12):
            random.seed(seed)
            enc = _Affine()
            for cur, nxt in ((0, 9999), (9999, 0), (42, 17), (17, 42)):
                assert lua.eval(f'{enc.enc(cur)}+{enc.delta_expr(cur,nxt)}') == enc.enc(nxt)
                assert lua.eval(enc.dec_expr(str(enc.enc(nxt)))) == nxt
            for value in (-100129, -1, 0, 1, 100129):
                assert lua.eval(_obf_int(value)) == value
            # Exercise every rich junk family independently, not just families
            # selected by a particular dispatcher seed. Each sink is integral.
            for segment in _JUNK_SEGS:
                lines = segment([0], [("state", "int")])
                sink = lua.execute('local state=42; ' + '\n'.join(lines)
                                   + '\nreturn ' + _last_zv(lines))
                assert abs(sink) < 2**53 and sink == int(sink)
        fixtures = (BOUNDARIES,
                    NESTED.replace('(lo + hi) // 2', 'math.floor((lo + hi) / 2)'),
                    LOOPS.replace('x = x ~ 0', 'x = x + 0'), PARAMETERS)
        for mode in ('cff', 'split', 'mixed'):
            for case, source in enumerate(fixtures):
                expected = execute(runtime, source)
                for seed in range(6):
                    random.seed(51000 + seed)
                    pipeline = build_pipeline_from_config({
                        'passes': ['function_obf'],
                        'target': {'lua_version': version, 'compatibility': 'portable'},
                        'function_obf_options': {
                            'boundary_mode': mode, 'loop_unroll_rate': 1.0,
                            'loop_max_generated_blocks': 96,
                        },
                    }, Pipeline, show_header=False)
                    output = pipeline.run(source)
                    protected = pipeline._passes[0]
                    assert protected.last_transformed_count > 0
                    if case == 1:
                        assert protected.last_nested_transformed_count > 0
                    if case == 2:
                        assert protected.last_loop_unrolled_count >= 2
                        assert protected.last_loop_lowered_count >= 2
                        assert protected.last_loop_split_body_count >= 3
                    if mode == 'split' and case < 3:
                        assert protected.last_split_helper_count > 0
                    assert execute(runtime, output) == expected, (version, mode, case, seed)
                    builds += 1
                print('function-native-ok', version, mode, case, flush=True)
    print(f'function-lua51-ok differential-builds={builds}')


if __name__ == '__main__':
    main()
