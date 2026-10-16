"""Compare Lua execution across lexical boundaries preserved by Minify."""
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from obfuscator.passes.minify import MinifyPass
from lua_runtime import lua_executable
from lupa.lua51 import LuaRuntime as Lua51
from lupa.lua53 import LuaRuntime as Lua53

CASES = (
    'print("=== RESULTS ===", "a + b", "a ; b", "x .. y", " - -- text")',
    'print(17 .. "x", 1. .. 2, .5 .. .25, 0x1p+1 .. "hex")',
    'local function f(...) return ... end; print(f("a", nil, "b"))',
    'print(3 - - 2, 3- -2, 3 - -- comment\n -2)',
    'print([=[line one\n  a + b -- text\n]=], "quote \\\" -- text", \'single \\\' quote\')',
    'local __KARITY_MINIFY_LITERAL_0__="original"; print(__KARITY_MINIFY_LITERAL_0__, "== preserved ==")',
    'print("--<<TARGET_51_NATIVE_TEST>>\\n== text ==")',
    '--<<TARGET_51_NATIVE_TEST>>\nprint("== native marker ==")\n--<<ENDTARGET_51_NATIVE_TEST>>\n',
    'local--[[separator]]x=4;print(x)',
    'local t={["key"]=7};print(t[ [=[key]=] ])',
    'print( 1\t+\t2, 4\v-\v-2, 9\f/\f3 )',
    'print("a" --[[separator]] .. "b", 7 --[[separator]] .. "x")',
    'local _ENV=setmetatable({}, {__index=_ENV});print(3 << 2, 8 // 3, ~0, 1 & 3)',
    'local x=1;::again::x=x+1;if x<3 then goto again end;print(x)',
)


def main():
    with tempfile.TemporaryDirectory(prefix='karity-minify-') as temp:
        path = Path(temp) / 'script.lua'
        for index, source in enumerate(CASES):
            results = []
            for script in (source, MinifyPass().run(source)):
                path.write_text(script, encoding='utf-8')
                result = subprocess.run([lua_executable(), str(path)], capture_output=True, timeout=10)
                assert result.returncode == 0, (index, script, result.stderr)
                results.append(result.stdout)
            assert results[0] == results[1], (index, results)
            assert MinifyPass().run(MinifyPass().run(source)) == MinifyPass().run(source)
    # Compare returned values directly on both runtimes, with deterministic
    # whitespace/comments at every expression boundary. No timing thresholds.
    for runtime in (Lua51, Lua53):
        lua = runtime(unpack_returned_tuples=True)
        for gap in (' ', '\t', '\r\n', '\v', '\f', ' --[[gap]] ', ' -- comment\n '):
            for value in range(16):
                source = gap.join(['local', 'x', '=', str(value), ';', 'return',
                                   'x', '-', '-', '2', ',', '"a"', '..', '[=[b]=]'])
                assert lua.execute(source) == lua.execute(MinifyPass().run(source)), (gap, source)
    # Selection coordinates must follow lexical edits even in large repetitive
    # source, while exclusions retain their readable source exactly.
    from obfuscator.pipeline import Pipeline
    from obfuscator.selection_runtime import SelectionRuntime
    source = ('local total = 0\n--@VM_START\n' + 'total = total + 1 -- repeat\n' * 1024
              + '--@VM_END\n--@NO_OBF_START\nlocal keep = "  readable  " -- keep\n'
                '--@NO_OBF_END\nreturn total, keep\n')
    selection = SelectionRuntime(Pipeline(show_header=False), source)
    before = selection.plan.source
    with patch('difflib.SequenceMatcher', side_effect=AssertionError('unexpected character diff')):
        after = selection.run_post(MinifyPass(), before)
    span = next(s for s in selection.plan.spans if s.feature == 'vm')
    assert after[span.start:span.end].count('total=total+1') == 1024
    assert 'local keep = "  readable  " -- keep' in after
    lua = Lua53(unpack_returned_tuples=True)
    assert lua.execute(before) == lua.execute(after) == (1024, '  readable  ')
    print(f'minify-regression-ok cases={len(CASES)} strings,numbers,varargs,comments,markers')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
