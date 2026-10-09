"""Compare Lua execution across lexical boundaries preserved by Minify."""
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from obfuscator.passes.minify import MinifyPass
from lua_runtime import lua_executable

CASES = (
    'print("=== RESULTS ===", "a + b", "a ; b", "x .. y", " - -- text")',
    'print(17 .. "x", 1. .. 2, .5 .. .25, 0x1p+1 .. "hex")',
    'local function f(...) return ... end; print(f("a", nil, "b"))',
    'print(3 - - 2, 3- -2, 3 - -- comment\n -2)',
    'print([=[line one\n  a + b -- text\n]=], "quote \\\" -- text", \'single \\\' quote\')',
    'local __KARITY_MINIFY_LITERAL_0__="original"; print(__KARITY_MINIFY_LITERAL_0__, "== preserved ==")',
    'print("--<<TARGET_51_NATIVE_TEST>>\\n== text ==")',
    '--<<TARGET_51_NATIVE_TEST>>\nprint("== native marker ==")\n--<<ENDTARGET_51_NATIVE_TEST>>\n',
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
    print(f'minify-regression-ok cases={len(CASES)} strings,numbers,varargs,comments,markers')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
