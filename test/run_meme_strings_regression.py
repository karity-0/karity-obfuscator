"""Check string-length replacement semantics and output-pass integration."""
import random
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

from lua_runtime import lua_executable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from obfuscator.passes.meme_strings import MemeStringsPass, STRINGS_BY_LENGTH, MEME_STRINGS
from obfuscator.passes.meme_expressions import MEME_STRING_GROUPS, MemeExpressionEngine
from obfuscator.passes.minify import MinifyPass
from obfuscator.passes.packer import _obfuscate_packer_output
from obfuscator.pipeline import Pipeline
from obfuscator.registry import PASS_REGISTRY, get_pass_contexts
from obfuscator.vm.vm_pass import _obfuscate_vm_output


def execute(source):
    result = subprocess.run(
        [lua_executable(), "-"], input=source.encode("utf-8"),
        capture_output=True, timeout=10, cwd=ROOT,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    return result.stdout


def check_group_selection():
    from lupa.lua51 import LuaRuntime as Lua51
    from lupa.lua53 import LuaRuntime as Lua53
    groups = {name: texts for name, texts in MEME_STRING_GROUPS.items() if texts}
    owners = {text: name for name, texts in groups.items() for text in texts}
    for seed in (17, 519, 811):
        random.seed(seed)
        engine = MemeExpressionEngine()
        for _ in range(10):
            cycle = [owners[engine._choose_phrase()] for _ in groups]
            assert set(cycle) == set(groups), cycle
    # Exact-length small integers must still admit every phrase, including
    # long/UTF-8 strings. Lua executes the actual residual expressions.
    for version, runtime in (('5.1', Lua51), ('5.3', Lua53)):
        lua = runtime(encoding=None)
        for value in (1, 5):
            for text in MEME_STRINGS:
                with patch.object(engine, '_choose_phrase', return_value=text):
                    expression = engine.generated_int(value, lua_version=version, depth=1)
                assert engine._length(text) in expression
                assert lua.eval(expression.encode('utf8')) == value, (version, value, text)
    # Reusing a pass after resetting the seed must not leak prior bag state.
    full = MemeStringsPass(); full.replacement_rate = 1.0
    pipeline = Pipeline(show_header=False).add(full)
    random.seed(811); before = pipeline.run('print(1,5,1,5,1,5)')
    pipeline.run('print(77,88,99)')
    random.seed(811); assert before == pipeline.run('print(1,5,1,5,1,5)')


def main():
    check_group_selection()
    source = '''-- 3 should stay in this comment
local marker = "한글 123"
local untouched = "3 bruh 4"
local values = {0, 1, 2, 3, 4, -3, 0xE, 0X04, 003, 3.0, 3e0,
    0x3p0, -0.0, 0.5, 999999, 0xffffffffffffffff, 9223372036854775807,
    3^2, -3^2, 2^-3, ~3, 8//3, 1<<3, (3) .. "x"}
for i,v in ipairs(values) do print(i, v, math.type(v)) end
local t = {[3] = "ok"}; print(t[3], marker, untouched)
for i=1,3 do print(i) end
'''
    baseline = execute(source)
    full = MemeStringsPass()
    full.replacement_rate = 1.0
    transformed = Pipeline(show_header=False).add(full).run(source)
    assert '(#"' in transformed
    assert '-- 3 should stay in this comment' in transformed
    assert '"3 bruh 4"' in transformed
    assert execute(transformed) == baseline
    assert execute(Pipeline(show_header=False).add(MinifyPass()).run(transformed)) == baseline

    # Every phrase length, decimal and hexadecimal, including unary negatives.
    all_lengths = 'print(' + ','.join(
        token for size in STRINGS_BY_LENGTH
        for token in (str(size), hex(size), '-' + str(size))
    ) + ')'
    assert execute(Pipeline(show_header=False).add(full).run(all_lengths)) == execute(all_lengths)
    # Force every number through the pass, including integer wraparound and
    # decimal overflow to float. Observe types and signed zero as well as value.
    tokens = ['0', '999999', '9223372036854775807', '9223372036854775808',
              '18446744073709551615', '0xffffffffffffffff',
              '0x8000000000000000', '0x10000000000000003',
              '0.0', '-0.0', '0.1', '3e0', '0x3p0', '1e309', '1e-320']
    for seed in range(32):
        random.seed(seed)
        for token in tokens:
            original = f'local v={token}; print(v, math.type(v), 1/v)'
            converted = Pipeline(show_header=False).add(full).run(original)
            assert converted != original and '#"' in converted
            assert execute(converted) == execute(original), (seed, token, converted)
    # The pool permits a standalone RLO. Also keep coverage for a phrase with
    # an explicit PDF terminator, independent of the current pool contents.
    for phrase in (*MEME_STRINGS, '\u202eclosed phrase\u202c'):
        assert int(execute('print(' + full._length(phrase) + ')')) == len(phrase.encode('utf-8'))
        if phrase.startswith('\u202e'):
            size = len(phrase.encode('utf-8'))
            probe = f'print({size})'
            # Force each direction-controlled phrase through actual Lua
            # parsing, minification, and the VM/packer numeric emitters.
            with patch.object(MemeExpressionEngine, '_choose_phrase', return_value=phrase), \
                    patch.object(MemeStringsPass, 'replacement_rate', 1.0):
                converted = Pipeline(show_header=False).add(full).add(MinifyPass()).run(probe)
                assert phrase in converted
                assert execute(converted) == execute(probe)
                for transform in (_obfuscate_vm_output, _obfuscate_packer_output):
                    result = transform(probe, ['meme_strings', 'number_obf', 'minify'])
                    if isinstance(result, tuple):
                        result = result[0]
                    assert phrase in result
                    assert execute(result) == execute(probe)
    # The integer-wrapping construction is intentionally unavailable on
    # binary64-only Lua 5.1: its rounded residual can change the value.
    try:
        from lupa.lua51 import LuaRuntime
    except ImportError:
        pass
    else:
        lua51 = LuaRuntime(encoding=None)
        # Force a wrapped hexadecimal residual instead of depending on the
        # phrase pool and a seed happening to produce one.
        with patch.object(full, '_choose_phrase', return_value='lol'), \
                patch('obfuscator.passes.meme_strings.random.choice', return_value='-'):
            transformed_integer = full._integer(9007199254740991, depth=1)
        assert lua51.eval(transformed_integer.encode()) != lua51.eval(b'9007199254740991')
    escaped = 'quote" slash\\ newline\n한글'
    assert int(execute('print(' + full._length(escaped) + ')')) == len(escaped.encode('utf-8'))
    assert PASS_REGISTRY['meme_strings']['cls'] is MemeStringsPass
    assert len(get_pass_contexts('meme_strings')) == 3
    outputs = set()
    for seed in range(16):
        random.seed(seed)
        output = Pipeline(show_header=False).add(MemeStringsPass()).run(source)
        outputs.add(output)
        assert execute(output) == baseline
        random.seed(seed)
        assert Pipeline(show_header=False).add(MemeStringsPass()).run(source) == output
        for transform in (_obfuscate_vm_output, _obfuscate_packer_output):
            result = transform(source, ['meme_strings', 'minify'])
            if isinstance(result, tuple):
                result = result[0]
            assert execute(result) == baseline
    assert len(outputs) > 1
    with patch.object(MemeStringsPass, 'replacement_rate', 1.0):
        result, _ = _obfuscate_vm_output(
            'print(3, "hello")', ['string_obf', 'meme_strings', 'minify'],
        )
        assert '#"' in result
        assert execute(result) == execute('print(3, "hello")')
    print('meme-strings-ok: literal semantics, seeds, minify, VM/packer output')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
