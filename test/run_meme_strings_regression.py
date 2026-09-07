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


def main():
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
    for phrase in MEME_STRINGS:
        assert int(execute('print(' + full._length(phrase) + ')')) == len(phrase.encode('utf-8'))
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
