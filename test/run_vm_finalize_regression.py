"""Final VM naming/stripping coverage and equivalence to sequential passes."""
from pathlib import Path
import random
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lupa.lua51 import LuaRuntime as Lua51
from lupa.lua53 import LuaRuntime as Lua53
from obfuscator.names import RENAME_OPTIONS
from obfuscator.passes.rename_ts import resolve_bindings, rename_script_ts
from obfuscator.passes.strip_info import StripInfoPass
from obfuscator.passes.ts_utils import parse
from obfuscator.vm.backends.runtime_emitter import _finalize_output_identifiers, _obfuscate_vm_output
from obfuscator.vm.output_emitter import emit_vm_literals
from obfuscator.passes.numeric_provenance import CodeText, protected_number, number_origin


CORPUS = [
    'local secret=7; local function outer(x) local secret=x; return function(y) return secret+y end end; return outer(secret)(3)',
    'local private={secret=1};local alias=private;alias.secret=4;return private.secret',
    'local private={secret=1};local key="secret";return private[key]',
    'local private={secret=1};local alias=private;alias={secret=2};return private.secret,alias.secret',
    'local private={["sec" .. ("ret")]=9};return private[("s" .. "ecret")]',
    'local t={};function t:read(x) local y=x+1;return self,y end;local a,b=t:read(8);return a==t,b',
    'local a=3;local function f(...)local x=a;return x,... end;return f(1,nil,3,nil)',
    'local x=5;repeat local x=x-1;if x==4 then break end until x<0;return x',
    'local x=1;for x=1,3 do local function f()return x end;x=f() end;for k,v in ipairs({2,3}) do x=x+v end;return x',
    'local co=coroutine.create(function(x)coroutine.yield(x+1);return x+2,nil end);local a,b=coroutine.resume(co,8);local c,d,e=coroutine.resume(co);return a,b,c,d,e',
    'local x=4;local ok,value=pcall(function()error("한글 오류") end);return ok,value:match("한글 오류")~=nil,x',
    'local private--[[separator]]={secret=1};return private.secret -- tail',
    'local marker="--[[VM_DISPATCH_ENTRY]]";local unicode="한글🍤";return marker,unicode',
    'local function empty() end;local function f(x)return x end;return f(3)',
]
LUA53_ONLY = [
    'local _ENV=setmetatable({x=7},{__index=_ENV});local function f()return x end;return f()',
    'local n=0;::retry::n=n+1;if n<3 then goto retry end;return n',
    '::retry::local function f()local n=0;::retry::n=n+1;if n<2 then goto retry end;return n end;return f()',
]


def signature(resolution):
    return [(b.original, [(n.start_byte, n.end_byte) for n in b.nodes]) for b in resolution[0]], resolution[1]


def main():
    cases = 0
    source = 'local secret=7;return secret'
    start = source.index('7')
    annotated = CodeText(source, [(start, start+1)], origins=[(start, start+1, 'function_constant')])
    ctx = parse(annotated)
    number = next(n for n in ctx.walk() if n.type == 'number')
    assert type(ctx.plain_text(number)) is str and isinstance(ctx.text(number), CodeText)
    assert ctx.script is annotated
    output, _ = _finalize_output_identifiers(annotated, rename=True, strip=True)
    final = parse(output)
    number = next(n for n in final.walk() if n.type == 'number')
    assert protected_number(output, final.cs(number), final.ce(number)+1)
    assert number_origin(output, final.cs(number), final.ce(number)+1) == 'function_constant'
    for source in CORPUS + LUA53_ONLY:
        ctx = parse(source)
        complete = resolve_bindings(ctx, sparse=False)
        captured = resolve_bindings(ctx)
        sparse = resolve_bindings(ctx, collect_literals=False)
        assert signature(complete) == signature(captured), source
        assert [(n.type, n.start_byte, n.end_byte) for n in complete[2]] == [(n.type, n.start_byte, n.end_byte) for n in captured[2]], source
        assert signature(complete) == signature(sparse), source
        assert not sparse[2]
        for readable in (False, True):
            token = RENAME_OPTIONS.set({'seed': 12345, 'readable': readable})
            try:
                for rename, strip in ((True, True), (True, False), (False, True)):
                    reference = rename_script_ts(source) if rename else source
                    if strip:
                        reference = StripInfoPass(rename_locals=not rename).run(reference)
                    actual, details = _finalize_output_identifiers(source, rename=rename, strip=strip)
                    # Exact naming/field/comment output, not just successful
                    # execution: leaving an unrenamed binding would fail here.
                    assert actual == reference, (source, readable, rename, strip, actual, reference)
                    names = next(d for d in details if d['phase'] == 'vm_output:final_names')
                    assert names['replacements'] == sum(len(b.nodes) for b in complete[0])
                    assert sum(d.get('parse_count', 0) for d in details) == 1
                    runtimes = (Lua53,) if source in LUA53_ONLY else (Lua51, Lua53)
                    for runtime in runtimes:
                        assert runtime(unpack_returned_tuples=True).execute(actual) == runtime(unpack_returned_tuples=True).execute(source), source
                    cases += 1
            finally:
                RENAME_OPTIONS.reset(token)

    # Dense literal trees must not hide surrounding references or upvalues.
    source = 'local secret=8;local data={' + ','.join('((1+2)*3)' for _ in range(6000)) + '};local function read()return secret,data[6000] end;return read()'
    ctx = parse(source)
    assert signature(resolve_bindings(ctx, sparse=False)) == signature(resolve_bindings(ctx, collect_literals=False))
    actual, _ = _finalize_output_identifiers(source, rename=True, strip=True)
    assert 'secret' not in actual and Lua53(unpack_returned_tuples=True).execute(actual) == (8, 9)

    # Late StringObf helpers and localized aliases are still analyzed, including
    # custom pass lists and explicit repeated StripInfo layers (legacy path).
    source = 'local secret="hello";local value=7;return secret,value,true'
    for passes in [
        ['rename_obf', 'strip_info', 'meme_strings', 'number_obf'],
        ['strip_info', 'meme_strings', 'number_obf'],
        ['rename_obf', 'string_obf', 'localize_globals', 'number_obf', 'strip_info', 'minify'],
        ['rename_obf', 'strip_info', 'strip_info', 'number_obf', 'minify'],
    ]:
        random.seed(9300)
        output, details = _obfuscate_vm_output(source, passes)
        assert Lua53(unpack_returned_tuples=True).execute(output) == ('hello', 7, True), passes
        assert 'secret' not in output and 'value' not in output, output
        strips = [d for d in details if d['phase'] == 'vm_output:strip_info']
        if passes.count('strip_info') == 2:
            assert len(strips) == 2 and all(d.get('backend') != 'shared_final_context' for d in strips)
        else:
            assert len(strips) == 1 and strips[0]['backend'] == 'shared_final_context'
    for passes in ([], ['rename_obf'], ['strip_info', 'minify']):
        source = 'local marker="--[[VM_DISPATCH_ENTRY]]"; --[[VM_DISPATCH_ENTRY]]\nreturn marker'
        output, _ = _obfuscate_vm_output(source, passes)
        assert Lua53().execute(output) == '--[[VM_DISPATCH_ENTRY]]'
    # Removing the early assignment must not change ordinary names, literal
    # PRNG use or protection coverage. Readable-name hint spelling keeps the
    # previous two assignments; alias/string generation also retains it.
    for source in CORPUS + LUA53_ONLY:
        for readable in (False, True):
            token = RENAME_OPTIONS.set({'seed': 12, 'readable': readable})
            try:
                random.seed(9300)
                initial = rename_script_ts(source)
                literals, _ = emit_vm_literals(initial, ['meme_strings', 'number_obf'])
                expected = StripInfoPass(rename_locals=False).run(rename_script_ts(literals))
                random.seed(9300)
                actual, details = _obfuscate_vm_output(source, ['rename_obf', 'meme_strings', 'number_obf', 'strip_info'])
                assert actual == expected, (source, readable)
                named = next(d for d in details if d['phase'] == 'vm_output:rename_obf')
                assert (named['backend'] == 'deferred_final_context') == (not readable)
            finally:
                RENAME_OPTIONS.reset(token)
    print(f'vm-finalize-ok: {cases} exact-output cases, Lua 5.1/5.3, sparse coverage, late helpers, repeated passes')


if __name__ == '__main__':
    main()
