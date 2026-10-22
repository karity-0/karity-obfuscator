"""Final VM naming/stripping coverage and equivalence to sequential passes."""
from pathlib import Path
import random
import sys
from unittest.mock import patch

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
from obfuscator.passes.number_obfuscation import NumberObfuscationPass
from obfuscator.passes.packer import _loader_binding, _dump_loader_stripped, _cache_loader_meme_constants
from obfuscator.passes.minify import MinifyPass
from obfuscator.vm.targets.lua51 import Lua51Target
from obfuscator.vm.targets.lua53 import Lua53Target


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
    'local private={secret=9,[1]=8};return private.secret,private[1]',
    'local private={["secret"]=8};return private.secret',
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
    # Minify may place a delimiter directly after return. Loader extraction
    # and generic chunk wrapping must preserve lexical boundaries in either
    # form, in the same context used for native dumping and runtime loading.
    for loader in ('return(function()return 7 end)', 'return function()return 7 end',
                   'local returner=function()return 7 end;return returner',
                   'local f=function()return 7 end;return f -- trailing comment'):
        wrapped = _loader_binding(loader) + 'return _P()'
        for runtime in (Lua51, Lua53):
            assert runtime().execute(wrapped) == 7, wrapped
        assert _dump_loader_stripped(loader).startswith(b'\x1bLua')
    loader = MinifyPass().run('return function() return (#"gg"+3) end')
    cached = _cache_loader_meme_constants(loader)
    assert Lua53().execute(_loader_binding(cached) + 'return _P()') == 5
    assert _dump_loader_stripped(cached).startswith(b'\x1bLua')
    source = 'return(function(...)return function(blob,self)return 7,nil end end)'
    for target, runtime in ((Lua51Target(), Lua51), (Lua53Target(), Lua53)):
        wrapped = target.wrap(source, 'vmfn', '"blob"')
        assert runtime(unpack_returned_tuples=True).execute(wrapped) == (7, None)
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
    output, details = _obfuscate_vm_output(annotated, ['rename_obf', 'meme_strings', 'number_obf', 'strip_info'])
    assert any(d.get('reused') for d in details if d['phase'] == 'vm_output:analysis_reuse')
    final = parse(output)
    number = next(n for n in final.walk() if n.type == 'number')
    assert protected_number(output, final.cs(number), final.ce(number)+1)
    assert number_origin(output, final.cs(number), final.ce(number)+1) == 'function_constant'
    for source in CORPUS + LUA53_ONLY:
        ctx = parse(source)
        complete = resolve_bindings(ctx, sparse=False)
        captured = resolve_bindings(ctx)
        sparse = resolve_bindings(ctx, collect_literals=False)
        from obfuscator.passes.rename_ts import collect_output_nodes
        shared_nodes = collect_output_nodes(ctx)
        shared = resolve_bindings(ctx, captures=shared_nodes)
        assert signature(complete) == signature(captured), source
        assert [(n.type, n.start_byte, n.end_byte) for n in complete[2]] == [(n.type, n.start_byte, n.end_byte) for n in captured[2]], source
        assert signature(complete) == signature(sparse), source
        assert signature(complete) == signature(shared), source
        assert [(n.type, n.start_byte, n.end_byte) for n in captured[2]] == [(n.type, n.start_byte, n.end_byte) for n in shared[2]], source
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
            assert len(strips) == 1 and strips[0]['backend'] in {'shared_final_context', 'reused_source_context'}
    for passes in ([], ['rename_obf'], ['strip_info', 'minify']):
        source = 'local marker="--[[VM_DISPATCH_ENTRY]]"; --[[VM_DISPATCH_ENTRY]]\nreturn marker'
        output, _ = _obfuscate_vm_output(source, passes)
        assert Lua53().execute(output) == '--[[VM_DISPATCH_ENTRY]]'
    # A future number strategy introducing helpers/references must trigger the
    # complete final analysis, not silently leave its new bindings unrenamed.
    def with_helper(self, token):
        return '(function(generated_helper)return generated_helper+external-external end)(' + token + ')'
    with patch.object(NumberObfuscationPass, 'obfuscate_token', with_helper):
        output, details = _obfuscate_vm_output('local external=tonumber("4");return 8',
            ['rename_obf', 'number_obf', 'strip_info'])
    assert Lua53().execute(output) == 8
    assert 'generated_helper' not in output and 'external' not in output
    reuse = next(d for d in details if d['phase'] == 'vm_output:analysis_reuse')
    assert not reuse['reused'] and reuse['fallback_reason'] == 'generated_non_scalar_syntax'
    assert next(d for d in details if d['phase'] == 'vm_output:final_parse')['parse_count'] == 1
    # Compare the shared pipeline with a sequential reference using the same
    # function-scoped final naming policy. Literal PRNG use and full binding
    # coverage remain exact. Readable-name hint spelling keeps the
    # previous two assignments; alias/string generation also retains it.
    for source in CORPUS + LUA53_ONLY:
        for readable in (False, True):
            token = RENAME_OPTIONS.set({'seed': 12, 'readable': readable})
            try:
                random.seed(9300)
                initial = rename_script_ts(source)
                literals, _ = emit_vm_literals(initial, ['meme_strings', 'number_obf'])
                expected = StripInfoPass(rename_locals=False).run(rename_script_ts(literals, reuse_function_names=True))
                random.seed(9300)
                actual, details = _obfuscate_vm_output(source, ['rename_obf', 'meme_strings', 'number_obf', 'strip_info'])
                assert actual == expected, (source, readable)
                named = next(d for d in details if d['phase'] == 'vm_output:rename_obf')
                assert (named['backend'] == 'reused_source_context') == (not readable)
            finally:
                RENAME_OPTIONS.reset(token)
    print(f'vm-finalize-ok: {cases} exact-output cases, Lua 5.1/5.3, sparse coverage, late helpers, repeated passes')


if __name__ == '__main__':
    main()
