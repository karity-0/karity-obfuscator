"""Compiler-distance, numeric-origin and reconstruction composition regressions."""
from pathlib import Path
import random
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from obfuscator.pipeline import Pipeline
from obfuscator.registry import build_pipeline_from_config
from obfuscator.passes.function_obfuscation import FunctionObfuscationPass
from obfuscator.passes.number_obfuscation import NumberObfuscationPass
from obfuscator.passes.meme_strings import MemeStringsPass
from obfuscator.passes.function_costs import measure, MAX_JUMP
from obfuscator.passes.numeric_provenance import CodeText, join_code
from obfuscator.passes.ts_utils import parse
from obfuscator.vm.output_emitter import emit_vm_literals
from obfuscator.vm.vm_mutation import _new_state


SEMANTICS = '''
local function f(x)
  local function get() return x,nil,x+1,nil end
  x=x+2
  if x>3 then x=x+1 else x=x-1 end
  return get()
end
local function pack(...) return select('#',...),... end
local function worker(x)
  x=x+1; coroutine.yield(x,nil,x+1,nil)
  x=x+2; return x,nil
end
local function fail(x) x=x+1; if x>0 then error('expected',0) end; return x end
local c=coroutine.create(worker)
local n,a,b,d,e=pack(f(2))
assert(n==4 and a==5 and b==nil and d==6 and e==nil)
local n1,ok,v,z,w,t=pack(coroutine.resume(c,1))
assert(n1==5 and ok and v==2 and z==nil and w==3 and t==nil)
local n2,ok2,v2,z2=pack(coroutine.resume(c))
assert(n2==3 and ok2 and v2==4 and z2==nil)
local ok3,err=pcall(fail,1); assert(not ok3 and err=='expected')
return 'semantics-ok'
'''


def runtime(version):
    if version == '5.1':
        from lupa.lua51 import LuaRuntime
    else:
        from lupa.lua53 import LuaRuntime
    return LuaRuntime()


def apply(source, edits):
    return Pipeline(show_header=False)._apply(source, edits)


def main():
    saturated = set(range(100,10000))
    with patch('obfuscator.vm.vm_mutation.random.randint', return_value=100):
        assert _new_state(saturated) == 10000
    # More than three helpers are needed under a small, explicit jump budget.
    large = 'local function f(x)\n' + '\n'.join('x=x+1' for _ in range(180)) + '\nreturn x,nil\nend\nreturn f(2)'
    for version in ('5.1', '5.3'):
        for seed in (4601, 4602):
            random.seed(seed)
            p = FunctionObfuscationPass(boundary_mode='cff', inline=False,
                max_jump_instructions=2048)
            p.lua_version = version
            result = Pipeline(show_header=False).add(p).run(large)
            costs = measure(result, version=version)
            assert 'error' not in costs, costs
            assert max(r['max_jump'] for r in costs['functions']) < MAX_JUMP//2, costs
            assert p.last_split_helper_count > 3, p.last_profile
            assert runtime(version).execute(result) == (182, None)
            assert sum(r.get('cff_blocks', 0) for r in p.last_function_costs) >= 181
            if version == '5.3':
                expanded = Pipeline(show_header=False).add(NumberObfuscationPass()).add(MemeStringsPass()).run(result)
                expanded_costs = measure(expanded,version=version)
                assert 'error' not in expanded_costs, expanded_costs
                assert max(r['max_jump'] for r in expanded_costs['functions']) < MAX_JUMP//2
                assert runtime(version).execute(expanded) == (182, None)
            print('function-cost-large-ok', version, seed, p.last_split_helper_count, flush=True)
        for seed in (4603, 4604):
            random.seed(seed)
            p = FunctionObfuscationPass(boundary_mode='split', inline=False)
            p.lua_version = version
            result = Pipeline(show_header=False).add(p).run(SEMANTICS)
            assert runtime(version).execute(result) == 'semantics-ok'
        capture_source = '\n'.join(f'local v{i}={i}' for i in range(1,61))
        capture_source += '\nlocal function f(x) local y=x+' + '+'.join(f'v{i}' for i in range(1,61)) + ';\ny=y+1;'
        capture_source += '\nreturn y,nil end\nreturn f(2)'
        random.seed(4609)
        capture_pass = FunctionObfuscationPass(boundary_mode='split',inline=False)
        capture_pass.lua_version = version
        capture_result = Pipeline(show_header=False).add(capture_pass).run(capture_source)
        assert runtime(version).execute(capture_result) == (1833,None)
        if version == '5.1':
            assert capture_pass.last_profile[1]['avoid_helper_captures']

    # CFF-generated numbers remain marked across Unicode and ordinary edits;
    # original literals must still be processed by NumberObf.
    random.seed(4605)
    f = FunctionObfuscationPass(inline=False)
    source = '-- 한글 🍤\nlocal function f(x) local y=73; y=y+x; return y,nil end\nreturn f(4)'
    generated = Pipeline(show_header=False).add(f).run(source)
    assert isinstance(generated, CodeText) and generated.protected
    number = NumberObfuscationPass()
    edits = number.run(generated, parse(generated))
    assert edits and number.last_skipped_generated_count > 0
    assert any(generated[r.start:r.end+1] == '73' for r in edits), 'original numeric protection lost'
    protected = [generated[a:b] for a,b in generated.protected]
    numbered = apply(generated, edits)
    assert protected == [numbered[a:b] for a,b in numbered.protected]
    assert runtime('5.3').execute(numbered) == (77, None)
    emitted, _ = emit_vm_literals(generated, ['number_obf', 'meme_strings'])
    assert isinstance(emitted, CodeText) and emitted.protected
    assert runtime('5.3').execute(emitted) == (77, None)
    random.seed(4608)
    no_cff = FunctionObfuscationPass(cff=False,inline=False)
    no_cff_source = Pipeline(show_header=False).add(no_cff).run(source)
    no_cff_edits = number.run(no_cff_source,parse(no_cff_source))
    assert number.last_skipped_generated_count > 0
    assert any(no_cff_source[r.start:r.end+1] == '73' for r in no_cff_edits)
    assert join_code((CodeText('🍤1', [(1,2)]), 'x'))[1:2].protected == ((0,1),)

    # The reconstruction helpers are source functions for FunctionObf; no
    # exclusion of StringObf-generated instructions is permitted.
    random.seed(4606)
    pipeline = build_pipeline_from_config({'passes':['string_obf','function_obf','number_obf'],
        'function_obf_options': {'inline':False}}, Pipeline, show_header=False)
    result = pipeline.run('return STRING_OBF("hello world")')
    function_pass = next(p for p in pipeline._passes if isinstance(p, FunctionObfuscationPass))
    assert function_pass.last_transformed_count > 0
    assert sum(r.get('cff_blocks', 0) for r in function_pass.last_function_costs) > 10
    assert runtime('5.3').execute(result) == 'hello world'

    # Function directives override structural budgets, while the pass budget
    # stays a global setting rather than being silently ignored per function.
    random.seed(4610)
    selected = build_pipeline_from_config({'passes':['function_obf'],
        'selection_modes':{'function_obf':'marked'}}, Pipeline,show_header=False)
    result = selected.run('-- @FUNCTION_OBF(inline=false,max_jump_instructions=1024)\n'+large)
    selected_pass = next(p for p in selected._passes if isinstance(p,FunctionObfuscationPass))
    assert selected_pass.last_split_helper_count > 3
    assert runtime('5.3').execute(result) == (182,None)

    # An impossible whole-pass budget reports the bounded retry failure.
    random.seed(4607)
    try:
        Pipeline(show_header=False).add(FunctionObfuscationPass(
            max_pass_instructions=256, inline=False)).run(large)
    except RuntimeError as exc:
        assert 'pass budget exhausted after compact retry' in str(exc), str(exc)
    else:
        raise AssertionError('impossible pass budget was ignored')
    print('function-cost-regression-ok compiler distances, origins, strings, closures, coroutines, nils, diagnostics')


if __name__ == '__main__':
    main()
