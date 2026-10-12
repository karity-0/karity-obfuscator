"""Paired VM-only runtime measurements against a historical Karity emitter.

No source/output passes or packing. Blob bytes refer to serialized protected
IR before runtime-dependent integrity patching/encryption. Runtime execution
includes loading, decryption and initialization; subprocess launch is excluded
by an in-Lua clock. Build samples alternate order and use the same seed.
"""
from contextlib import ExitStack
from pathlib import Path
import argparse
import ast
import hashlib
import json
import random
import statistics
import subprocess
import sys
import time
import types
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

FIXTURES = {
    'hello': "print('Hello World')",
    'arithmetic': "local function f(a,b) return a+b,a-b,a*b,a/b,a%b,a^b,"
                  "-a,a//b,a&b,a|b,a~b,a<<b,a>>b,~a end;print(f(23,3));"
                  "local function g(a,b) return a+b,a-b,a*b,a/b,a%b,a^b end;print(g(19.5,2))",
    'loops': "local x=0;for i=1,80 do for j=1,4 do "
             "if i%2==0 then x=x+i*j else x=x-j end end end;"
             "local t={a=1,b=2};for k,v in pairs(t) do x=x+v end;print(x)",
    'closures': "local fs={};for i=1,4 do local n=i;fs[i]=function(...) "
                "n=n+1;return n,... end end;for i=1,4 do "
                "local a,b,c=fs[i](nil,9);print(a,b,c) end;"
                "local co=coroutine.create(function()coroutine.yield('yield',nil);return 'done' end);"
                "print(coroutine.resume(co));print(coroutine.resume(co));"
                "print(pcall(function()error('expected',0)end))",
    'metamethods': "local mt={__add=function(a,b)return a.x+b.x end,"
                   "__index=function(t,k)return 'missing:'..k end,"
                   "__len=function(t)return 17 end};local t=setmetatable({x=3},mt);"
                   "local u=setmetatable({x=8},mt);print(t+u,t.y,#t);"
                   "local function f(...)return ... end;print(f(1,nil,3,nil))",
}
SETTINGS = {
    'default': {},
    'graphs_off': {'graph_execution_rate': 0, 'runtime_polymorphism_rate': 0},
    'protected': {
        'vm_count': 2, 'graph_execution_rate': 1, 'cross_instruction_rate': 1,
        'runtime_polymorphism_rate': 1, 'block_variant_rate': 1,
        'semantic_state_threading': True, 'argument_virtualization': True,
        'upvalue_virtualization': True, 'table_virtualization': True,
        'branch_virtualization': True, 'dispatcher_target_hiding': True,
        'fake_handlers': True, 'mutate_handlers': True, 'junk_instructions': True,
        'junk_rate': .2, 'integrity_constants': True,
    },
}


def historical_graphs(ref):
    text = subprocess.run(['git', '-c', f'safe.directory={ROOT.as_posix()}', 'show',
                           f'{ref}:obfuscator/vm/backends/karity_graphs.py'],
                          cwd=ROOT, capture_output=True, check=True).stdout.decode()
    module = types.ModuleType('obfuscator.vm.backends._historical_graphs')
    exec(compile(text, '<historical Karity graphs>', 'exec'), module.__dict__)
    from obfuscator.vm.backends import karity_graphs
    module._GRAPH_ENCODING_RNG = karity_graphs._GRAPH_ENCODING_RNG
    # Restore the historical Lua 5.1 capture compactor too: its limit fix is
    # part of this change, so a baseline must not silently inherit that fix.
    from obfuscator.vm.targets import lua51
    target_source = subprocess.run(['git', '-c', f'safe.directory={ROOT.as_posix()}', 'show',
                                   f'{ref}:obfuscator/vm/targets/lua51.py'],
                                  cwd=ROOT, capture_output=True, check=True).stdout.decode()
    function = next(n for n in ast.parse(target_source).body
                    if isinstance(n, ast.FunctionDef) and n.name == '_compact_executor_captures')
    namespace = dict(lua51.__dict__)
    exec(ast.get_source_segment(target_source, function), namespace)
    module.capture_compactor = namespace['_compact_executor_captures']
    return module


def bank_sizes(source):
    import tree_sitter as ts
    from obfuscator.passes.ts_utils import parse, _LANG
    ctx = parse(source)
    assert not ctx.root.has_error
    query = ts.Query(_LANG, '(variable_declaration) @declaration')
    nodes = ts.QueryCursor(query).captures(ctx.root)['declaration']
    result = {}
    for node in nodes:
        assignment = next((n for n in node.named_children if n.type == 'assignment_statement'), None)
        if assignment is None:
            continue
        names = assignment.child_by_field_name('name')
        # Lua grammar uses lists rather than assignment name/value fields.
        names = next((n for n in assignment.named_children if n.type == 'variable_list'), names)
        values = next((n for n in assignment.named_children if n.type == 'expression_list'), None)
        if names is not None and values is not None and len(names.named_children) == 1:
            name = ctx.plain_text(names.named_children[0])
            if name in ('_AR', '_DG', '_LG', '_GV', '_CG', '_FG', '_OG'):
                result[name] = len(ctx.plain_text(values).encode())
    return result


def function_counts(source):
    import tree_sitter as ts
    from obfuscator.passes.ts_utils import parse, _LANG
    from obfuscator.vm.backends.karity_runtime_usage import _HELPERS
    ctx = parse(source)
    captures = ts.QueryCursor(ts.Query(_LANG,
        '(function_declaration) @named (function_definition) @anonymous')).captures(ctx.root)
    return {
        'total_functions': sum(len(nodes) for nodes in captures.values()),
        'audited_helpers': sum(
            ctx.plain_text(node.child_by_field_name('name')) in _HELPERS
            for node in captures.get('named', [])
            if node.children[0].type == 'local'
        ),
    }


def build(source, options, seed, legacy=None):
    from obfuscator.vm import VMPass
    from obfuscator.vm import vm_pass
    from obfuscator.vm.backends import karity_graphs, karity_runtime_usage
    from obfuscator.vm.backends.base import VMBackend
    from obfuscator.vm.targets.profile import TargetProfile
    capture = {}
    serialize = VMBackend.serialize_program
    transform = vm_pass._obfuscate_vm_output
    def observe_blob(self, lowered, context):
        blob = serialize(self, lowered, context)
        capture.update(blob_bytes=len(blob), blob_sha256=hashlib.sha256(blob).hexdigest())
        return blob
    def observe_runtime(script, passes, **kwargs):
        assert not passes
        capture['runtime'] = script
        return transform(script, passes, **kwargs)
    random.seed(seed)
    p = VMPass(vm_options={'backend': 'karity', **options},
               target=TargetProfile(options.get('lua_version', '5.3'), 'karity'))
    wrap = p._backend.target.wrap
    def observe_wrap(script, *args):
        capture['runtime'] = script
        capture['blob_literal_bytes'] = len(args[3].encode())
        return wrap(script, *args)
    with ExitStack() as stack:
        stack.enter_context(patch.object(VMBackend, 'serialize_program', observe_blob))
        stack.enter_context(patch.object(vm_pass, '_obfuscate_vm_output', observe_runtime))
        stack.enter_context(patch.object(p._backend.target, 'wrap', observe_wrap))
        if legacy is not None:
            def old_graphs(*args, **kwargs):
                kwargs.pop('stats', None)
                kwargs.pop('requirements', None)
                return legacy._apply_handler_graphs(*args, **kwargs)
            stack.enter_context(patch.object(karity_runtime_usage, 'specialize_runtime', lambda s: (s, {})))
            stack.enter_context(patch.object(karity_graphs, '_apply_handler_graphs', old_graphs))
            if p.target_profile.lua_version == '5.1':
                from obfuscator.vm.targets import lua51
                stack.enter_context(patch.object(lua51, '_compact_executor_captures', legacy.capture_compactor))
        wall, cpu = time.perf_counter(), time.process_time()
        output = p.run(source)
        capture['build_seconds'] = time.perf_counter() - wall
        capture['build_cpu_seconds'] = time.process_time() - cpu
    capture['output'] = output
    capture['output_bytes'] = len(output.encode())
    capture['runtime_bytes'] = len(capture['runtime'].replace('--[[KARITY_EXACT_BEGIN]]', '')
                                   .replace('--[[KARITY_EXACT_END]]', '').encode())
    capture['bank_bytes'] = bank_sizes(capture['runtime'])
    capture['function_counts'] = function_counts(capture['runtime'])
    capture['emission'] = p.last_lowered_ir.backend_data['runtime_emission']
    capture['plan_sha256'] = hashlib.sha256(p.last_protection_plan.dump().encode()).hexdigest()
    capture['profile'] = p.last_profile
    return capture


def execute(source, version='5.3'):
    from obfuscator.toolchain import LuaToolchain
    if version == '5.1':
        from lupa.lua51 import LuaRuntime
        lua = LuaRuntime(encoding=None)
        lua.execute(b"_lines={};print=function(...)local t={};for i=1,select('#',...)do t[i]=tostring(select(i,...))end;_lines[#_lines+1]=table.concat(t,'\t')end")
        run = lua.eval(b'function(f)local s=os.clock();f();return os.clock()-s end')
        elapsed = run(lua.eval(b'assert(loadstring(...))', source.encode()))
        return lua.eval(b"table.concat(_lines,'\\n')"), elapsed
    # Keep generated line positions unchanged for the runtime integrity probe.
    wrapped = ("local _clock=os.clock();local _bench=function() " + source
               + " end;_bench();io.stderr:write(string.format('\\nVM-BENCH:%.9f',os.clock()-_clock))")
    result = subprocess.run([LuaToolchain().lua(), '-'], input=wrapped.encode(), capture_output=True, timeout=120)
    if result.returncode:
        raise AssertionError(result.stderr.decode(errors='replace'))
    return result.stdout.replace(b'\r\n', b'\n').rstrip(b'\n'), float(result.stderr.rsplit(b'VM-BENCH:', 1)[1])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-ref', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--fixtures', nargs='+', choices=FIXTURES, default=list(FIXTURES))
    parser.add_argument('--settings', nargs='+', choices=SETTINGS, default=list(SETTINGS))
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--seed', type=int, default=9171)
    parser.add_argument('--lua-version', choices=['5.1', '5.3'], default='5.3')
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error('repeats must be positive')
    legacy = historical_graphs(args.baseline_ref)
    report = {'baseline_ref': args.baseline_ref, 'seed': args.seed, 'repeats': args.repeats,
              'python': sys.version, 'lua_version': args.lua_version, 'records': []}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    for fixture in args.fixtures:
        source = FIXTURES[fixture]
        expected, _ = execute(source, args.lua_version)
        for setting in args.settings:
            samples = {'before': [], 'after': []}
            options = {**SETTINGS[setting], 'lua_version': args.lua_version}
            for repeat in range(args.repeats):
                pair = {}
                for side in (('before', 'after') if repeat % 2 == 0 else ('after', 'before')):
                    row = build(source, options, args.seed, legacy if side == 'before' else None)
                    actual, row['execution_cpu_seconds'] = execute(row.pop('output'), args.lua_version)
                    assert actual == expected, (fixture, setting, side, actual, expected)
                    row.pop('runtime')
                    pair[side] = row
                    samples[side].append(row)
                assert pair['before']['blob_sha256'] == pair['after']['blob_sha256']
                assert pair['before']['plan_sha256'] == pair['after']['plan_sha256']
            result = {'fixture': fixture, 'setting': setting, 'options': options, 'samples': samples}
            for side in samples:
                result[side] = {metric: statistics.median(s[metric] for s in samples[side])
                                for metric in ('output_bytes', 'runtime_bytes', 'blob_bytes', 'build_seconds',
                                               'build_cpu_seconds', 'execution_cpu_seconds', 'blob_literal_bytes')}
                result[side]['bank_bytes'] = samples[side][0]['bank_bytes']
                result[side]['function_counts'] = samples[side][0]['function_counts']
                result[side]['emission'] = samples[side][0]['emission']
            report['records'].append(result)
            args.output.write_text(json.dumps(report, indent=2), encoding='utf-8')
            print(f"runtime-pair {fixture} {setting} {result['before']['output_bytes']} -> "
                  f"{result['after']['output_bytes']} build "
                  f"{result['before']['build_seconds']:.3f} -> {result['after']['build_seconds']:.3f}", flush=True)


if __name__ == '__main__':
    main()
