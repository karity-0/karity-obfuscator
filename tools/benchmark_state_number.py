"""Isolated state/number benchmark against a selected checkout.

Run revisions serially with the same interpreter. Digests cover every state
field, every generated expression and the final RNG state; timing assertions
do not belong in CI. Ordinary complete builds should be measured separately.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import random
import statistics
import sys
import time
from dataclasses import asdict


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=asdict).encode()).hexdigest()


def measure(operation, repeats):
    samples = []
    expected = None
    for _ in range(repeats):
        wall, cpu = time.perf_counter(), time.process_time()
        value = operation()
        samples.append({'wall_seconds': time.perf_counter()-wall,
                        'cpu_seconds': time.process_time()-cpu})
        signature = digest(value)
        if expected is None:
            expected = signature
        assert signature == expected
    return {'samples': samples, 'digest': expected,
            'wall_median': statistics.median(s['wall_seconds'] for s in samples),
            'cpu_median': statistics.median(s['cpu_seconds'] for s in samples)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--repeats', type=int, default=5)
    parser.add_argument('--number-reference', type=Path,
                        help='alternate number measurements with this baseline checkout')
    parser.add_argument('--numbers-only', action='store_true')
    args = parser.parse_args()
    sys.path.insert(0, str(args.checkout.resolve()))
    from lupa.lua53 import LuaRuntime
    from obfuscator import Pipeline
    from obfuscator.passes.function_obfuscation import FunctionObfuscationPass
    from obfuscator.passes.string_obfuscation import StringObfuscationPass
    from obfuscator.passes.number_expressions import NumberExpressionEngine
    from obfuscator.parser import parse_bytes
    from obfuscator.vm.semantic_ir import build_semantic_ir
    from obfuscator.vm.protection import ProtectionPlanner, protect
    from obfuscator.vm.backends import get_backend, BackendContext, karity_state
    from obfuscator.vm.backends.runtime_layout import iter_functions

    report = {'python': sys.version, 'checkout': str(args.checkout), 'repeats': args.repeats,
              'state': {}, 'number': {}}
    lua = LuaRuntime(encoding=None)
    dump = lua.eval(b'function(s)return string.dump(assert(load(s)))end')
    sources = {
        'straight': 'local a,b=1,2;' + 'a=a+b;b=b+1;'*180 + 'return a,b',
        'loop': 'local a,b=1,2;for i=1,8 do ' + 'a=a+b;b=b+1;'*40
                + 'if i%2==0 then a=a-b else b=b*2 end end;return a,b',
        'closures': 'local t={};for i=1,8 do local a,b=i,i+1;'
                    't[i]=function()a=a+b;return a,b end;if i%2==0 then b=b*2 end end;return t',
        'cff_string': 'local function f(x)local s="dependency reconstruction";'
                      'for i=1,4 do x=x+#s;if i%2==0 then x=x-1 end end;return x,s end;return f(3)',
    }
    for index, (name, source) in enumerate(sources.items() if not args.numbers_only else ()):
        random.seed(9300+index)
        if name == 'cff_string':
            source = Pipeline(show_header=False).add(StringObfuscationPass()).add(FunctionObfuscationPass()).run(source)
        ir = build_semantic_ir(parse_bytes(dump(source.encode())))
        options = {'graph_execution_rate': 0.5, 'cross_instruction_rate': 1.0,
                   'runtime_polymorphism_rate': 1.0, 'block_variant_rate': 1.0, 'vm_count': 1}
        lowered = get_backend('karity').lower(protect(ir, ProtectionPlanner(options).build(ir)), BackendContext(options))
        layout = lowered.backend_data['layout']
        functions = tuple(iter_functions(layout.functions))
        profiles = []

        def states():
            profiles.clear()
            return [karity_state._function_state(f, layout.vm_maps[f.vm_id], profiles) for f in functions]

        row = measure(states, args.repeats)
        row['profile'] = list(profiles)
        row['source_bytes'] = len(source.encode())
        report['state'][name] = row

    tokens = ('0','1','255','3.125','.25','0xAF','0X1.Ap4','2147483647','4294967295','549755813887')
    reference = None
    if args.number_reference:
        path = args.number_reference / 'obfuscator/passes/number_expressions.py'
        spec = importlib.util.spec_from_file_location('reference_number_expressions', path)
        reference = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(reference)
        report['number_reference'] = str(args.number_reference)
    for portable in (False, True):
        engine = NumberExpressionEngine()
        engine.portable = portable

        def numbers():
            random.seed(9300)
            expressions = [engine.obfuscate_token(tokens[i % len(tokens)]) for i in range(24000)]
            return expressions, random.getstate()

        name = 'portable' if portable else 'native'
        if reference is None:
            report['number'][name] = measure(numbers, args.repeats)
        else:
            current = engine
            previous = reference.NumberExpressionEngine()
            previous.portable = portable
            paired = {'before': [], 'after': []}
            # Warm both engines, then alternate order to reduce drift.
            for engine in (previous, current):
                numbers()
            for iteration in range(args.repeats):
                order = [('before', previous), ('after', current)]
                if iteration % 2:
                    order.reverse()
                for revision, engine in order:
                    paired[revision].append(measure(numbers, 1))
            signatures = {row['digest'] for rows in paired.values() for row in rows}
            assert len(signatures) == 1
            report['number'][name] = {
                revision: {'samples': [row['samples'][0] for row in rows],
                           'digest': rows[0]['digest'],
                           'wall_median': statistics.median(row['wall_median'] for row in rows),
                           'cpu_median': statistics.median(row['cpu_median'] for row in rows)}
                for revision, rows in paired.items()
            }
    args.output.write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print('state-number-benchmark-ok', args.output)


if __name__ == '__main__':
    main()
