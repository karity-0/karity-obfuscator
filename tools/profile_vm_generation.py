"""VM-only paired DAG generation and shared-skeleton ablation measurements.

Historical graph emission keeps the existing dependency pruning. Source/output
passes, bytecode serialization changes and packing are not part of this test.
"""
from contextlib import ExitStack
from pathlib import Path
import argparse
import json
import statistics
import sys
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from profile_vm_runtime import build, execute, historical_graphs, FIXTURES, SETTINGS
from obfuscator.vm.backends import karity_graphs
from obfuscator.vm.backends.karity import KarityBackend


def measure(source, options, seed, mode, historical):
    graph_emitter = historical._apply_handler_graphs if mode == 'before' else karity_graphs._apply_handler_graphs
    graph_cpu = 0.0
    def emit(*args, **kwargs):
        nonlocal graph_cpu
        start = time.process_time()
        result = graph_emitter(*args, **kwargs)
        graph_cpu += time.process_time() - start
        return result
    with ExitStack() as stack:
        stack.enter_context(patch.object(karity_graphs, '_apply_handler_graphs', emit))
        if mode != 'after':
            stack.enter_context(patch.object(KarityBackend, 'shared_runtime_helpers', ()))
        row = build(source, options, seed)
    actual, row['execution_cpu_seconds'] = execute(row.pop('output'), options['lua_version'])
    row['graph_cpu_seconds'] = graph_cpu
    row.pop('runtime')
    return row, actual


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-ref', default='bd28f7b')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--seed', type=int, default=9171)
    parser.add_argument('--lua-version', choices=['5.1', '5.3'], default='5.3')
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error('repeats must be positive')
    historical = historical_graphs(args.baseline_ref)
    report = {'baseline_ref': args.baseline_ref, 'seed': args.seed, 'repeats': args.repeats,
              'python': sys.version, 'lua_version': args.lua_version, 'records': []}
    cases = [(f, 'single', {}) for f in ('hello', 'arithmetic', 'loops', 'closures')]
    cases += [(f, f'protected-{count}', {**SETTINGS['protected'], 'vm_count': count})
              for f in ('arithmetic', 'closures') for count in (2, 3)]
    cases += [('loops', 'graphs-off', SETTINGS['graphs_off'])]
    metrics = ('output_bytes', 'runtime_bytes', 'blob_bytes', 'build_seconds', 'build_cpu_seconds',
               'graph_cpu_seconds', 'execution_cpu_seconds', 'blob_literal_bytes')
    for fixture, setting, settings in cases:
        source = FIXTURES[fixture]
        if args.lua_version == '5.1' and fixture == 'arithmetic':
            # Lua 5.1 source cannot use Lua 5.3 bitwise/floor-division syntax.
            source = 'local function f(a,b)return a+b,a-b,a*b,a/b,a%b,a^b,-a end;print(f(23,3));local function g(a,b)return a+b,a-b,a*b,a/b,a%b,a^b end;print(g(19.5,2))'
        expected, _ = execute(source, args.lua_version)
        options = {**settings, 'lua_version': args.lua_version}
        samples = {side: [] for side in ('before', 'dag_only', 'after')}
        for repeat in range(args.repeats):
            order = ('before', 'dag_only', 'after') if repeat % 2 == 0 else ('after', 'dag_only', 'before')
            pair = {}
            for side in order:
                row, actual = measure(source, options, args.seed, side, historical)
                assert actual == expected, (fixture, setting, side, actual, expected)
                samples[side].append(row)
                pair[side] = row
            assert len({r['blob_sha256'] for r in pair.values()}) == 1
            assert len({r['plan_sha256'] for r in pair.values()}) == 1
            for key in ('arithmetic_dags_after', 'semantic_variants_after', 'occurrence_families'):
                assert len({r['emission'][key] for r in pair.values()}) == 1, key
        result = {'fixture': fixture, 'setting': setting, 'options': options}
        for side, rows in samples.items():
            result[side] = {m: statistics.median(r[m] for r in rows) for m in metrics}
            result[side].update({k: rows[0][k] for k in ('emission', 'bank_bytes', 'function_counts',
                                                       'effective_vm_count', 'blob_sha256', 'plan_sha256')})
            result[side]['timing_samples'] = [{m: r[m] for m in metrics if 'seconds' in m} for r in rows]
        report['records'].append(result)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2), encoding='utf-8')
        print(f"generation-pair {fixture} {setting}: {result['before']['output_bytes']} -> "
              f"{result['after']['output_bytes']}; build {result['before']['build_seconds']:.3f} -> "
              f"{result['after']['build_seconds']:.3f}; DAG CPU {result['before']['graph_cpu_seconds']:.3f} -> "
              f"{result['after']['graph_cpu_seconds']:.3f}", flush=True)


if __name__ == '__main__':
    main()
