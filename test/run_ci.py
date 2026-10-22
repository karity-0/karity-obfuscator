"""Select quick/related/full checks from one manifest, locally and in CI."""
import argparse
from dataclasses import replace
import json
import os
import subprocess
import sys
import time

from verification import (ROOT, make_checks, validate_manifest, changed_paths,
                          select_checks, shards, actions_matrix, FEATURE_SUITES)

REGRESSIONS = (
    'verification',
    'pass_contract',
    'typing',
    'bare_backend',
    'source_protection',
    'anti_env',
    'import',
    'blob_form',
    'serialization',
    'runtime_security',
    'block_permutation',
    'ir_facts',
    'ir_morphing',
    'ir_options',
    'opcode_synthesis',
    'opcode_synthesis_backend',
    'opcode_edges',
    'vm_lifetime',
    'kes',
    'kes_integration',
    'synthesis_dag',
    'synthesis_control',
    'selection',
    'strip_info',
    'minify',
    'semicolon',
    'string_encode',
    'meme_strings',
    'string_obf',
    'boolean_table',
    'rename',
    'backend_options',
    'number_obf',
    'packer',
    'runtime_poly',
    'runtime_trace',
    'vm_ir',
    'cross_backend_generated',
    'lua_frontend',
    'lua51_word',
    'lua51_runtime',
    'lua51_pass_matrix',
    'lua51_semantic_matrix',
    'dump51',
    'lua51_toolchain',
    'closure_gc',
    'register_cache',
    'target_capability',
    'image_resolver',
    'host_materialization',
    'native_lowering',
    'vm_backend',
    'mov_backend',
    'state_coupling',
    'vm_mutation',
    'vm_output_emitter',
    'vm_runtime_size',
    'runtime_skeleton',
    'vm_finalize',
    'vm_choke',
    'gui',
    'gui_experience',
    'signature',
    'line_state',
    'function_boundary',
    'function_loop',
    'function_nested',
    'function_lua51',
    'function_cost',
    'karity_analysis',
    'literal_mosaic',
    'toolchain',
    'user_presets',
)
CHECKS = make_checks(REGRESSIONS)
COMMANDS = [c.command for c in CHECKS]


def plan_from_args(args):
    level = args.level or ('related' if args.feature or args.changed else 'full')
    if args.github:
        event = os.environ.get('GITHUB_EVENT_NAME', '')
        full = (event in {'workflow_dispatch', 'schedule'}
                or os.environ.get('GITHUB_REF') == 'refs/heads/main'
                or os.environ.get('GITHUB_BASE_REF') == 'main')
        level = 'full' if full else 'related'
        args.changed = None if full else os.environ.get('VERIFICATION_BASE')
        if not full and not args.changed:
            level = 'full'
    paths = changed_paths(args.changed) if args.changed else None
    if args.changed and paths is None:
        return replace(select_checks(CHECKS, level='full'),
                       reasons=('full: Git comparison base is unavailable',))
    plan = select_checks(CHECKS, level=level, features=args.feature, paths=paths)
    if args.selection_env:
        try:
            data = json.loads(os.environ[args.selection_env])
            plan = select_checks(CHECKS, level=data['level'], features=data['features'],
                                 paths=() if data['level'] == 'related' else None)
            by_name = {c.name: c for c in plan.checks}
            ids = data['checks']
            if (not isinstance(ids, list) or not ids or len(set(ids)) != len(ids)
                    or not all(isinstance(n, str) and n in by_name for n in ids)):
                raise ValueError('Invalid or empty check selection')
            plan = replace(plan, checks=tuple(by_name[n] for n in ids))
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError(f'Invalid CI selection: {error}') from error
    if args.shard:
        try:
            index, total = map(int, args.shard.split('/'))
            if not 1 <= index <= total <= len(plan.checks):
                raise ValueError('out of range')
            plan = replace(plan, checks=shards(plan.checks, total)[index-1])
        except ValueError as error:
            raise ValueError('Use --shard INDEX/TOTAL within the selected check count') from error
    return plan


def execute(plan, *, keep_going=False, report=None):
    report = report or ROOT / 'local/verification' / f'report-{time.time_ns()}.json'
    report.parent.mkdir(parents=True, exist_ok=True)
    result = {'level': plan.level, 'features': sorted(plan.features),
              'selected': [c.name for c in plan.checks], 'checks': [], 'passed': False}
    failed = False
    for check in plan.checks:
        print('python ' + ' '.join(check.command), flush=True)
        started = time.perf_counter()
        completed = subprocess.run([sys.executable, *check.command], cwd=ROOT)
        failed |= completed.returncode != 0
        result['checks'].append({'name': check.name, 'command': check.command,
                                'seconds': round(time.perf_counter()-started, 3),
                                'exit_code': completed.returncode})
        report.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        if completed.returncode and not keep_going:
            break
    result['passed'] = not failed and len(result['checks']) == len(plan.checks)
    report.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    failures = [c['name'] for c in result['checks'] if c['exit_code']]
    print(f"verification: {len(result['checks'])}/{len(plan.checks)} checks; "
          f"failures={failures}; report={report.relative_to(ROOT) if report.is_relative_to(ROOT) else report}",
          flush=True)
    return int(not result['passed'])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--level', choices=('quick', 'related', 'full'))
    parser.add_argument('--feature', action='append', default=[], choices=sorted(FEATURE_SUITES))
    parser.add_argument('--changed', metavar='BASE', help='compare BASE to the current tree; missing history selects full')
    parser.add_argument('--shard', metavar='INDEX/TOTAL', help='run one deterministically balanced shard')
    parser.add_argument('--shards', type=int, default=4, help='maximum shards per Actions platform')
    parser.add_argument('--matrix', action='store_true', help='emit an Actions matrix as JSON; do not execute')
    parser.add_argument('--github', action='store_true', help='plan from GitHub event/base environment')
    parser.add_argument('--selection-env', help='read a validated matrix selection from this environment variable')
    parser.add_argument('--explain', action='store_true')
    parser.add_argument('--list', action='store_true')
    parser.add_argument('--keep-going', action='store_true', help='run remaining selected checks after a failure')
    args = parser.parse_args(argv)
    try:
        validate_manifest(REGRESSIONS, CHECKS)
        plan = plan_from_args(args)
        if args.shards < 1:
            raise ValueError('--shards must be positive')
    except ValueError as error:
        parser.error(str(error))
    if args.matrix:
        print(json.dumps(actions_matrix(plan, args.shards)))
        return 0
    if args.explain or not args.list:
        print(f'verification level={plan.level}; checks={len(plan.checks)}; '
              f'estimated Linux serial seconds={sum(c.seconds for c in plan.checks)}',
              file=sys.stderr, flush=True)
        for reason in plan.reasons:
            print(reason, file=sys.stderr, flush=True)
    if args.list:
        for check in plan.checks:
            print('python ' + ' '.join(check.command))
        return 0
    return execute(plan, keep_going=args.keep_going)


if __name__ == '__main__':
    raise SystemExit(main())
