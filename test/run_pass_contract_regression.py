"""Native differential contracts for individual source passes and valid orders."""
from pathlib import Path
import argparse
import json
import tempfile

from pass_contracts import (ROOT, Case, Oracle, PASSES, DEDICATED, run_contracts,
                            config_for)
from verification import PASS_FEATURES, FEATURE_SUITES


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--quick', action='store_true', help='single-pass contracts only')
    parser.add_argument('--feature', action='append', default=[], choices=sorted(FEATURE_SUITES))
    parser.add_argument('--generated', type=int, default=0, help='extra seeded expression programs')
    parser.add_argument('--replay', type=Path)
    args = parser.parse_args(argv)
    if args.generated < 0:
        parser.error('--generated must be nonnegative')
    assert PASSES.keys() | DEDICATED == PASS_FEATURES.keys(), 'Source passes need declared contracts or dedicated suites'
    from obfuscator import Pipeline, build_pipeline_from_config
    from obfuscator.registry import ConfigError
    rejections = 0
    for name, spec in PASSES.items():
        for version in ('5.1', '5.3'):
            try:
                build_pipeline_from_config(config_for((name,), version), Pipeline, show_header=False)
            except ConfigError:
                assert version not in spec.versions, (name, version, 'declared support rejected')
                rejections += 1
            else:
                assert version in spec.versions, (name, version, 'supported version missing from contracts')

    with tempfile.TemporaryDirectory(prefix='karity-pass-contracts-') as folder:
        oracle = Oracle(folder)
        if args.replay:
            row = json.loads(args.replay.read_text(encoding='utf-8'))
            context, backend = row.get('context', 'source'), row.get('backend')
            if row['config'] != config_for(row['passes'], row['version'], context, backend):
                raise ValueError('Replay configuration no longer matches the declared contract')
            oracle.compare(Case(row['case'], row['source'], frozenset()), tuple(row['passes']),
                           row['version'], row['seed'], context=context, backend=backend)
            count = 1
        else:
            count = run_contracts(oracle, quick=args.quick, features=args.feature, generated=args.generated)
    print(f'pass-contracts-ok builds={count} unsupported_targets={rejections} mode={"quick" if args.quick else "combinations"}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
