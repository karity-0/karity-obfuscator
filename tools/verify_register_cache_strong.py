"""Regenerate a Strong protocol payload and compare CHECK/MIX/MAP with its source.

The input and generated payload stay local. This tool never modifies an existing
obfuscated file: hashes are bound by the generator to the newly emitted runtime.
"""
from pathlib import Path
import argparse
import json
import random
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    from obfuscator.registry import resolve_config_profile, build_pipeline_from_config
    from obfuscator.pipeline import Pipeline
    from obfuscator.toolchain import LuaToolchain
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--config', type=Path, default=ROOT / 'config.example.json')
    parser.add_argument('--profile', default='builtin:strong')
    parser.add_argument('--seed', type=int, default=124)
    parser.add_argument('--key', help='optional successful CHECK candidate')
    parser.add_argument('--output', type=Path, default=ROOT / 'local/register-cache/01_strong.lua')
    args = parser.parse_args()
    config = resolve_config_profile(json.loads(args.config.read_text(encoding='utf-8')), args.profile)
    pipeline = build_pipeline_from_config(config, Pipeline)
    random.seed(args.seed)
    started = time.perf_counter()
    output = pipeline.run(args.source.read_text(encoding='utf-8'))
    build_seconds = time.perf_counter() - started
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(output, encoding='utf-8')
    lua = LuaToolchain.from_config(config).lua()
    cases = {'CHECK': 'CHECK ' + (args.key or 'x' * 24) + '\nQUIT\n',
             'MIX': 'MIX abc\nQUIT\n', 'MAP': 'MAP hello\nQUIT\n',
             'combined': 'PING\nCHECK candidate\nMIX abc\nMAP hello\nMIX \nMAP \nUNKNOWN\nQUIT\n'}
    rows = []
    for name, data in cases.items():
        expected = subprocess.run([lua, str(args.source)], input=data.encode(), capture_output=True, timeout=120)
        actual = subprocess.run([lua, str(args.output)], input=data.encode(), capture_output=True, timeout=120)
        assert expected.returncode == 0, expected.stderr.decode(errors='replace')
        assert actual.returncode == 0, actual.stderr.decode(errors='replace')
        assert actual.stdout == expected.stdout, (name, actual.stdout, expected.stdout)
        rows.append({'case': name, 'stdout': actual.stdout.decode('utf-8', 'replace'), 'exit_code': 0})
        print('strong-register-cache-ok', name, flush=True)
    report = {'source': str(args.source.resolve()), 'config': str(args.config.resolve()),
              'profile': args.profile, 'seed': args.seed, 'output': str(args.output.resolve()),
              'build_seconds': build_seconds, 'output_bytes': len(output.encode()), 'cases': rows}
    args.output.with_suffix('.json').write_text(json.dumps(report, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
