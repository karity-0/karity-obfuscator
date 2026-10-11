"""Profile compiler costs at every source pass without changing pass behavior."""
from pathlib import Path
import argparse
import json
import random
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from obfuscator import Pipeline, build_pipeline_from_config
from obfuscator.profiling import Profiler
from obfuscator.registry import resolve_config_profile
from obfuscator.passes.function_costs import measure


class Capture(Pipeline):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stages = []

    def _apply(self, source, replacements):
        output = super()._apply(source, replacements)
        self.stages.append(output)
        return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('--profile', choices=('high','max'), default='high')
    parser.add_argument('--seed', type=int, default=9300)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-output', type=Path)
    parser.add_argument('--reconstruction-group-size', type=int, choices=range(1,9))
    args = parser.parse_args()
    config = resolve_config_profile(json.loads((ROOT/'config.example.json').read_text(encoding='utf-8')), args.profile)
    config['passes'] = [p for p in config['passes'] if p not in ('vm','pack')]
    if args.reconstruction_group_size is not None:
        config.setdefault('function_obf_options', {})['reconstruction_group_size'] = args.reconstruction_group_size
    random.seed(args.seed)
    profiler = Profiler()
    pipeline = build_pipeline_from_config(config, Capture, show_header=False)
    source = args.input.read_text(encoding='utf-8')
    started = time.perf_counter()
    result = pipeline.run(source, profiler=profiler)
    elapsed = time.perf_counter()-started
    records = [r for r in profiler.records if r.step == 'BASE']
    if len(records) != len(pipeline.stages):
        raise RuntimeError(f'profiling snapshots ({len(pipeline.stages)}) do not match '
                           f'source pass records ({[r.name for r in records]})')
    stages = []
    for record, text in zip(records, pipeline.stages):
        stages.append({**record.as_dict(), 'bytecode': measure(text,version=pipeline.target_profile.lua_version)})
    report = {'profile':args.profile, 'seed':args.seed, 'input_bytes':len(source.encode()),
              'source_obfuscation_seconds':elapsed, 'output_bytes':len(result.encode()),
              'all_passes':profiler.as_dict(),
              'final_bytecode':measure(result,version=pipeline.target_profile.lua_version),
              'stages':stages,
              'note':'Compiler probes run after timed obfuscation; whole VM timing uses main.py --profile-report.'}
    args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    if args.source_output is not None:
        args.source_output.write_text(result,encoding='utf-8')
    print(f'{args.profile}: {len(result.encode())} bytes, {elapsed:.3f}s; {args.output}')


if __name__ == '__main__':
    main()
