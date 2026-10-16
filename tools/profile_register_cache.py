"""Compare old, validating and disabled register caches in real Karity builds.

Template substitution occurs before generation and integrity binding. Nonce
entropy is frozen only in this benchmark. Broken old-cache programs are never
used as performance baselines; these workloads do not mutate captured owners.
"""
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch
import argparse
import json
import statistics
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'tools')]
from profile_opcode_synthesis import BASE, PROTECTED, build
from profile_vm_runtime import execute

MODES = ('old', 'checked_positions', 'checked', 'disabled')
FIXTURES = {
    'arithmetic': 'local a,b,s=17,29,0;for i=1,4000 do s=s+a*b+a-b end;print(s)',
    'table_reads': 'local t={3,5,7};local s=0;for i=1,2500 do s=s+t[1]+t[2]+t[3] end;print(s)',
    'repeated_operand': 'local t={};local n=0;for i=1,4000 do if t==t then n=n+1 end end;print(n)',
    'captured_reads': 'local t={1};local function read() return t end;local n=0;for i=1,2500 do if read()==read() then n=n+1 end end;print(n)',
    'cross_instruction': 'local anchor=7;local sum=0;for i=1,4000 do local a=anchor;local b=anchor;sum=sum+a+b end;print(sum)',
}


def cache_template(source, mode):
    if mode == 'checked':
        return source
    cache = '_MJ._RC' if '_MJ._RC[i]' in source else '_RC'
    start = source.index('--<<RGET>>')
    end = source.index('--<<ENDRGET>>', start)
    body = source[start:end]
    guard = f'''        local generation=_MG[1]
        local cached={cache}[i]
        -- The cached epoch-bank address is valid only in this generation.
        -- Reuse it on hits instead of computing all four bank addresses.
        if cached and cached[3]==generation and cached[2]==_RE[cached[4]] then
            return cached[1]
        end
        local p1,p2,p3,p4=_rpositions(i)
        local epoch=_RE[p3]'''
    assert body.count(guard) == 1, 'cache template changed; update benchmark substitution'
    if mode == 'checked_positions':
        replacement = f'''        local p1,p2,p3,p4=_rpositions(i)
        local epoch=_RE[p3]
        local generation=_MG[1]
        local cached={cache}[i]
        if cached and cached[2]==epoch and cached[3]==generation then
            return cached[1]
        end'''
        body = body.replace(guard, replacement).replace(',generation,p3}', ',generation}')
    else:
        replacement = f'''        local cached={cache}[i]
        if cached then return cached[1] end
''' if mode == 'old' else ''
        replacement += '''        local p1,p2,p3,p4=_rpositions(i)
        local epoch=_RE[p3]'''
        body = body.replace(guard, replacement)
        if mode == 'old':
            body = body.replace('{nil,nil,generation,p3}', '{nil}').replace('{value,epoch,generation,p3}', '{value}')
        elif mode == 'disabled':
            body = body.replace(f'{cache}[i]={{nil,nil,generation,p3}}; ', '').replace(
                f'        {cache}[i]={{value,epoch,generation,p3}}\n', '')
        else:
            raise ValueError(mode)
    return source[:start] + body + source[end:]


@contextmanager
def template_mode(mode):
    original = Path.read_text
    paths = {ROOT / 'obfuscator/vm/vm.lua', ROOT / 'obfuscator/vm/runtimes/lua51/vm.lua'}

    def read(path, *args, **kwargs):
        result = original(path, *args, **kwargs)
        return cache_template(result, mode) if path in paths else result

    with patch.object(Path, 'read_text', read):
        yield


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repeats', type=int, default=9)
    parser.add_argument('--lua', nargs='+', choices=('5.1', '5.3'), default=['5.1', '5.3'])
    parser.add_argument('--fixtures', nargs='+', choices=tuple(FIXTURES), default=list(FIXTURES))
    parser.add_argument('--resume', action='store_true')
    parser.add_argument('--output', type=Path, default=ROOT / 'local/performance/register-cache.json')
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error('repeats must be positive')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    report = {'seed': 124, 'python': sys.version, 'repeats': args.repeats,
              'scope': 'VM-only Karity; no synthesis/source/output passes; identical seed/nonce; CPU includes loading/initialization',
              'records': []}
    from obfuscator.vm.vm_pass import _DEFAULT_VM_OPTIONS
    report['options'] = {setting: {**_DEFAULT_VM_OPTIONS, **BASE, **extra, 'opcode_synthesis': False}
                         for setting, extra in (('bare', {}), ('protected', PROTECTED))}
    if args.resume:
        previous = json.loads(args.output.read_text(encoding='utf-8'))
        assert all(previous[key] == report[key] for key in ('seed', 'python', 'repeats', 'scope'))
        report = previous
        report['options'] = {setting: {**_DEFAULT_VM_OPTIONS, **BASE, **extra, 'opcode_synthesis': False}
                             for setting, extra in (('bare', {}), ('protected', PROTECTED))}
    done = {(row['lua'], row['setting'], row['fixture']) for row in report['records']}
    for version in args.lua:
        for setting, extra in (('bare', {}), ('protected', PROTECTED)):
            for fixture in args.fixtures:
                if (version, setting, fixture) in done:
                    continue
                source = FIXTURES[fixture]
                if version == '5.1':
                    source = source.replace('4000', '200').replace('2500', '150')
                expected, _ = execute(source, version)
                outputs, rows = {}, {}
                for mode in MODES:
                    with template_mode(mode):
                        output, data, _ = build(source, 'karity', version,
                            {**BASE, **extra, 'opcode_synthesis': False}, seed=124)
                    outputs[mode] = output
                    rows[mode] = {key: data[key] for key in ('output_bytes', 'build_seconds', 'blob_bytes')}
                    rows[mode]['execution_samples'] = []
                    print('cache-generated', version, setting, fixture, mode, flush=True)
                    actual, _ = execute(output, version)
                    assert actual == expected, (version, setting, fixture, mode, actual, expected)
                for repeat in range(args.repeats):
                    order = MODES[repeat % len(MODES):] + MODES[:repeat % len(MODES)]
                    for mode in order:
                        actual, elapsed = execute(outputs[mode], version)
                        assert actual == expected
                        rows[mode]['execution_samples'].append(elapsed)
                for mode, row in rows.items():
                    row['execution_cpu_seconds'] = statistics.median(row['execution_samples'])
                report['records'].append({'lua': version, 'setting': setting, 'fixture': fixture, 'source': source, 'modes': rows})
                args.output.write_text(json.dumps(report, indent=2), encoding='utf-8')
                print('cache-benchmark', version, setting, fixture,
                      {mode: round(row['execution_cpu_seconds'], 6) for mode, row in rows.items()}, flush=True)
    lines = ['# Register cache validation costs', '',
        f'Python {sys.version.split()[0]}, seed 124; {args.repeats} rotated-order executions of each generated file. '
        'VM-only Karity, synthesis disabled; graph/state/dispatch protection remains enabled in protected cases. '
        'CPU includes blob loading and runtime initialization, excluding source parsing/process startup; builder timings are single samples. '
        'Lua 5.1 uses 200 arithmetic/comparison / 150 table/closure iterations; Lua 5.3 uses 4000 / 2500. '
        'Old cache is correct on these workloads, which never overwrite captured owner slots. '
        '[Raw samples](register-cache.json).', '',
        '| Lua / options / input | Old s | Full-position guard s | Cached-address guard s | Disabled s | Change vs old |',
        '|---|---:|---:|---:|---:|---:|']
    for row in report['records']:
        times = [row['modes'][mode]['execution_cpu_seconds'] for mode in MODES]
        lines.append(f"| {row['lua']} / {row['setting']} / {row['fixture']} | " +
            ' | '.join(f'{value:.4f}' for value in times) + f' | {(times[2]/times[0]-1)*100:+.1f}% |')
    deltas = [(row['modes']['checked']['execution_cpu_seconds'] /
               row['modes']['old']['execution_cpu_seconds'] - 1) * 100 for row in report['records']]
    reuse = next((row for row in report['records'] if (row['lua'], row['setting'], row['fixture']) ==
                  ('5.1', 'bare', 'cross_instruction')), None)
    reuse_note = ''
    if reuse:
        checked, disabled = (reuse['modes'][mode]['execution_cpu_seconds'] for mode in ('checked', 'disabled'))
        reuse_note = (f'On the proven cross-instruction-reuse Lua 5.1 bare fixture, checked execution takes {checked:.3f} s '
                      f'versus {disabled:.3f} s disabled ({(checked/disabled-1)*100:+.1f}%). ')
    lines += ['', 'The validating cache stores `{value, epoch, generation, epoch_bank_address}`. '
        'Generation is checked before dereferencing the cached bank address, so remapping cannot read an old slot. '
        'Valid hits avoid recomputing all four mapped addresses and avoid representation decoding. '
        'Pending producers finish before validation. Both Lua templates and their generated getter variants use the same rule. '
        'No protection option is removed. These timings are workload dependent and include coarse native clock resolution.', '',
        f'Across this matrix the checked cache changes CPU by {min(deltas):+.1f}% to {max(deltas):+.1f}% versus the old cache. '
        'That range includes measurement noise and runtime path changes caused by integrity rebinding; it is not an isolated getter-cost estimate. '
        + reuse_note + 'Several other fixtures run faster disabled, so caching is not a universal speedup. '
        'Version checks preserve correctness without eliminating valid cross-instruction hits. '
        'The existing VM regression independently instruments real hits across instruction PCs. '
        'Representation/escape invalidation and generation rotations limit useful reuse on protected paths.', '']
    args.output.with_suffix('.md').write_text('\n'.join(lines), encoding='utf-8')


if __name__ == '__main__':
    main()
