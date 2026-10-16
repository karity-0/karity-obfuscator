"""Bounded native/VM differential exploration with reproducible local artifacts.

Includes hand-selected lifetime/effect boundaries and seeded generated programs.
Every target runs in a fresh process with a timeout, including native Lua 5.1.
"""
from pathlib import Path
import argparse
import json
import random
import subprocess
import sys
import time
from itertools import zip_longest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'test')]


def expression_source(seed):
    """Typed expression grammar with observable read/write and metamethod order."""
    rng = random.Random(seed)
    def number(depth):
        if depth == 0:
            return rng.choice(('read()', f'tap({rng.randrange(-9, 10)})',
                               f'proxy.k{rng.randrange(4)}', str(rng.randrange(-12, 13))))
        left, right = number(depth-1), number(depth-1)
        choice = rng.randrange(5)
        if choice < 3:
            return f'((({left}){("+", "-", "*")[choice]}({right}))%997)'
        if choice == 3:
            return f'(choose({left}) and {right} or read())'
        return f'select(2,nil,{left},{right},nil)'
    expressions = [number(3) for _ in range(8)]
    return '''local state=7; local trace={}
local function read() trace[#trace+1]='r'; return state end
local function tap(n) state=(state+n)%101;trace[#trace+1]='t'..n;return state end
local function choose(n) trace[#trace+1]='c';return n%3==0 end
local proxy=setmetatable({}, {__index=function(_,k)
    trace[#trace+1]=k; state=(state+tonumber(k:sub(2))+1)%101;return state
end})
local sum=0
''' + '\n'.join(f'sum=(sum+({expr}))%997' for expr in expressions) + '''
local closures={}
for i=1,5 do local value=(sum+i)%97
    closures[i]=function(delta) value=value+delta;return value,nil,false end
end
for i=5,1,-1 do local a,b,c=closures[i](i);assert(b==nil and c==false);sum=sum+a end
print(sum,state,table.concat(trace,','))
'''


def execute(source, version, timeout=60, harness=None):
    from lua_runtime import lua_executable
    if version=='5.1':
        command=[sys.executable,__file__,'--lua51-worker',str(source)]
        if harness: command += ['--harness',str(harness)]
    else:
        command=[lua_executable(version)] + ([str(harness)] if harness else []) + [str(source)]
    started = time.perf_counter()
    try:
        result = subprocess.run(command, capture_output=True, timeout=timeout)
        return {'returncode': result.returncode,
                'stdout': result.stdout.decode('utf-8', errors='replace').replace('\r\n', '\n'),
                'stderr': result.stderr.decode('utf-8', errors='replace'),
                'seconds': time.perf_counter() - started}
    except subprocess.TimeoutExpired:
        return {'returncode': 'timeout', 'stdout': '', 'stderr': '',
                'seconds': time.perf_counter() - started}


def settings(backend, mode, seed):
    from run_vm_backend_regression import options
    result = options(backend)
    if mode == 'protected':
        result.update(vm_count=2, integrity_constants=True,
                      integrity_constant_rate=0.5, dispatcher_type='mixed',
                      helper_variant_count=3, helper_diversity_rate=1.0,
                      semantic_diversity_rate=0.5, block_variant_rate=0.3,
                      graph_execution_rate=0.5, cross_instruction_rate=0.5,
                      runtime_polymorphism_rate=0.5, semantic_state_threading=True,
                      argument_virtualization=True, upvalue_virtualization=True,
                      table_virtualization=True, branch_virtualization=True)
        result['blob_form'] = ('string', 'table', 'numeric')[seed % 3]
    return result


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, default=ROOT/'local/vm-audit/2026-10-16')
    p.add_argument('--seeds', type=int, nargs='+', default=[124, 7719, 20261016])
    p.add_argument('--versions', nargs='+', default=['5.1', '5.3'])
    p.add_argument('--backends', nargs='+', default=['classic', 'karity', 'mov'])
    p.add_argument('--modes', nargs='+', default=['minimal', 'protected'])
    p.add_argument('--generated', type=int, default=8)
    p.add_argument('--generated-only', action='store_true')
    p.add_argument('--inputs', type=Path, nargs='+', default=[],
                   help='use these Lua inputs instead of the built-in boundary fixture')
    p.add_argument('--harness', type=Path, help='Lua observer that receives the input filename in arg[1]')
    p.add_argument('--pack', action='store_true', help='also exercise the Lua 5.3 packer')
    p.add_argument('--vm-output-passes', nargs='+', default=[])
    p.add_argument('--lua51-worker', type=Path)
    args = p.parse_args(argv)
    if args.generated_only and args.generated < 1:
        p.error('--generated-only requires a positive --generated')
    if args.pack and '5.1' in args.versions:
        p.error('--pack requires --versions 5.3')
    if args.lua51_worker:
        from lupa.lua51 import LuaRuntime
        runtime=LuaRuntime(encoding=None)
        if args.harness:
            runtime.globals().arg=runtime.table_from({1:str(args.lua51_worker).encode()})
        runtime.execute((args.harness or args.lua51_worker).read_bytes())
        return 0
    from obfuscator.vm import VMPass
    from obfuscator.vm.targets.profile import TargetProfile
    from run_cross_backend_generated_regression import generated_source
    args.output.mkdir(parents=True, exist_ok=True)
    if args.harness:
        observer=args.harness.read_text(encoding='utf-8')
        args.harness=args.output/'_observer.lua'
        args.harness.write_text(observer,encoding='utf-8')
    fixture = (ROOT/'test/fixtures/vm_unexpected.lua').read_text(encoding='utf-8')
    sources = ([(path.stem, path.read_text(encoding='utf-8')) for path in args.inputs]
               if args.inputs else [('unexpected', fixture)])
    if args.generated_only:
        sources=[]
    sources += [(f'generated-{seed}', generated_source(seed)) for seed in range(args.generated)]
    sources += [(f'expressions-{seed}', expression_source(seed)) for seed in range(args.generated)]
    report = {'python': sys.version, 'records': [], 'failures': []}
    for name, source in sources:
        original = args.output/(name+'.lua')
        original.write_text(source, encoding='utf-8')
        for version in args.versions:
            expected = execute(original, version, harness=args.harness)
            if expected['returncode'] != 0:
                raise RuntimeError(('native oracle failed', name, version, expected))
            for backend in args.backends:
                for mode in args.modes:
                    generated = name.startswith(('generated-', 'expressions-'))
                    for seed in args.seeds[:1] if generated else args.seeds:
                        tag = f'{name}-{version}-{backend}-{mode}-{seed}'
                        random.seed(seed)
                        options = settings(backend, mode, seed)
                        start = time.perf_counter()
                        row = dict(tag=tag, version=version, backend=backend,
                                   mode=mode, seed=seed, options=options, expected=expected,
                                   vm_output_passes=args.vm_output_passes)
                        try:
                            output = VMPass(target=TargetProfile(version, backend),
                                            vm_options=options, vm_output_passes=args.vm_output_passes).run(source)
                            if args.pack:
                                from obfuscator.passes.packer import PackerPass
                                output=PackerPass(packer_output_passes=['minify']).run(output)
                                row['packer_options']={'output_passes':['minify']}
                            row['build_seconds'] = time.perf_counter()-start
                            row['output_bytes'] = len(output.encode())
                            artifact = args.output/(tag+'.lua')
                            artifact.write_text(output, encoding='utf-8')
                            actual = execute(artifact, version, harness=args.harness)
                            row['actual'] = actual
                            row['matches'] = actual['returncode'] == 0 and actual['stdout'] == expected['stdout']
                            row['differences'] = [{'native': a, 'vm': b} for a, b in
                                zip_longest(expected['stdout'].splitlines(), actual['stdout'].splitlines()) if a != b]
                        except Exception as error:
                            row.update(matches=False, build_error=repr(error))
                        report['records'].append(row)
                        if not row['matches']:
                            report['failures'].append(tag)
                        (args.output/'report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
                        print('MATCH' if row['matches'] else 'DIFFERENCE', tag,
                              row.get('differences', row.get('build_error')), flush=True)
    print('differential-summary', len(report['records']), 'builds', len(report['failures']), 'differences')
    return int(bool(report['failures']))


if __name__ == '__main__':
    raise SystemExit(main())
