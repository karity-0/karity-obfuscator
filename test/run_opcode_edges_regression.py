"""Differential opcode boundaries against the matching native Lua interpreter."""
from pathlib import Path
import argparse
import random
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lua_runtime import lua_executable
from obfuscator.vm import VMPass
from obfuscator.vm.targets.profile import TargetProfile
from run_vm_backend_regression import options


def check_loop_effects():
    from obfuscator.vm.frontends.lua51 import build_semantic_ir as build51
    from obfuscator.vm.frontends.lua53 import build_semantic_ir as build53
    from run_vm_ir_regression import proto, abc, abx
    for build, prep, ret in ((build51, 32, 30), (build53, 40, 38)):
        ir = build(proto([abx(prep, 0, 131071), abc(ret, 0, 1)]))
        instruction = ir.root.blocks[0].instructions[0]
        registers = {value.id for value in ir.root.values
                     if value.kind == 'register' and value.index in (0, 1, 2)}
        assert len(registers) == 3
        assert registers <= set(instruction.inputs)
        assert registers <= set(instruction.outputs)


def execute(source, version):
    if version == '5.1':
        from lupa.lua51 import LuaRuntime
        runtime = LuaRuntime()
        rows = []
        runtime.globals().print = lambda *args: rows.append('\t'.join(
            str(v).lower() if isinstance(v, bool) else str(v) for v in args))
        runtime.execute(source)
        return rows
    with tempfile.TemporaryDirectory(prefix='opcode-edges-') as folder:
        path = Path(folder) / 'output.lua'
        path.write_text(source, encoding='utf-8')
        result = subprocess.run([lua_executable(version), str(path)],
                                capture_output=True, timeout=60)
        assert result.returncode == 0, result.stderr.decode(errors='replace')
        return result.stdout.decode().splitlines()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--numeric-matrix', action='store_true',
                        help='run 1,728 bounded loop input combinations per target/backend')
    args = parser.parse_args()
    check_loop_effects()
    fixture = 'opcode_numeric_matrix.lua' if args.numeric_matrix else 'opcode_edges.lua'
    source = (ROOT / 'test/fixtures' / fixture).read_text(encoding='utf-8')
    failures = []
    for version in ('5.1', '5.3'):
        expected = execute(source, version)
        if args.numeric_matrix:
            assert len(expected) == 1728
        else:
            assert 'error-cell-gc\ttrue\ttrue' in expected
            expected_errors = {'for-metamethod-rejected', 'concat-nil',
                               'concat-trailing-nil', 'concat-metamethod-returns-nil'}
            for row in expected:
                name, success, _ = row.split('\t', 2)
                assert (success == 'false') == (name in expected_errors), row
        for backend in ('classic', 'karity', 'mov'):
            modes = (('minimal', 20261016),) if args.numeric_matrix else (
                ('minimal', 124), ('protected', 7719))
            for mode, seed in modes:
                random.seed(seed)
                settings = options(backend)
                if mode == 'protected':
                    settings.update({
                        'helper_variant_count': 4, 'helper_diversity_rate': 1.0,
                        'upvalue_virtualization': True, 'argument_virtualization': True,
                        'table_virtualization': True, 'semantic_diversity_rate': 0.5,
                        'graph_execution_rate': 0.5, 'cross_instruction_rate': 0.5,
                        'runtime_polymorphism_rate': 0.5,
                    })
                output = VMPass(target=TargetProfile(version, backend),
                                vm_options=settings, vm_output_passes=[]).run(source)
                actual = execute(output, version)
                if actual != expected:
                    failures.append((version, backend, mode))
                    for native, protected in zip(expected, actual):
                        if native != protected:
                            print('MISMATCH', version, backend, mode,
                                  repr(native), '!=', repr(protected), flush=True)
                    assert len(actual) == len(expected), (expected, actual)
                else:
                    print('opcode-edges-ok', version, backend, mode, len(expected), flush=True)
    assert not failures, failures
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
