"""One verification manifest, feature ownership, and deterministic CI planning.

Planning uses only the standard library so Actions can select jobs before pip.
Unclassified production changes and missing Git history select the full suite.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, replace
from fnmatch import fnmatchcase
import math
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]

# A suite can protect several features. This is intentionally an explicit
# contract map, rather than Python import discovery (which misses Lua/codegen).
FEATURE_SUITES = {
    'strings': 'string_encode string_obf literal_mosaic function_cost vm_output_emitter vm_finalize runtime_security line_state selection packer lua51_pass_matrix user_presets',
    'numbers': 'number_obf meme_strings literal_mosaic boolean_table function_cost vm_output_emitter vm_finalize opcode_edges user_presets',
    'tables': 'boolean_table selection vm_output_emitter source_protection',
    'functions': 'function_boundary function_loop function_nested function_lua51 function_cost selection literal_mosaic string_obf lua51_pass_matrix vm_output_emitter',
    'formatting': 'minify semicolon strip_info selection vm_finalize line_state string_encode runtime_security',
    'naming': 'rename strip_info selection function_boundary vm_finalize vm_output_emitter runtime_security',
    'security': 'anti_env source_protection runtime_security line_state signature runtime_skeleton vm_lifetime closure_gc bare_backend',
    'packing': 'packer signature line_state string_encode string_obf runtime_security vm_finalize',
    'selection': 'selection kes kes_integration user_presets function_cost target_capability',
    'gui': 'gui gui_experience user_presets signature',
    'presets': 'user_presets gui gui_experience backend_options target_capability vm_runtime_size',
    'kes': 'kes kes_integration selection',
    'ir': 'ir_facts ir_morphing ir_options vm_ir opcode_edges cross_backend_generated block_permutation register_cache',
    'synthesis': 'opcode_synthesis opcode_synthesis_backend synthesis_dag synthesis_control opcode_edges vm_choke state_coupling',
    'runtime': 'runtime_poly runtime_trace vm_lifetime closure_gc register_cache state_coupling vm_mutation runtime_skeleton vm_runtime_size cross_backend_generated',
    'backends': 'backend_options vm_backend mov_backend bare_backend block_permutation vm_ir cross_backend_generated',
    'karity': 'karity_analysis state_coupling vm_backend register_cache runtime_poly runtime_trace vm_choke vm_runtime_size',
    'mov': 'mov_backend vm_backend cross_backend_generated opcode_edges',
    'bare': 'bare_backend source_protection runtime_security cross_backend_generated',
    'targets': 'lua_frontend lua51_word lua51_runtime lua51_pass_matrix lua51_semantic_matrix dump51 lua51_toolchain target_capability closure_gc host_materialization',
    'host': 'image_resolver host_materialization native_lowering target_capability',
    'toolchain': 'toolchain lua51_toolchain dump51 lua_frontend',
    'serialization': 'serialization blob_form source_protection opcode_edges',
}
FEATURE_SUITES = {k: frozenset(v.split()) for k, v in FEATURE_SUITES.items()}
PASS_FEATURES = {
    'strip_info': 'naming formatting', 'remove_comment': 'formatting',
    'string_encode': 'strings', 'string_obf': 'strings', 'string_flow_obf': 'strings',
    'boolean_obf': 'numbers', 'number_obf': 'numbers', 'meme_strings': 'numbers strings',
    'table_obf': 'tables', 'function_obf': 'functions', 'rename_obf': 'naming',
    'localize_globals': 'naming', 'minify': 'formatting', 'semicolon': 'formatting',
    'vm': 'backends runtime', 'anti_debug': 'security', 'anti_env': 'security',
    'anti_decompile': 'security', 'pack': 'packing',
}
BACKEND_FEATURES = {'classic': 'backends targets', 'karity': 'karity',
                    'mov': 'mov', 'bare': 'bare'}

# Historical Ubuntu Actions seconds, rounded. Scheduling hints, never budgets
# or pass criteria. They may be updated without changing coverage.
WEIGHTS = dict(zip(
    'kes_integration synthesis_dag synthesis_control opcode_synthesis_backend lua51_pass_matrix mov_backend cross_backend_generated runtime_trace vm_backend lua51_runtime vm_output_emitter vm_lifetime runtime_skeleton vm_runtime_size function_lua51 ir_morphing kes block_permutation lua51_semantic_matrix selection string_obf function_cost'.split(),
    (510, 495, 490, 450, 370, 270, 225, 195, 185, 135, 125, 105, 100, 85, 85, 80, 80, 65, 65, 50, 50, 45),
))
QUICK = frozenset('verification pass_contract import typing ir_facts ir_options opcode_synthesis strip_info minify rename backend_options target_capability image_resolver dump51 lua51_toolchain'.split())

FULL_PATHS = (
    '.github/**', 'requirements*.txt', 'pyproject.toml', 'mypy.ini', '.gitattributes', 'bin/**',
    'test/run_ci.py', 'test/verification.py', 'test/run_verification_regression.py',
    'test/pass_contracts.py', 'test/run_pass_contract_regression.py',
    'obfuscator/__init__.py', 'obfuscator/passes/__init__.py', 'obfuscator/passes/base.py',
    'obfuscator/passes/ts_utils.py', 'obfuscator/pipeline.py', 'obfuscator/registry.py',
    'obfuscator/config_types.py', 'obfuscator/data_types.py', 'obfuscator/parser*.py',
    'obfuscator/names.py', 'obfuscator/profiling.py', 'obfuscator/toolchain.py',
    'test/lua_runtime.py',
)
PATH_FEATURES = (
    ('obfuscator/passes/string*.py', 'strings'),
    ('obfuscator/passes/*mosaic*.py', 'strings numbers functions'),
    ('obfuscator/passes/numeric_provenance.py', 'strings numbers functions'),
    ('obfuscator/passes/number*.py', 'numbers'),
    ('obfuscator/passes/meme*.py', 'strings numbers'),
    ('obfuscator/passes/boolean*.py', 'numbers tables'),
    ('obfuscator/passes/table*.py', 'tables'),
    ('obfuscator/passes/function*.py', 'functions'),
    ('obfuscator/passes/rename*.py', 'naming'),
    ('obfuscator/passes/localize_globals.py', 'naming'),
    ('obfuscator/passes/strip_info.py', 'naming formatting'),
    ('obfuscator/passes/remove_comment.py', 'formatting'),
    ('obfuscator/passes/minify.py', 'formatting'),
    ('obfuscator/passes/semicolon.py', 'formatting'),
    ('obfuscator/passes/anti_*.py', 'security'),
    ('obfuscator/passes/output_signature.py', 'security packing'),
    ('obfuscator/passes/pack*', 'packing'),
    ('obfuscator/selection*.py', 'selection'),
    ('obfuscator/selective_vm.py', 'selection'),
    ('obfuscator/presets.py', 'presets'),
    ('config*.example.json', 'presets selection'),
    ('obfuscator/kes*.py', 'kes'),
    ('obfuscator/vm/ir/**', 'ir'),
    ('obfuscator/vm/synthesis/**', 'synthesis'),
    ('obfuscator/vm/mov/**', 'mov'),
    ('obfuscator/vm/backends/mov.py', 'mov'),
    ('obfuscator/vm/backends/bare*.py', 'bare'),
    ('obfuscator/vm/backends/karity*.py', 'karity'),
    ('obfuscator/vm/targets/image_resolver.py', 'host'),
    ('obfuscator/vm/targets/materialization.py', 'host'),
    ('obfuscator/vm/targets/**', 'targets'),
    ('obfuscator/vm/runtime_security.py', 'security'),
    ('obfuscator/vm/runtime_finalization.py', 'strings naming formatting security'),
    ('obfuscator/vm/environment.py', 'security strings'),
    ('obfuscator/vm/line_state.py', 'security strings formatting'),
    ('obfuscator/vm/source_protection.py', 'security bare'),
    ('obfuscator/vm/string_storage.py', 'strings security'),
    ('obfuscator/vm/output_emitter.py', 'strings numbers functions naming'),
    ('obfuscator/vm/native_capture.py', 'security naming'),
    ('obfuscator/vm/blob_formats.py', 'serialization'),
    ('obfuscator/serializer*.py', 'serialization'),
    ('gui/**', 'gui'),
    ('obfuscator_gui.py', 'gui'),
    ('tools/generate_config_docs.py', 'presets'),
)


@dataclass(frozen=True)
class Check:
    name: str
    command: tuple[str, ...]
    features: frozenset[str]
    quick: bool = False
    seconds: int = 10


@dataclass(frozen=True)
class Plan:
    level: str
    features: frozenset[str]
    checks: tuple[Check, ...]
    reasons: tuple[str, ...] = ()


def features_for_suite(name):
    return frozenset(k for k, suites in FEATURE_SUITES.items() if name in suites)


def make_checks(regressions):
    checks = [Check('docs', ('tools/generate_config_docs.py', '--check'), frozenset(), True, 1)]
    for name in regressions:
        command = (f'test/run_{name}_regression.py',)
        if name == 'register_cache':
            command += ('--full',)
        checks.append(Check(name, command, features_for_suite(name), name in QUICK,
                            WEIGHTS.get(name, 2 if name in QUICK else 15)))
    checks += [
        Check('lua51_audit', ('tools/audit_lua51_dependencies.py',), frozenset({'targets', 'runtime', 'backends'}), seconds=45),
        Check('semantic_scripts', ('test/run_test.py', '--config', 'config.example.json', '--profile', 'dev', '--jobs', '2'),
              frozenset(FEATURE_SUITES), seconds=30),
    ]
    return tuple(checks)


def validate_manifest(regressions, checks, root=ROOT):
    if len(set(regressions)) != len(regressions):
        raise ValueError('Duplicate regression names')
    expected = {f'run_{n}_regression.py' for n in regressions}
    discovered = {p.name for p in (root / 'test').glob('run_*_regression.py')}
    if expected != discovered:
        raise ValueError(f'CI regression manifest is out of sync: {sorted(expected ^ discovered)}')
    declared = set(regressions)
    used = set().union(*FEATURE_SUITES.values())
    if used - declared:
        raise ValueError(f'Unknown suites in feature map: {sorted(used - declared)}')
    missing = declared - used - QUICK
    if missing:
        raise ValueError(f'Regressions need feature ownership: {sorted(missing)}')
    tree = ast.parse((root / 'obfuscator/registry.py').read_text(encoding='utf-8'))
    registry = next(n.value for n in tree.body if isinstance(n, ast.AnnAssign)
                    and isinstance(n.target, ast.Name) and n.target.id == 'PASS_REGISTRY')
    passes = {k.value for k in registry.keys}
    if passes != PASS_FEATURES.keys():
        raise ValueError(f'Passes need verification ownership: {sorted(passes ^ PASS_FEATURES.keys())}')
    for name, features in PASS_FEATURES.items():
        if not set(features.split()) <= FEATURE_SUITES.keys():
            raise ValueError(f'Unknown feature ownership for {name}')
    backend_tree = ast.parse((root / 'obfuscator/vm/backends/__init__.py').read_text(encoding='utf-8'))
    backend_registry = next(n.value for n in backend_tree.body if isinstance(n, ast.AnnAssign)
                            and isinstance(n.target, ast.Name) and n.target.id == '_BACKENDS')
    backends = {k.value for k in backend_registry.keys}
    if backends != BACKEND_FEATURES.keys():
        raise ValueError(f'Backends need verification ownership: {sorted(backends ^ BACKEND_FEATURES.keys())}')
    for name, features in BACKEND_FEATURES.items():
        if not set(features.split()) <= FEATURE_SUITES.keys():
            raise ValueError(f'Unknown feature ownership for backend {name}')
    if len({c.name for c in checks}) != len(checks):
        raise ValueError('Duplicate check IDs')


def changed_paths(base, root=ROOT):
    """Include staged/worktree/untracked changes locally; CI checkout is clean."""
    def git(*args):
        return subprocess.check_output(['git', '-c', f'safe.directory={root.as_posix()}', *args],
                                       cwd=root, stderr=subprocess.DEVNULL)
    try:
        commit = git('rev-parse', '--verify', '--end-of-options', base + '^{commit}').decode().strip()
        ancestor = git('merge-base', commit, 'HEAD').decode().strip()
        raw = git('diff', '--name-only', '--no-renames', '-z', ancestor, '--')
        raw += git('ls-files', '--others', '--exclude-standard', '-z')
        return tuple(sorted(set(p.decode('utf-8') for p in raw.split(b'\0') if p)))
    except (subprocess.CalledProcessError, OSError, UnicodeError):
        return None


def impact(paths, checks):
    affected, explicit, reasons = set(), set(), []
    for original in paths:
        path = original.replace('\\', '/')
        if any(fnmatchcase(path, pattern) for pattern in FULL_PATHS):
            return frozenset(), frozenset(), (f'full: shared infrastructure changed ({path})',)
        if path.startswith('docs/') or path.lower().startswith('readme') or path in {'LICENSE', '.gitignore'}:
            continue
        suite = next((c for c in checks if path == c.command[0]), None)
        if suite is not None:
            explicit.add(suite.name)
            affected.update(suite.features)
            continue
        matched = [features for pattern, features in PATH_FEATURES if fnmatchcase(path, pattern)]
        if not matched:
            return frozenset(), frozenset(), (f'full: unclassified changed path ({path})',)
        for features in matched:
            affected.update(features.split())
    if affected:
        reasons.append('features: ' + ', '.join(sorted(affected)))
    else:
        reasons.append('no runtime changes; quick checks only')
    return frozenset(affected), frozenset(explicit), tuple(reasons)


def select_checks(checks, *, level='full', features=(), paths=None):
    if level not in {'quick', 'related', 'full'}:
        raise ValueError(f'Unknown verification level: {level}')
    features = frozenset(features)
    unknown = features - FEATURE_SUITES.keys()
    if unknown:
        raise ValueError(f'Unknown verification features: {sorted(unknown)}')
    explicit, reasons = frozenset(), ()
    if level == 'related' and paths is not None:
        affected, explicit, reasons = impact(paths, checks)
        features |= affected
        if any(r.startswith('full:') for r in reasons):
            level = 'full'
    elif level == 'related' and not features:
        level, reasons = 'full', ('full: no feature or change base supplied',)
    selected = tuple(c for c in checks if level == 'full' or c.quick
                     or (level == 'related' and (c.features & features or c.name in explicit)))
    adapted = []
    for check in selected:
        if check.name == 'pass_contract':
            command = check.command
            if level == 'quick' or not features and level != 'full':
                command += ('--quick',)
            elif level == 'related':
                for feature in sorted(features):
                    command += ('--feature', feature)
            check = replace(check, command=command, seconds=10 if '--quick' in command else 60)
        adapted.append(check)
    return Plan(level, features, tuple(adapted), reasons)


def shards(checks, count):
    if count < 1:
        raise ValueError('Shard count must be positive')
    bins = [[] for _ in range(min(count, len(checks)))]
    costs = [0] * len(bins)
    for check in sorted(checks, key=lambda c: (-c.seconds, c.name)):
        index = min(range(len(bins)), key=lambda i: (costs[i], i))
        bins[index].append(check)
        costs[index] += check.seconds
    # Fast checks (including function-cost contracts) fail before large builds.
    return tuple(tuple(sorted(bucket, key=lambda c: (not c.quick, c.seconds, c.name))) for bucket in bins)


def actions_matrix(plan, count=4):
    # Do not multiply runner startup/install work for a small quick-only plan.
    count = min(count, max(1, math.ceil(sum(c.seconds for c in plan.checks)/240)))
    groups = shards(plan.checks, count)
    platforms = (('ubuntu-latest', '3.12'), ('ubuntu-latest', '3.15'), ('windows-latest', '3.12'))
    return {'include': [
        {'os': os, 'python': python, 'shard': f'{index+1}/{len(groups)}',
         'selection': {'level': plan.level, 'features': sorted(plan.features),
                       'checks': [c.name for c in group]}}
        for os, python in platforms for index, group in enumerate(groups)
    ]}
