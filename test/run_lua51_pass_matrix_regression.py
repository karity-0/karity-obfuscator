"""Lua 5.1 VM output passes: explicit rejection and executable support."""
from __future__ import annotations

import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lupa.lua51 import LuaRuntime

from obfuscator import Pipeline, build_pipeline_from_config
from obfuscator.passes.localize_globals import LocalizeGlobalsPass
from obfuscator.vm import VMPass
from obfuscator.vm.targets.profile import TargetProfile


SOURCE = '''
-- source-pass matrix marker
local function f(value, ...)
    local args = {...}
    return value, args[1]
end
local a, b = f(false, "matrix")
assert(a == false and b == "matrix")
'''
OUTPUT_CASES = (
    ('strip_info',),
    ('remove_comment',),
    ('string_encode',),
    ('table_obf',),
    ('minify',),
    ('rename_obf',),
    ('localize_globals',),
    ('rename_obf', 'localize_globals', 'minify'),
)
SOURCE_PASSES = (
    'strip_info', 'remove_comment', 'string_encode',
    'table_obf', 'rename_obf', 'minify',
)


def main() -> int:
    # A generated VM closure may already use nearly every Lua 5.1 local.
    # Compact localization snapshots the same globals with two locals total.
    names = ','.join(f'v{index}' for index in range(196))
    near_limit = (
        'local _ENV=_G; return function() local ' + names +
        '; return type(1), math.floor(1.5), string.char(65) end'
    )
    compact = Pipeline(show_header=False).add(
        LocalizeGlobalsPass(compact_aliases=True)
    ).run(near_limit)
    assert LuaRuntime(encoding=None).execute(compact.encode())() == (
        b'number', 1, b'A'
    )

    builds = 0
    for index, name in enumerate(SOURCE_PASSES):
        random.seed(8700 + index)
        pipeline = build_pipeline_from_config({
            'passes': [name, 'vm'],
            'target': {'lua_version': '5.1'},
            'vm_options': {
                'backend': 'classic', 'vm_count': 1, 'blob_form': 'string',
                'fake_handlers': False, 'mutate_handlers': False,
                'junk_instructions': False,
            },
        }, Pipeline, show_header=False)
        LuaRuntime(encoding=None).execute(pipeline.run(SOURCE).encode())
        builds += 1
        print('lua51-pass-source-ok', name, flush=True)
    for backend_index, backend in enumerate(('classic', 'karity', 'mov')):
        for case_index, passes in enumerate(OUTPUT_CASES):
            random.seed(8800 + 100 * backend_index + case_index)
            vm = VMPass(
                target=TargetProfile('5.1', backend),
                vm_output_passes=list(passes),
                vm_options={
                    'vm_count': 1, 'blob_form': 'string',
                    'fake_handlers': False, 'mutate_handlers': False,
                    'junk_instructions': False, 'integrity_constants': True,
                },
            )
            output = vm.run(SOURCE)
            details = next(item['details'] for item in vm.last_profile
                           if item['phase'] == 'obfuscate_vm_output')
            phases = {item['phase'] for item in details}
            assert all('vm_output:' + name in phases for name in passes)
            LuaRuntime(encoding=None).execute(output.encode())
            builds += 1
            print('lua51-pass-output-ok', backend, ','.join(passes), flush=True)
    print(f'lua51-pass-matrix-ok executable-builds={builds}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
