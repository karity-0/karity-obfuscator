"""Measure textual target-runtime dependencies for fixed Lua 5.1 builds.

Counts are static call sites after VM output passes but before line-state and
wrapper emission, not execution frequency or a completion percentage.
"""
from collections import Counter
import json
from pathlib import Path
import random
import re
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from obfuscator.vm.targets.lua51 import Lua51Target
from obfuscator.vm.targets.profile import TargetProfile
from obfuscator.vm.vm_pass import VMPass


def main():
    source = '''local function f(a,...)
local t={...};local s=a
for i=1,#t do s=s+t[i] end
return s,function(x) return s+x end
end
local a,g=f(1,2,3);assert(a==6 and g(4)==10)
'''
    original = Lua51Target.lower_source
    results = []
    for profile, options in (
        ('lean', {'fake_handlers': False, 'mutate_handlers': False, 'junk_instructions': False}),
        ('default', {}),
        ('lean-string', {'fake_handlers': False, 'mutate_handlers': False,
                         'junk_instructions': False, 'blob_form': 'string'}),
    ):
        for backend in ('classic', 'karity', 'mov'):
            captured = []
            def capture(self, runtime):
                # Count the actual target path for every native backend. Keep
                # this audit sensitive to accidental compatibility calls even
                # though no backend should inject the old module prelude.
                translated = original(self, runtime)
                _, marker, body = translated.partition('--[[TARGET51_PRELUDE_END]]')
                if not marker:
                    body = translated
                captured.append({
                    'compatibility_modules': (
                        'local I=(function' in translated
                        or 'local _target51=(function' in translated
                    ),
                    'legacy_aliases': '_legacy_' in translated,
                    'shim_calls': dict(sorted(Counter(re.findall(
                        r'\b_target51\.([A-Za-z_]\w*)\s*\(', body)).items())),
                    'storage_calls': dict(sorted(Counter(re.findall(
                        r'\bI\.([A-Za-z_]\w*)\s*\(', body)).items())),
                })
                return translated
            random.seed(5812)
            outcome = {}
            vm = VMPass(target=TargetProfile('5.1', backend), vm_options=options)
            try:
                with patch.object(Lua51Target, 'lower_source', capture):
                    output = vm.run(source)
                outcome['output_bytes'] = len(output.encode())
                from lupa.lua51 import LuaRuntime
                LuaRuntime(encoding=None).execute(output.encode())
                outcome['execution'] = 'passed'
            except Exception as error:
                outcome['error'] = str(error)
            if vm._backend.last_protection_plan is not None:
                plan = vm._backend.last_protection_plan
                outcome['blob_form'] = next(state['blob_form'] for state in plan.functions.values()
                                            if 'blob_form' in state)
            assert len(captured) == 1
            results.append({'profile': profile, 'backend': backend, 'seed': 5812,
                            **outcome, **captured[0]})
    print(json.dumps({'scope': 'after VM output passes; before line-state and wrapper',
                      'source': source, 'builds': results}, indent=2))
    failures = [result for result in results
                if result.get('execution') != 'passed' or result['compatibility_modules']
                or result['legacy_aliases']
                or result['shim_calls'] or result['storage_calls']]
    if failures:
        raise SystemExit(f'{len(failures)} Lua 5.1 build(s) retain compatibility dependencies')


if __name__ == '__main__':
    main()
