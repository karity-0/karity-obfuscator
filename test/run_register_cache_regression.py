"""Open upvalues must observe writes made by resumed VM execution frames."""
from pathlib import Path
import random
import sys
import argparse
import re

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tools'))
from profile_vm_runtime import execute
from obfuscator.vm.targets.profile import TargetProfile
from obfuscator.vm.vm_pass import VMPass

SOURCE = r'''
local value = function() return 7 end
local function get() return value end
local function set(v) value = v end
assert(type(get()) == 'function')
value = {11, 22, 33}
assert(type(get()) == 'table', 'stale function after resumed owner write')
assert(#get() == 3)
value = nil
assert(get() == nil, 'stale table after nil write')
value = false
assert(get() == false, 'cached nil hid false write')
set(42)
assert(get() == 42, 'sibling upvalue write was not visible')
value = {99}
assert(get()[1] == 99)
for i = 1, 40 do
    value = i * 3
    assert(get() == i * 3)
    set(i * 7)
    assert(get() == i * 7)
end
print('register-cache-ok')
'''

OPTIONS = {
    'fake_handlers': False, 'mutate_handlers': False,
    'junk_instructions': False, 'junk_rate': 0,
    'graph_execution_rate': 0, 'cross_instruction_rate': 0,
    'runtime_polymorphism_rate': 0, 'block_variant_rate': 0,
    'helper_variant_count': 1, 'helper_diversity_rate': 0,
    'semantic_diversity_rate': 0, 'blob_form': 'string',
}

def cache_contract_checks(version):
    # Exercise the real guard with representation decoding stubbed. A remap
    # can change the bank address while retaining the same register epoch.
    path = ROOT / ('obfuscator/vm/runtimes/lua51/vm.lua' if version == '5.1'
                   else 'obfuscator/vm/vm.lua')
    source = path.read_text(encoding='utf-8').split('--<<RGET>>', 1)[1].split('--<<ENDRGET>>', 1)[0]
    source = re.sub(r'\(--<<TARGET_PRIVATE_EXPRESSION>>.*?--<<ENDTARGET_PRIVATE_EXPRESSION>>\s*\)',
                    'regs[p1]', source, flags=re.S)
    harness = '''
local _RC,_MJ={}, {_RC={}}
local _MG,_RE,_RT,regs,_RS,_PD={1},{},{},{},{},{}
local positions,decoded,pending=0,0,0
local function _rpos(_,i) return _MG[1]*10+i end
local function _rpositions(i)
    positions=positions+1;local p=_rpos(1,i);return p,p,p,p
end
local function _rparams() return 1,0,1 end
local function _rdecode(value,kind)
    decoded=decoded+1;if kind==3 then return nil end;return value
end
local function _pending_finish(i)
    pending=pending+1;local p=_rpos(1,i);_PD[p]=nil
    regs[p],_RE[p],_RT[p]=77,12,1
end
''' + source + '''
assert(rget(1)==nil);local n=positions
assert(rget(1)==nil and positions==n and decoded==0)
regs[11],_RE[11],_RT[11]=false,10,1
assert(rget(1)==false);n=positions
assert(rget(1)==false and positions==n and decoded==1)
regs[11],_RE[11],_RT[11]=nil,11,3
assert(rget(1)==nil and decoded==2)
_MG[1]=2;regs[21],_RE[21],_RT[21]=123,11,1
assert(rget(1)==123 and decoded==3, 'remap used an old bank address')
_PD[21]=true
assert(rget(1)==77 and pending==1 and decoded==4, 'cache hid pending producer')
'''
    module = __import__('lupa.lua51' if version == '5.1' else 'lupa.lua53', fromlist=['LuaRuntime'])
    module.LuaRuntime().execute(harness)
    print('cache-contract-ok', version, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--full', action='store_true')
    parser.add_argument('--lua', nargs='+', choices=('5.1', '5.3'), default=['5.1', '5.3'])
    args = parser.parse_args()
    for version in args.lua:
        cache_contract_checks(version)
    cases = [(124, 'ifelseif', 1, 1, False)]
    if args.full:
        cases += [(71337, 'tailcall', 2, 3, False), (2718, 'bsearch', 2, 3, False),
                  (42, 'mixed', 2, 3, True)]
    for version, backend, (seed, dispatcher, count, helpers, protected) in (
        (version, backend, case) for version in args.lua
        for backend in ('karity', 'classic', 'mov')
        for case in (cases if backend == 'karity' else cases[:1])
    ):
        random.seed(seed)
        vm = VMPass(target=TargetProfile(version, backend), vm_options={
            **OPTIONS, 'dispatcher_type': dispatcher, 'vm_count': count,
            'helper_variant_count': helpers,
            'helper_diversity_rate': 1 if helpers > 1 else 0,
            'semantic_diversity_rate': 1 if helpers > 1 else 0,
            'graph_execution_rate': .25 if protected else 0,
            'cross_instruction_rate': .5 if protected else 0,
            'runtime_polymorphism_rate': .4 if protected else 0,
            'semantic_state_threading': protected,
            'dispatcher_target_hiding': protected,
            'argument_virtualization': protected,
            'upvalue_virtualization': protected,
            'table_virtualization': protected,
        })
        output = vm.run(SOURCE)
        actual, _ = execute(output, version)
        assert actual == b'register-cache-ok', actual
        print('register-cache-ok', version, backend, seed, dispatcher, count, helpers, protected, flush=True)

if __name__ == '__main__':
    main()
