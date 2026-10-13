"""Audited shared leaves must not capture VM state or change protection."""
from pathlib import Path
import random
import sys
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tools'))
from lupa.lua53 import LuaRuntime
from obfuscator.vm.backends.runtime_skeleton import share_runtime_helpers
from obfuscator.vm.backends.classic import ClassicBackend
from profile_vm_runtime import build,execute,FIXTURES


def structural_checks():
    prefix='local function _pmix(x)return x*3 end; local _ex0,_ex1;'
    def executor(index,extra='',ending='return _rmix(_rslot(proto))'):
        return f'''_ex{index}=function(proto) {extra}
local function _rmix(x)return _pmix(x) end
local function _rslot(slot)return ((slot&0x3FF)) end
{ending} end;'''
    source=prefix+executor(0)+executor(1)+'return _ex0(7),_ex1(9)'
    after,stats=share_runtime_helpers(source,('_rmix','_rslot'))
    assert LuaRuntime().execute(source)==LuaRuntime().execute(after)==(21,27)
    assert stats['skeleton_declarations_removed']==2
    assert stats['skeleton_shared_helpers']==['_rmix','_rslot']
    # Different lexical mixers must not be merged despite identical spelling.
    shadow=prefix+executor(0,'local _pmix=function(x)return x*4 end')+executor(1)+'return _ex0(7),_ex1(9)'
    after,stats=share_runtime_helpers(shadow,('_rmix','_rslot'))
    assert LuaRuntime().execute(shadow)==LuaRuntime().execute(after)==(28,27)
    assert stats['skeleton_shared_helpers']==['_rslot']
    escape=prefix+executor(0,ending='return {_rslot}')+executor(1)+'return _ex1(9)'
    after,stats=share_runtime_helpers(escape,('_rslot',))
    assert after==escape and not stats['skeleton_shared_helpers']
    changed=source.replace('(slot&0x3FF)','(slot&0x7FF)')
    assert not share_runtime_helpers(changed,('_rslot',))[1]['skeleton_shared_helpers']
    mutable=source.replace('return _ex0(7),_ex1(9)','_pmix=function(x)return x*5 end;return _ex0(7),_ex1(9)')
    after,stats=share_runtime_helpers(mutable,('_rmix',))
    assert after==mutable and not stats['skeleton_shared_helpers']
    # Parenthesized calls can truncate multiple results; do not normalize them.
    arity=source.replace('return _pmix(x)', 'return (_pmix(x))', 1)
    assert not share_runtime_helpers(arity,('_rmix',))[1]['skeleton_shared_helpers']
    scoped=prefix+'do '+executor(0)+'end;do '+executor(1)+'end;return _ex0(7),_ex1(9)'
    after,stats=share_runtime_helpers(scoped,('_rmix','_rslot'))
    assert after==scoped and not stats['skeleton_shared_helpers']
    assert LuaRuntime().execute(after)==(21,27)
    local_owners=source.replace('_ex0=function', 'local _ex0=function').replace('_ex1=function', 'local _ex1=function')
    assert share_runtime_helpers(local_owners,('_rslot',))[0]==local_owners


def main():
    structural_checks()
    for version in ('5.1','5.3'):
        for count in (1,2,3):
            options={'lua_version':version,'vm_count':count,'graph_execution_rate':1,
                     'cross_instruction_rate':1,'runtime_polymorphism_rate':1,'block_variant_rate':1,
                     'semantic_state_threading':True,'argument_virtualization':True,
                     'upvalue_virtualization':True,'table_virtualization':True,'branch_virtualization':True}
            source=FIXTURES['closures']
            expected,_=execute(source,version)
            def unchanged(source,candidates,**kwargs):
                # Keep closed-runtime dead-helper removal when sharing is off.
                return share_runtime_helpers(source,(),**kwargs)
            with patch('obfuscator.vm.backends.runtime_skeleton.share_runtime_helpers',unchanged):
                before=build(source,options,9913)
            after=build(source,options,9913)
            assert before['blob_sha256']==after['blob_sha256']
            assert before['plan_sha256']==after['plan_sha256']
            assert execute(before['output'],version)[0]==execute(after['output'],version)[0]==expected
            if count==1:
                assert before['runtime']==after['runtime']
            else:
                stats=after['emission'];assert stats['skeleton_declarations_removed']>0
                for key in ('arithmetic_dags_after','semantic_variants_after','occurrence_families'):
                    assert before['emission'][key]==stats[key]
                assert len(after['runtime'].encode())<len(before['runtime'].encode())
            print('runtime-skeleton-ok',version,count,flush=True)
        for backend in ('classic', 'mov'):
            options = {'lua_version': version, 'backend': backend, 'vm_count': 2}
            source = FIXTURES['closures']
            expected, _ = execute(source, version)
            with patch.object(ClassicBackend, 'shared_runtime_helpers', ()):
                before = build(source, options, 9913)
            after = build(source, options, 9913)
            assert before['blob_sha256'] == after['blob_sha256']
            assert before['plan_sha256'] == after['plan_sha256']
            assert execute(before['output'], version)[0] == execute(after['output'], version)[0] == expected
            if backend == 'classic':
                assert after['emission']['skeleton_shared_helpers'] == ['_acount', '_aget', '_carry']
                assert after['runtime_bytes'] < before['runtime_bytes']
            else:
                assert before['runtime'] == after['runtime']
            print('runtime-skeleton-backend-ok', version, backend, flush=True)
    print('runtime-skeleton-regression-ok captures, escapes, masks, mutations, VM independence and results')


if __name__=='__main__':main()
