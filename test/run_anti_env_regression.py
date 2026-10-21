"""Anti Env coverage, false positives, placement and pipeline composition."""
from pathlib import Path
import random
import re
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'test')]
from lupa.lua51 import LuaRuntime as Lua51,LuaError as Error51
from lupa.lua53 import LuaRuntime as Lua53,LuaError as Error53
from obfuscator import Pipeline,build_pipeline_from_config
from obfuscator.passes.anti_env import AntiEnvPass,_CORE,_EXTRA,_SIGNALS
from obfuscator.registry import ConfigError,PASS_REGISTRY,get_pass_contexts,validate_config
from run_cross_backend_generated_regression import execute
from run_vm_backend_regression import options


def setup_for(signals):
    declarations=[]
    owners=set()
    for name in signals:
        path,kind=_SIGNALS[name]
        if len(path)>1 and path[0] not in owners:
            declarations.append(path[0]+'={}')
            owners.add(path[0])
        declarations.append('.'.join(path)+('={}' if kind=='object' else
            '=function() api_calls=api_calls+1;return nil end'))
    return ';'.join(declarations)


def invoke(runtime_type,source,setup='',blocked=False,proxy=False):
    runtime=runtime_type(unpack_returned_tuples=True)
    runtime.execute('ran=false;api_calls=0;'+setup)
    # Compilation is outside the rejection assertion: a syntax error is no
    # evidence that a coherent environment was detected.
    fn=runtime.compile(source)
    if proxy:
        fn=runtime.eval('''function(f,source,mode)
 local index=_G;if mode=='function' then index=function(_,k)return _G[k]end end
 local e=setmetatable({},{__index=index})
 if _VERSION=='Lua 5.1' then setfenv(f,e);return f end
 return assert(load(source,'=anti-env','t',e))
end''')(fn,source,proxy)
    if blocked:
        try:fn()
        except (Error51,Error53):
            pass
        else:raise AssertionError('matching environment was accepted')
        assert runtime.globals().ran is False
        result=None
    else:
        result=fn()
        assert result==17,result
        assert runtime.globals().ran is True
    assert runtime.globals().api_calls==0,'a discovered host API was invoked'
    return result


def main():
    source='local function work() ran=true;return 17 end;return work()'
    artifacts=set()
    for seed in range(12):
        random.seed(seed)
        guard=AntiEnvPass()
        output=guard.run(source)
        artifacts.add(output)
        assert set(_CORE)<=set(guard.last_selected_profiles)
        assert 2<=guard.last_guard_count<=4
        assert 'error(' not in output
        for runtime in (Lua51,Lua53):
            invoke(runtime,output)
            for profile in guard.last_selected_profiles:
                members=(_CORE|_EXTRA)[profile][0]
                for proxy in (False,True,'function'):
                    invoke(runtime,output,setup_for(members),True,proxy)
            # No single named signal may independently deny execution.
            for signal in _SIGNALS:
                invoke(runtime,output,setup_for([signal]))
            invoke(runtime,output,setup_for(['game','workspace']))
            invoke(runtime,output,setup_for(['getgc','getgenv']))
            invoke(runtime,output,setup_for(['readfile','writefile','isfile']))
            invoke(runtime,output,'game=false;workspace=7;typeof="present";getgc=true;getgenv={};hookfunction=1')
            # A removed entry guard still encounters the snapshot guard in work.
            removed=re.sub(r'\nif \w+ then [^\n]+\n','\n',output,count=1)
            assert removed!=output
            invoke(runtime,removed,setup_for(['game','workspace','typeof']),True)
            # Guest-created names do not retroactively change the initial verdict.
            changed=AntiEnvPass().run('game={};workspace={};typeof=function()end;'+source)
            invoke(runtime,changed)
        assert len(artifacts)==seed+1
    for runtime in (Lua51,Lua53):
        invoke(runtime,AntiEnvPass().run('ran=true;return 17'))
        invoke(runtime,AntiEnvPass().run('local function empty()end;ran=true;return 17'))
        # Protected fallback handles inherited lookups that throw.
        invoke(runtime,AntiEnvPass().run(source),
            'setmetatable(_G,{__index=function() error("missing") end})')
    assert PASS_REGISTRY['anti_env']['group']=='pre'
    assert PASS_REGISTRY['anti_env']['label']=='Anti Env'
    assert get_pass_contexts('anti_env')==['passes']
    from obfuscator_gui import _pass_meta
    meta=next(p for p in _pass_meta() if p['name']=='anti_env')
    assert meta['group']=='pre' and meta['contexts']==['passes']
    pipeline=build_pipeline_from_config({'passes':['anti_env'],'signature':{'mode':'none'}},Pipeline)
    native='--@NO_OBF_START\nlocal untouched=17\n--@NO_OBF_END\nreturn untouched'
    pipeline.run(native)
    assert any(row['feature']=='anti_env' and row['status']=='skipped' for row in pipeline.last_selection_report)
    for key in ('vm_output_passes','packer_output_passes'):
        try:validate_config({key:['anti_env']})
        except ConfigError:pass
        else:raise AssertionError('source pre-pass accepted as an output transform')
    for version in ('5.1','5.3'):
        config={'passes':['anti_env','strip_info','rename_obf','minify'],
            'target':{'lua_version':version},'signature':{'mode':'none'}}
        pipeline=build_pipeline_from_config(config,Pipeline)
        output=pipeline.run('local function f(...)return ... end;print(f(1,nil,false,nil))')
        assert execute(version,output)==execute(version,'print(1,nil,false,nil)')
        for backend in ('bare','classic','karity','mov'):
            from run_source_protection_regression import run
            pipeline=build_pipeline_from_config({**config,'passes':['anti_env','vm'],
                'vm_options':options(backend),'vm_output_passes':['strip_info','rename_obf','minify']},Pipeline)
            output=pipeline.run('return 17')
            assert run(version,output)==17
            try:run(version,output,b'game={};workspace={};typeof=function()end')
            except (Error51,RuntimeError):pass
            else:raise AssertionError(('VM accepted denied host',version,backend))
    print('anti-env-regression-ok both targets, profiles, isolated signals, proxies, snapshots, placement, four backends')


if __name__=='__main__':main()
