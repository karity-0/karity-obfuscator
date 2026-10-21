"""Native-oracle and adversarial checks for protection before Bare lowering."""
from pathlib import Path
import random
import sys
import tempfile
import subprocess

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'test')]
from lupa.lua51 import LuaRuntime as Lua51
from lupa.lua53 import LuaRuntime as Lua53
from obfuscator.vm import VMPass
from obfuscator.vm.targets.profile import TargetProfile
from obfuscator.vm.backends.bare_emitter import literal
from run_vm_backend_regression import options


def build(version,source,passes=()):
    random.seed(7719)
    vm=VMPass(target=TargetProfile(version,'bare'),vm_options={**options('bare'),
        'integrity_constants':True,'integrity_constant_rate':1.0},vm_output_passes=list(passes))
    return vm,vm.run(source)


def run(version,source,setup=b'',call=b'local f=assert((loadstring or load)(source));local value=f();if type(value)=="function" then return value() end;return value'):
    if version=='5.3':
        from lua_runtime import lua_executable
        with tempfile.TemporaryDirectory(prefix='source-security-') as folder:
            path=Path(folder)/'check.lua'
            script=('source='+literal(source)+'\n'+setup.decode()+'\nlocal function observe()\n'+call.decode()+
                '''\nend
local function packet(...)return {n=select('#',...),...}end
local p=packet(observe());for i=1,p.n do io.write(type(p[i]),' ',tostring(p[i]),'\\n')end''')
            path.write_text(script,encoding='utf8')
            result=subprocess.run([lua_executable(),str(path)],capture_output=True,timeout=60)
            if result.returncode:raise RuntimeError(result.stderr.decode(errors='replace'))
            values=[]
            for row in result.stdout.splitlines():
                kind,_,value=row.partition(b' ')
                values.append(value if kind==b'string' else None if kind==b'nil' else
                    value==b'true' if kind==b'boolean' else int(value) if b'.' not in value else float(value))
            return values[0] if len(values)==1 else tuple(values)
    runtime=(Lua51 if version=='5.1' else Lua53)(encoding=None,unpack_returned_tuples=True)
    runtime.globals()[b'source']=source.encode()
    if setup:runtime.execute(setup)
    return runtime.execute(call)


def rejected(version,source,setup=b'',call=None):
    try:
        if call is None:run(version,source,setup)
        else:run(version,source,setup,call)
    except Exception:
        return
    raise AssertionError(('modified runtime was accepted',version))


def check_native_capture():
    from obfuscator.vm.native_capture import bind_native_calls
    source='''return function(_BN)
--<<BARE_NATIVE_CAPTURE>>
local function shadow()local math={floor=function()return 91 end};return math.floor()end
return function()return math.floor(3.75),string.byte('A'),shadow()end,__BARE_NATIVE_BINDINGS__
end'''
    frozen,apis=bind_native_calls(source)
    assert set(apis)=={'math.floor','string.byte'}
    for runtime_type in (Lua51,Lua53):
        runtime=runtime_type(encoding=None,unpack_returned_tuples=True)
        factory=runtime.execute(frozen.encode())
        fn,_=factory(runtime.globals())
        assert fn()==(3,65,91)
        runtime.execute(b'math.floor=function()return 99 end')
        assert fn()==(3,65,91)


def main():
    check_native_capture()
    for version in ('5.1','5.3'):
        vm,source=build(version,'return function()return 123,"protected-value" end')
        protection=vm.last_lowered_ir.backend_data['source_protection']
        assert run(version,source)==(123,b'protected-value')
        assert any(f.debug_metadata.get('security_owned') for f in vm.last_semantic_ir.functions())
        assert any(i.metadata.get('protection_origin')=='source_integrity'
                   for f in vm.last_semantic_ir.functions() for b in f.blocks for i in b.instructions)
        phases={p['phase'] for p in vm.last_profile}
        assert {'source_line_state','dump_vm_function'}<=phases
        assert 'serialize_blob' not in phases
        # Same-line executable edit leaves observed line numbers unchanged.
        edited=source.replace('local _BE=','local changed=true;local _BE=',1)
        assert edited!=source
        rejected(version,edited)
        rejected(version,'\n'+source)
        # Changing only the payload cannot be mistaken for self-code hashing.
        payload=protection.payload(literal)
        slot=protection.constants.index(123)
        raw=bytearray(protection.raw_payload())
        offset=(protection.constant_slots[slot]^protection.index_mask)-1
        raw[offset+5]^=1
        bad=literal(protection.printable(raw))
        rejected(version,source.replace(payload,bad,1))
        slot=protection.constants.index(b'protected-value')
        raw=bytearray(protection.raw_payload())
        offset=(protection.constant_slots[slot]^protection.index_mask)-1
        raw[offset+13]^=1
        rejected(version,source.replace(payload,literal(protection.printable(raw)),1))
        assert '\\' not in payload and payload[0]=='"'
        # Constant keys and all private factory/probe keys vary; there is no
        # literal 1..5 probe bank or escaped per-constant record list.
        assert len(set(protection.constant_slots))==len(protection.constants)
        assert all(index>31 for index in protection.constant_slots)
        import re
        assert not re.search(r'\[[1-5]\]=function\(\w+\) return',source)
        # Initial Lua wrappers and hooks are checked before guest execution.
        rejected(version,source,b'string.byte=function()return 0 end')
        rejected(version,source,b'debug.getmetatable=function()return nil end')
        rejected(version,source,b'debug.sethook(function()end,"",100)')
        # Forced post-call checks catch native callbacks modifying the host.
        _,callback=build(version,'hook();return 123')
        rejected(version,callback,b'hook=function()string.byte=function()return 0 end end')
        rejected(version,callback,b'hook=function()debug.setmetatable(_G,{__index=function()end})end')
        # Legitimate writes retain native guest semantics and private decoders.
        _,legitimate=build(version,'''local old=string.byte
string.byte=function()return 17 end
local answer=string.byte('A');string.byte=old
local oldmeta=getmetatable(math);setmetatable(math,{__index=function()return 29 end})
local other=math.missing;setmetatable(math,oldmeta)
return answer+other''')
        assert run(version,legitimate)==46
        # Native tailcalls must stay bounded and permit dead arguments to die.
        _,tails=build(version,'''local function loop(n)if n==0 then return 7 end;return loop(n-1)end
return loop(12000)''')
        assert run(version,tails)==7
        passes=('strip_info','rename_obf','minify')
        _,renamed=build(version,'return function()return -4503599627370495,4503599627370495,"ok" end',passes)
        assert run(version,renamed)==(-4503599627370495,4503599627370495,b'ok')
        minimal,tiny=build(version,'return 17',passes)
        assert len(tiny.encode())<18000,(version,len(tiny.encode()))
        package=minimal.last_lowered_ir.backend_data['source_protection']
        assert not ({'string','write','setmeta'} & package.features)
        assert len([f for f in minimal.last_semantic_ir.functions() if f.debug_metadata.get('security_owned')])<=4
        assert 'local function _Btail' not in tiny
        scaled='local n=INPUT or 0;'+''.join('n=n+'+str(i%17+1)+';' for i in range(256))+'return n'
        _,grown=build(version,scaled,passes)
        assert len(grown.encode())<48000,(version,len(grown.encode()))
        assert run(version,grown)==sum(i%17+1 for i in range(256))
        _,loop=build(version,'local n=0;for i=1,4 do n=n+i end;return n')
        assert run(version,loop)==10
        assert all(name not in loop for name in ('.type','.floor','.ceil','.tointeger','.mininteger','.maxinteger','.table.unpack','_for_api'))
        if version=='5.3':
            from obfuscator import Pipeline,build_pipeline_from_config
            from obfuscator.passes.packer import PackerPass,_alloc_plan
            assert _alloc_plan(source).is_vm
            assert run(version,PackerPass(['minify']).run(source))==(123,b'protected-value')
            # Packing preserves the finalized function's lines and dump while
            # removing its three private loader arguments from guest varargs.
            pipeline=build_pipeline_from_config({'passes':['vm','pack'],
                'vm_options':{**options('bare'),'integrity_constants':True,'integrity_constant_rate':1.0},
                'vm_output_passes':list(passes),'packer_output_passes':['minify'],
                'signature':{'mode':'custom','custom':'source protection\npacked regression'}},Pipeline)
            packed=pipeline.run('return ...')
            assert run(version,packed,call=b'local f=assert(load(source));return f(17,nil,false,nil)')==(17,None,False,None)
            pipeline=build_pipeline_from_config({'passes':['pack'],
                'vm_options':options('bare'),'vm_output_passes':list(passes),
                'packer_output_passes':['minify'],
                'signature':{'mode':'custom','custom':'source protection\nselective packing'}},Pipeline)
            packed=pipeline.run('local n=2\n--@VM_START\nn=n+5\n--@VM_END\nreturn n')
            assert run(version,packed)==7
        print('source-protection-ok',version,'code/line/payload/hooks/host/environment/guest/tailcalls',flush=True)
    print('source-protection-regression-ok')


if __name__=='__main__':main()
