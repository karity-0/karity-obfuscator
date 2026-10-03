"""Lua 5.1 generated API, control-field and executor capture boundaries."""
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
    from lupa.lua51 import LuaRuntime
    lua = LuaRuntime(encoding=None)
    decoder = Lua51Target().numeric_blob_decoder('')
    assert '_target51' not in decoder and 'table.unpack' not in decoder
    decode = lua.execute(('return function(blob) return ' + decoder + ' end').encode())
    rng = random.Random(5812)
    for length in (*range(17), 4095, 4096, 4097, 16385):
        data = bytes(rng.randrange(256) for _ in range(length))
        words = {0: length}
        for offset in range(0, length, 4):
            words[offset // 4 + 1] = int.from_bytes(data[offset:offset + 4].ljust(4, b'\0'), 'little')
        assert decode(lua.table_from(words)) == data, length

    source = (ROOT / 'test/fixtures/lua51_runtime_boundaries.lua').read_text(encoding='utf-8')
    original = Lua51Target.lower_source
    profiles = (
        ('lean', {'fake_handlers': False, 'mutate_handlers': False, 'junk_instructions': False}),
        ('default', {}),
        ('lean-string', {'fake_handlers': False, 'mutate_handlers': False,
                         'junk_instructions': False, 'blob_form': 'string'}),
    )
    # Keep the original audited spelling: source/debug changes can alter the
    # emitted protection plan, so test the original reproducer as well.
    reproducer = '''local function f(a,...)
local t={...};local s=a
for i=1,#t do s=s+t[i] end
return s,function(x) return s+x end
end
local a,g=f(1,2,3);assert(a==6 and g(4)==10)
'''
    for name, options in profiles:
        for backend in ('classic', 'karity', 'mov'):
            captured = []
            def capture(self, runtime):
                lowered = original(self, runtime)
                assert not re.search(r'\b(?:math\.type|table\.(?:unpack|pack))\s*\(', lowered)
                captured.append(lowered)
                return lowered
            random.seed(5812)
            with patch.object(Lua51Target, 'lower_source', capture):
                output = VMPass(target=TargetProfile('5.1', backend), vm_options=options).run(reproducer)
            assert len(captured) == 1
            runtime = LuaRuntime(encoding=None)
            runtime.execute(output.encode())
            print('lua51-runtime-ok', name, backend, flush=True)
    random.seed(5813)
    output = VMPass(target=TargetProfile('5.1', 'karity'), vm_options={
        'blob_form': 'numeric'}).run(source)
    LuaRuntime(encoding=None).execute(output.encode())
    random.seed(5814)
    closed_upvalues = '''local function make(v)
        local x=v
        return function() return x end, function(y) x=y end,
               function() return function() return x end end
    end
    local identity={}
    for _,initial in ipairs({false,true,3.25,'value',identity}) do
        local get,set,nested=make(initial)
        local other=nested()
        assert(get()==initial and other()==initial,'initial '..type(initial))
        set(nil);assert(get()==nil and other()==nil,'nil')
        set(false);assert(get()==false and other()==false,'false')
        set(identity);assert(get()==identity and other()==identity,'table')
        set(-7.5);assert(get()==-7.5 and other()==-7.5,'number')
    end
    local function pack(...) return {n=select('#',...),...} end
    local function echo(...) return ... end
    local function tail(...) return echo(...) end
    local function none() end
    local result=pack(tail(false,nil,3,nil))
    assert(result.n==4 and result[1]==false and result[2]==nil and result[3]==3 and result[4]==nil)
    assert(pack(tail()).n==0 and pack(none()).n==0)
    local a,b,c,d=echo(false,nil,3)
    assert(a==false and b==nil and c==3 and d==nil)'''
    for backend in ('classic','karity','mov'):
        random.seed(5814)
        output=VMPass(target=TargetProfile('5.1',backend),vm_options={
            'vm_count':3,'upvalue_virtualization':True,
            'semantic_state_threading':True}).run(closed_upvalues)
        LuaRuntime(encoding=None).execute(output.encode())
    table_source = '''local key={}
    local t={[false]=false,[key]='object',-123456,3.25}
    t.self=t
    assert(t[false]==false and t[key]=='object' and t[1]==-123456 and t[2]==3.25)
    assert(t.self==t and #t==2)
    t[key]=nil;assert(t[key]==nil)
    t[key]='again';t[1]=987654
    assert(t[key]=='again' and t[1]==987654)
    assert(rawget(t,'self')==t)
    assert(rawget(t,false)==false and rawget(t,key)=='again')
    local n=0;for k,v in pairs(t) do n=n+1 end;assert(n==5)
    t[false]=nil;t[2]=nil;assert(t[false]==nil and #t==1)
    assert(t.self.self==t and t[key]=='again')'''
    from run_vm_output_emitter_regression import run_source
    for version in ('5.1','5.3'):
        if version=='5.1':
            LuaRuntime(encoding=None).execute(table_source.encode())
        else:
            assert run_source(table_source)==(0,b'',b'')
        random.seed(5815)
        output=VMPass(target=TargetProfile(version,'karity'),vm_options={
            'vm_count':2,'table_virtualization':True,
            'runtime_trace':version=='5.1',
            'semantic_state_threading':True}).run(table_source)
        if version=='5.1':
            traced=LuaRuntime(encoding=None)
            traced.execute(b'''_captured_trace={}
                io.stderr={write=function(self,...)
                    for i=1,select('#',...) do
                        _captured_trace[#_captured_trace+1]=tostring(select(i,...))
                    end
                end}''')
            traced.execute(output.encode())
            trace=traced.eval(b"table.concat(_captured_trace)")
            assert re.fullmatch(rb'karity-vm-trace:[0-9a-f]{16} blocks:\d+ blocktrace:[0-9a-f]{16}\n',trace),trace
        else:
            result=run_source(output)
            assert result==(0,b'',b''),result
    print('lua51-runtime-regression-ok builds=15 numeric-lengths=21 closed-upvalues=5 closure-backends=3 table-targets=2')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
