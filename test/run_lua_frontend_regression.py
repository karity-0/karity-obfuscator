"""Version frontend and exact target arithmetic regression."""
from pathlib import Path
import random
import math
import re
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from obfuscator.parser51 import Lua51Parser
from obfuscator.vm.frontends.lua51 import build_semantic_ir


def main():
    data=(ROOT/'test/fixtures/ir/lua51_closure.luac').read_bytes()
    ir=build_semantic_ir(Lua51Parser(data).parse())
    assert ir.dump()==(ROOT/'test/fixtures/ir/lua51_closure.ir').read_text(encoding='utf-8')
    operations={i.operation for f in ir.functions() for b in f.blocks for i in b.instructions}
    assert {'GLOBAL_GET','ITER_CALL','ITER_LOOP','CLOSURE','VARARG'}<=operations
    try:
        from lupa.lua51 import LuaRuntime
    except ImportError:
        print('lua-frontend-regression-ok native Lua 5.1 execution skipped: lupa.lua51 unavailable')
        return 0
    lua=LuaRuntime(encoding=None)
    integers=lua.execute((ROOT/'obfuscator/vm/targets/int64.lua').read_bytes())
    rng=random.Random(1117)
    wrap=lambda x:(x+(1<<63))%(1<<64)-(1<<63)
    parse=lambda x:integers[b'parse'](str(x).encode())
    read=lambda x:int(integers[b'text'](x))
    pairs=[(-(1<<63),-1),((1<<63)-1,1),(-1,-(1<<63)),(0,1)]
    pairs += [(rng.randrange(-(1<<63),1<<63),rng.randrange(-(1<<63),1<<63) or 1) for _ in range(500)]
    for a,b in pairs:
        x,y=parse(a),parse(b)
        for op,expected in ((b'add',wrap(a+b)),(b'sub',wrap(a-b)),(b'mul',wrap(a*b)),
                            (b'band',a&b),(b'bor',a|b),(b'bxor',a^b)):
            assert read(integers[op](x,y))==expected,(op,a,b)
        q,r=integers[b'divmod'](x,y)
        assert (read(q),read(r))==(wrap(a//b),a%b),(a,b)
        assert bool(integers[b'lt'](x,y))==(a<b)
        count=rng.randrange(-80,81)
        expected=wrap((a&((1<<64)-1))<<count) if 0<=count<64 else (a&((1<<64)-1))>>-count if -64<count<0 else 0
        assert read(integers[b'shl'](x,count))==expected
    shim=lua.execute(('local I=(function() '+(ROOT/'obfuscator/vm/targets/int64.lua').read_text()+
                      ' end)(); return (function() '+(ROOT/'obfuscator/vm/targets/lua51_shim.lua').read_text()+' end)()').encode())
    assert all(shim[name] is None for name in
               (b'math',b'string',b'table',b'debug',b'type',b'tostring',b'tonumber',
                b'select',b'error',b'rawget',b'rawset',b'len',b'concat',b'div',b'pow'))
    assert all(shim[name] is None for name in (b'integer_number',b'invoke',b'getfenv'))
    for a in (-(1<<63),(1<<63)-1,(1<<53)+1):
        x=shim[b'integer'](str(a).encode())
        for b in (-math.inf,math.inf,math.nan,float(a),0.,-0.,1.5):
            assert bool(shim[b'lt'](x,b))==(a<b)
            assert bool(shim[b'eq'](x,b))==(a==b)
    from obfuscator.vm.targets.lua51_syntax import translate
    assert '_target51.integer' not in translate('return 17,0xffffffff')
    assert '_target51.integer' in translate('return 0x100000000')
    literal_keys=translate(
        'local t={[17]=1,["native"]=2,[0x100000000]=3};'
        'return t[17],t["native"],t[0x100000000],t[x]'
    )
    assert '_target51.key(17)' not in literal_keys
    assert '_target51.key("native")' not in literal_keys
    assert literal_keys.count('_target51.key(')==3,literal_keys
    native_operators=translate('return #x,a..b,a/b,a^b')
    assert '_target51' not in native_operators
    source="local x={}; for i=1,3 do x[i]=i*0x7fffffffffffffff end; return x[3]"
    translated=translate(source)
    factory=lua.eval(('function(_target51) '+translated+' end').encode())
    result=factory(shim)
    assert (result[b'hi'],result[b'lo'])==(0x7fffffff,0xfffffffd)
    native_state=lua.eval(b'''function(t)
        return t.band(0xf0f0f0f0,0x0ff00ff0),t.bxor(0xf0f0f0f0,0x0ff00ff0),
               t.shr(0x80000000,31),t.bnot(0)
    end''')
    native_state_result=native_state(shim)
    assert native_state_result==(0xf000f0,0xff00ff00,1,0xffffffff),native_state_result
    # The generated graph subset must preserve branch edges, lexical locals,
    # return arity and tail recursion on the older target.
    graph = ("return function(x) goto a;::a::do local y=x-1;x=y;"
             "if x>0 then goto a end;goto b end;::b::do return x,nil,7 end;end")
    graph_factory=lua.eval(('function(_target51) '+translate(graph)+' end').encode())
    result=graph_factory(shim)(10000)
    assert result[0]==0 and result[1] is None and result[2]==7
    # Lua 5.1 arithmetic graph variants must not feed native lua_Number values
    # through the VM's exact-integer/bitwise trace representation. In particular,
    # fractional operands and the sign of zero remain native target semantics.
    from obfuscator.vm.backends.runtime_emitter import (
        _compile_call_route_func, _compile_control_graph_func,
        _compile_integer_graph_func, _compile_loop_ir_func,
        _compile_occurrence_graph_func, _compile_semantic_ir_func,
        _compile_value_graph_func,
    )
    from obfuscator.vm.targets.lua51 import _translate_preserving_native_hooks
    private_helpers='''
local literals={}
local function _pint(text)local value=literals[text];if not value then value=I.parse(text);literals[text]=value end;return value end
local function _padd(a,b)return I.add(a,b)end
local function _psub(a,b)return I.sub(a,b)end
local function _pmul(a,b)return I.mul(a,b)end
local function _pband(a,b)return I.band(a,b)end
local function _pbor(a,b)return I.bor(a,b)end
local function _pxor(a,b)return I.bxor(a,b)end
local function _pshl(a,b)return I.shl(a,b)end
local function _pshr(a,b)return I.shr(a,b)end
local function _pneg(a)return I.neg(I.from(a))end
local function _pnot(a)return I.bnot(a)end
'''
    native_results={}
    for kind,a,b in (('ADD',1.5,2.25),('SUB',1.5,2.75),('MUL',1.5,1.5),('UNM',0.0,0.0)):
        random.seed(700+len(native_results))
        generated=('local f='+_compile_integer_graph_func(kind,preserve_native_numbers=True)+
                   ';return function(a,b)local r=f(a,b,{},nil,nil,{},{});return r,1/r end')
        lowered=_translate_preserving_native_hooks(generated)
        user_regions=re.findall(
            r'--<<TARGET_USER_EXPRESSION>>(.*?)--<<ENDTARGET_USER_EXPRESSION>>',
            lowered,re.S)
        assert user_regions and all('_target51' not in region for region in user_regions)
        private_regions=re.findall(
            r'--<<TARGET_PRIVATE_EXPRESSION>>(.*?)'
            r'--<<ENDTARGET_PRIVATE_EXPRESSION>>',lowered,re.S)
        assert private_regions
        assert all('_target51' not in region and '_p' in region
                   for region in private_regions)
        native_factory=lua.eval(
            ('function(I,_target51) '+private_helpers+lowered+' end').encode()
        )
        native_results[kind]=native_factory(integers,shim)(a,b)
    assert native_results['ADD'][0]==3.75 and native_results['SUB'][0]==-1.25
    assert native_results['MUL'][0]==2.25
    assert native_results['UNM'][0]==0 and native_results['UNM'][1]==-math.inf
    private_cases=0
    for kind in ('BAND','BOR','BXOR','SHL','SHR','BNOT'):
        random.seed(9000+private_cases)
        generated=_compile_integer_graph_func(kind,preserve_native_numbers=True)
        lowered=_translate_preserving_native_hooks(generated)
        private_region=lowered.split('--<<TARGET_PRIVATE_GRAPH>>',1)[1].split(
            '--<<ENDTARGET_PRIVATE_GRAPH>>',1)[0]
        assert '_target51' not in private_region and '_pint' in private_region
        factory=lua.eval(('function(I) '+private_helpers+' local f='+lowered+''' return function(a,b)
            local result=f(I.parse(a),I.parse(b),{},nil,function()end,{}, {})
            return I.text(result)
        end end''').encode())(integers)
        for _ in range(20):
            a=rng.randrange(-(1<<63),1<<63)
            b=rng.randrange(64) if kind in ('SHL','SHR') else rng.randrange(-(1<<63),1<<63)
            actual=int(factory(str(a).encode(),str(b).encode()))
            if kind=='BAND': expected=a&b
            elif kind=='BOR': expected=a|b
            elif kind=='BXOR': expected=a^b
            elif kind=='SHL': expected=wrap(a<<b)
            elif kind=='SHR': expected=wrap((a&((1<<64)-1))>>b)
            else: expected=~a
            assert actual==wrap(expected),(kind,a,b,actual,wrap(expected))
            private_cases+=1
    random.seed(9191)
    value_graph=_translate_preserving_native_hooks(_compile_value_graph_func())
    value_private_regions=re.findall(
        r'--<<TARGET_PRIVATE_EXPRESSION>>(.*?)'
        r'--<<ENDTARGET_PRIVATE_EXPRESSION>>',value_graph,re.S)
    assert value_private_regions
    assert all('_target51' not in region for region in value_private_regions)
    assert any('_p' in region for region in value_private_regions)
    value_factory=lua.eval(('function(I) '+private_helpers+' local f='+value_graph+''' return function(value,tag)
        local result=f(value,{},nil,function()end,{}, {},tag)
        return result,type(result),result==0 and 1/result or nil
    end end''').encode())(integers)
    for value in (1.25,-2.5,b'native-value',True):
        result,value_type,_=value_factory(value,37)
        assert result==value
        assert value_type==(b'number' if isinstance(value,float) else
                            b'string' if isinstance(value,bytes) else b'boolean')
    zero,zero_type,reciprocal=value_factory(-0.0,91)
    assert zero==0 and zero_type==b'number' and reciprocal==-math.inf
    for seed,graph_builder in (
        (9291,_compile_call_route_func),(9391,_compile_control_graph_func),
        (9491,lambda: _compile_occurrence_graph_func(0xA17D)),
        (9591,lambda: _compile_loop_ir_func('FORLOOP')),
        (9691,lambda: _compile_semantic_ir_func('GET')),
    ):
        random.seed(seed)
        private_graph=_translate_preserving_native_hooks(graph_builder())
        graph_private_regions=re.findall(
            r'--<<TARGET_PRIVATE_EXPRESSION>>(.*?)'
            r'--<<ENDTARGET_PRIVATE_EXPRESSION>>',private_graph,re.S)
        assert graph_private_regions
        assert all('_target51' not in region and '_p' in region
                   for region in graph_private_regions)
        private_mod_regions=re.findall(
            r'--<<TARGET_PRIVATE_MOD_EXPRESSION>>(.*?)'
            r'--<<ENDTARGET_PRIVATE_MOD_EXPRESSION>>',private_graph,re.S)
        if private_mod_regions:
            assert all('_target51' not in region and '_pmod' in region
                       for region in private_mod_regions)
        private_low_regions=re.findall(
            r'--<<TARGET_PRIVATE_LOW_EXPRESSION>>(.*?)'
            r'--<<ENDTARGET_PRIVATE_LOW_EXPRESSION>>',private_graph,re.S)
        if private_low_regions:
            assert all('_target51' not in region and '_plow' in region
                       for region in private_low_regions)
        graph_user_regions=re.findall(
            r'--<<TARGET_USER_(?:EXPRESSION|STATEMENT)>>(.*?)'
            r'--<<ENDTARGET_USER_(?:EXPRESSION|STATEMENT)>>',private_graph,re.S)
        assert all('_target51' not in region for region in graph_user_regions)
    for invalid in ('goto nowhere', 'return function() ::a::do return end end'):
        try:
            translate(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError('unsupported graph scope was accepted')
    from obfuscator.vm.targets.profile import TargetProfile
    from obfuscator.vm.vm_pass import VMPass
    from obfuscator.toolchain import LuaToolchain
    for backend in ('classic','karity','mov'):
        assert TargetProfile('5.3',backend).adapter().lua_version=='5.3'
        assert VMPass(target=TargetProfile('5.1',backend)).backend==backend
    try:
        VMPass(target=TargetProfile('5.1','classic'),toolchain=LuaToolchain(luac_executable='explicit-luac')).run('return')
    except FileNotFoundError as error:
        assert 'explicit-luac' in str(error)
    else:
        raise AssertionError('explicit compiler was silently ignored')
    random.seed(123)
    adapter=VMPass(target=TargetProfile('5.1','classic'),vm_options={
        'fake_handlers':False,'mutate_handlers':False,'junk_instructions':False})
    source = """
local x=0;for i=1,4 do x=x+i end;assert(x==10)
print("native-api",math.type,table.pack,table.unpack,string.pack,string.unpack)
x_global=3
print(x_global,type(#"abc"),#"abc",1/(-#""))
local function varargs(...) print(arg.n,arg[1],arg[2],arg[3]) end
varargs(1,nil,3)
local function g()
  return x_global,getfenv().x_global,function() return x_global end
end
setfenv(g,setmetatable({x_global=42},{__index=_G}))
local a,b,h=g();print(a,b,h(),getfenv(h).x_global)
local function change()
  setfenv(1,setmetatable({x_global=71},{__index=_G}))
  print(x_global,getfenv(1).x_global)
end
change()
local function env_inner()
  print("levels",getfenv(1).marker,getfenv(2).marker,getfenv(3).marker)
  setfenv(2,setmetatable({marker="middle-changed"},{__index=_G}))
end
local function env_middle()
  env_inner();print("level-change",marker,getfenv(1).marker)
end
local function env_outer() env_middle() end
setfenv(env_inner,setmetatable({marker="inner"},{__index=_G}))
setfenv(env_middle,setmetatable({marker="middle"},{__index=_G}))
setfenv(env_outer,setmetatable({marker="outer"},{__index=_G}))
env_outer()
local function results() return 1,nil,3 end
print(results())
"""
    def execute_capture(code):
        runtime=LuaRuntime(encoding=None)
        captured=[]
        runtime.globals()[b'print']=lambda *values: captured.append(values)
        runtime.execute(code.encode())
        return captured
    expected=execute_capture(source)
    for backend in ('classic','karity','mov'):
        random.seed(123)
        smoke=VMPass(target=TargetProfile('5.1',backend),vm_options={
            'fake_handlers':False,'mutate_handlers':False,'junk_instructions':False})
        print('lua51-target-smoke',backend,flush=True)
        output=smoke.run(source)
        assert 'assert(loadstring(' not in output[:256],backend
        actual=execute_capture(output)
        assert actual==expected,(backend,expected,actual)
    print('lua51-target-smoke expected failure',flush=True)
    random.seed(123)
    try:
        lua.execute(adapter.run('local fail=nil;fail()').encode())
    except Exception as error:
        assert 'call' in str(error) and 'nil' in str(error),str(error)
    else:
        raise AssertionError('target VM failed to execute source call')
    print(f'lua-frontend-regression-ok Lua51 golden, native int64 arithmetic pairs=504 private-graphs={private_cases}')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
