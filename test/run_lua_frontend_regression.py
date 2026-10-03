"""Version frontend and exact target arithmetic regression."""
from pathlib import Path
import random
import math
import struct
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
                      ' end)(); local N=(function() '+(ROOT/'obfuscator/vm/targets/dump51.lua').read_text()+' end)(); return (function() '+(ROOT/'obfuscator/vm/targets/lua51_shim.lua').read_text()+' end)()').encode())
    roundtrip=lua.eval(b'function(t,s) local v=t.string.unpack("<d",s);return t.string.pack("<d",v) end')
    floats=[0.,-0.,math.inf,-math.inf,2.**-1074,2.**-1022,1.,-1.]
    floats += [struct.unpack('<d',rng.getrandbits(64).to_bytes(8,'little'))[0] for _ in range(200)]
    for value in floats:
        if math.isnan(value): continue
        expected=struct.pack('<d',value)
        assert shim[b'string'][b'pack'](b'<d',value)==expected
        assert roundtrip(shim,expected)==expected
    for a in (-(1<<63),(1<<63)-1,(1<<53)+1):
        x=shim[b'integer'](str(a).encode())
        for b in (-math.inf,math.inf,math.nan,float(a),0.,-0.,1.5):
            assert bool(shim[b'lt'](x,b))==(a<b)
            assert bool(shim[b'eq'](x,b))==(a==b)
    from obfuscator.vm.targets.lua51_syntax import translate
    source="local x={}; for i=1,3 do x[i]=i*0x7fffffffffffffff end; return tostring(x[3]),math.type(x[1])"
    translated=translate(source)
    factory=lua.eval(('function(_target51) local math,tostring=_target51.math,_target51.tostring; '+translated+' end').encode())
    assert factory(shim)==(b'9223372036854775805',b'integer')
    # The generated graph subset must preserve branch edges, lexical locals,
    # return arity and tail recursion on the older target.
    graph = ("return function(x) goto a;::a::do local y=x-1;x=y;"
             "if x>0 then goto a end;goto b end;::b::do return x,nil,7 end;end")
    graph_factory=lua.eval(('function(_target51) '+translate(graph)+' end').encode())
    result=graph_factory(shim)(10000)
    assert shim[b'number'](result[0])==0 and result[1] is None and shim[b'number'](result[2])==7
    for invalid in ('goto nowhere', 'return function() ::a::do return end end'):
        try:
            translate(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError('unsupported graph scope was accepted')
    original_info=lua.eval(b'function(t) return t.debug.getinfo(t.string.byte,"S").what end')
    assert original_info(shim)==b'C'
    # An unrelated replacement must still fail the native-function check.
    replaced_info=lua.eval(b'function(t) return t.debug.getinfo(function() end,"S").what end')
    assert replaced_info(shim)==b'Lua'
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
        assert execute_capture(smoke.run(source))==expected,backend
    print('lua51-target-smoke expected failure',flush=True)
    random.seed(123)
    try:
        lua.execute(adapter.run('local fail=nil;fail()').encode())
    except Exception as error:
        assert 'call' in str(error) and 'nil' in str(error),str(error)
    else:
        raise AssertionError('target VM failed to execute source call')
    print('lua-frontend-regression-ok Lua51 golden, native int64 arithmetic pairs=504')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
