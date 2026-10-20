"""Protected-string storage, semantic boundaries and host-integrity regressions."""
from pathlib import Path
import random
import subprocess
import tempfile
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'test')]
from lupa.lua51 import LuaRuntime as Lua51
from lupa.lua53 import LuaRuntime as Lua53
from obfuscator.vm.string_storage import encode,decode,rebind


def kernel(version,script=123,line=456):
    path=ROOT/('obfuscator/vm/vm.lua' if version=='5.3' else 'obfuscator/vm/runtimes/lua51/vm.lua')
    source=path.read_text(encoding='utf8')
    xor=source.split('--<<TARGET_INSTRUCTION_XOR>>')[1].split('--<<ENDTARGET_INSTRUCTION_XOR>>')[0]
    body=(ROOT/'obfuscator/vm/runtimes/protected_strings.lua').read_text(encoding='utf8')
    body=body.replace('__PS_UNPACK__','unpack' if version=='5.1' else 'table.unpack').replace('__PS_BINDINGS__','{}')
    runtime=(Lua51 if version=='5.1' else Lua53)(encoding=None)
    ps=runtime.execute((f'local _IT={{script={script},line={line},seed=7}}; local function _kss(v) return v end; local _PS,_PS_GUARD;'+xor+body+';return _PS').encode())
    return runtime,ps


class RuntimeSecurity(unittest.TestCase):
    def test_vm_and_packer_entry_without_public_tail(self):
        from obfuscator.vm import VMPass
        from obfuscator.vm.targets.profile import TargetProfile
        from obfuscator.passes.packer import PackerPass,_VM_TAIL_RE,_alloc_plan
        from run_blob_form_regression import execute
        source="assert(select('#',...)==4);local a,b,c,d=...;assert(a==nil and b==false and c==3 and d==nil);print('forwarded-ok')"
        for version in ('5.1','5.3'):
            random.seed(61293)
            output=VMPass(target=TargetProfile(version,'karity'),vm_options={
                'backend':'karity','vm_count':1,'opcode_synthesis':False,
                'fake_handlers':False,'mutate_handlers':False,'junk_instructions':False,
                'graph_execution_rate':0.0,'block_variant_rate':0.0,
            },vm_output_passes=['strip_info','rename_obf','minify']).run(source)
            match=_VM_TAIL_RE.search(output)
            self.assertIsNotNone(match)
            self.assertIsNone(match.group('tail'))
            self.assertTrue(match.group('forward_args'))
            for token in ('karityObfuscator/','runtime integrity mismatch','line_state','function_dump','_runctx'):
                self.assertNotIn(token,output)
            harness="local source=[====["+output+"]====];local f=assert((loadstring or load)(source));f(nil,false,3,nil)"
            expected=[b'forwarded-ok'] if version=='5.1' else b'forwarded-ok\r\n'
            self.assertEqual(expected,execute(version,harness))
        # Both current and legacy wrappers retain packer routing and varargs.
        for legacy in (False,True):
            for forwarded in (False,True):
                tail=',"abcdefghijklmnop"' if legacy else ''
                packet=",{n=select('#',...),...}" if forwarded else ''
                parameters='blob,tail,self,packet' if legacy else 'blob,self,packet'
                output=("local f;f=function(a,b,c)return function("+parameters+")"
                        "return a+b+c,blob,type(self),packet and packet.n or 0 end end;"
                        "return (f(1,2,3))(\"BLOB\""+tail+",f"+packet+")")
                plan=_alloc_plan(output)
                self.assertTrue(plan.is_vm)
                self.assertEqual('abcdefghijklmnop' if legacy else None,plan.vm_tail)
                packed=PackerPass(packer_output_passes=['minify']).run(output)
                harness=("local source=[====["+packed+"]====];local f=assert(load(source));"
                         "local n,blob,kind,count=f(nil,false,3,nil);"
                         "assert(n==6 and blob=='BLOB' and kind=='function' and count=="+str(4 if forwarded else 0)+");print('packed-shape-ok')")
                self.assertEqual(b'packed-shape-ok\r\n',execute('5.3',harness))

    def test_native_member_coverage_and_shadowing(self):
        from obfuscator.vm.runtime_security import _capture_source,_freeze_calls,_CORE_MEMBERS,_CORE_GLOBALS
        from obfuscator.vm.vm_variants import _TAMPER_C_POOL,_TAMPER_ALWAYS
        covered=set(_CORE_GLOBALS)|{owner+'.'+name for owner,keys in _CORE_MEMBERS.items() for name in keys}
        self.assertTrue(set(_TAMPER_C_POOL+_TAMPER_ALWAYS)<=covered)
        for version,runtime_type in (('5.1',Lua51),('5.3',Lua53)):
            capture=_capture_source(native_unpack='unpack' if version=='5.1' else 'table.unpack',native_table_pack=version!='5.1')
            body='''local function shadow(math,string)
 return math.abs(-3),string.rep('x',2)
end
return function()
 local a,b=shadow({abs=function() return 'shadow-abs' end},{rep=function() return 'shadow-rep' end})
 return math.abs(-3),string.rep('ab',2),type(os.clock())=='number',a,b __EXTRA
end'''.replace('__EXTRA',",math.type(3),math.type(3.0)" if version=='5.3' else '')
            frozen=_freeze_calls(capture+body)
            runtime=runtime_type(unpack_returned_tuples=True)
            read=runtime.execute(frozen)
            expected=(3,'abab',True,'shadow-abs','shadow-rep')+(('integer','float') if version=='5.3' else ())
            self.assertEqual(expected,read())
            runtime.execute("math.abs=function() return 99 end;string.rep=function() return 'rebound' end;math.type=function() return 'rebound' end")
            self.assertEqual(expected,read())

    def test_internal_schema_names_preserve_diagnostics(self):
        from obfuscator.vm.backends.runtime_emitter import _rename_vm_keys,_VM_SCHEMA_RENAME_KEYS
        from obfuscator.passes.ts_utils import parse
        source='''local r={get=1,set=2,refs={},environment={}}
function r.uint() return 3 end
function r.header() return r.uint() end
function r.metadata() error('bad metadata mode') end
function r.iword() return r.header() end
return r.iword(),"iword metadata header",r'''
        output=_rename_vm_keys(source)
        self.assertIn("'bad metadata mode'",output)
        self.assertIn('"iword metadata header"',output)
        ctx=parse(output)
        for node in ctx.walk():
            key=node.child_by_field_name('field') if node.type=='dot_index_expression' else node.child_by_field_name('name') if node.type=='field' else None
            if key is not None:self.assertNotIn(ctx.plain_text(key),_VM_SCHEMA_RENAME_KEYS)
        for runtime_type in (Lua51,Lua53):
            self.assertEqual(3,runtime_type(unpack_returned_tuples=True).execute(output)[0])

    def test_private_value_and_api_slots(self):
        from obfuscator.vm.runtime_security import _capture_source, _freeze_calls
        runtime_body=(ROOT/'obfuscator/vm/runtimes/protected_strings.lua').read_text(encoding='utf8')
        body='''
local function exercise()
 local S={length=function() return 'shadow-length' end}
 local A={max=function() return 'shadow-max' end}
 local _PS={native=function() return 'shadow-native' end}
 return S.length(),A.max(),_PS.native(),"_PS.guard"
end
local function roundtrip()
 local value=_PS.seal('abc');local box={}
 value=_PS.cell_set(box,value)
 return _PS.open(_PS.cell_get(box,value)),_PS.length(value),_PS.api.max(3,9)
end
local function tamper(which)
 if which==1 then _PS.api.byte=function() end
 elseif which==2 then _PS.api={}
 else _PS.guard=function() end end
end
return _PS,_PS.api,_PS.guard,exercise,roundtrip,tamper
'''
        for version,runtime_type in (('5.1',Lua51),('5.3',Lua53)):
            template=ROOT/('obfuscator/vm/vm.lua' if version=='5.3' else 'obfuscator/vm/runtimes/lua51/vm.lua')
            xor=template.read_text(encoding='utf8').split('--<<TARGET_INSTRUCTION_XOR>>')[1].split('--<<ENDTARGET_INSTRUCTION_XOR>>')[0]
            helpers=runtime_body.replace('__PS_UNPACK__','unpack' if version=='5.1' else 'table.unpack')
            helpers=helpers.replace('__PS_BINDINGS__','{}')
            source=_capture_source(native_unpack='unpack' if version=='5.1' else 'table.unpack',native_table_pack=version!='5.1')
            source+='local _PS,_PS_GUARD;local _IT={script=123,line=456,seed=7};'+xor+helpers+body
            frozen=_freeze_calls(source)
            self.assertNotIn('SECURITY_VALUES',frozen)
            for which in (1,2,3):
                runtime=runtime_type(unpack_returned_tuples=True)
                values,api,guard,exercise,roundtrip,tamper=runtime.execute(frozen)
                for bank in (values,api):
                    self.assertTrue(all(isinstance(key,(int,float)) for key in bank.keys()))
                self.assertEqual(('shadow-length','shadow-max','shadow-native','_PS.guard'),exercise())
                self.assertEqual(('abc',3,9),roundtrip())
                self.assertIsNone(guard(True))
                tamper(which)
                self.assertEqual((False,None),runtime.eval('function(f) return pcall(f,true) end')(guard))

    def test_native_capture_slots_and_integrity(self):
        from obfuscator.vm.runtime_security import _capture_source, _freeze_calls
        runtime_body=(ROOT/'obfuscator/vm/runtimes/protected_strings.lua').read_text(encoding='utf8')
        body='''
local function shadow()
 local _PS_CORE={type=function() return 'shadow' end}
 return _PS_CORE.type()
end
local function read() return type(7),string.byte('A'),shadow(),"_PS_CORE.string_byte" end
return _PS_CORE,_PS.guard,read
'''
        previous=random.getstate()
        try:
            for version,runtime_type in (('5.1',Lua51),('5.3',Lua53)):
                capture=_capture_source(native_unpack='unpack' if version=='5.1' else 'table.unpack',
                                        native_table_pack=version!='5.1')
                helpers=runtime_body.replace('__PS_UNPACK__','unpack' if version=='5.1' else 'table.unpack')
                helpers=helpers.replace('__PS_BINDINGS__','{}')
                source=capture+'local _PS,_PS_GUARD\n'+helpers+body
                random.seed(91427);frozen=_freeze_calls(source)
                random.seed(91427);self.assertEqual(frozen,_freeze_calls(source))
                random.seed(91428);self.assertNotEqual(frozen,_freeze_calls(source))
                runtime=runtime_type(unpack_returned_tuples=True)
                bank,guard,read=runtime.execute(frozen)
                self.assertTrue(all(isinstance(key,(int,float)) and int(key)==key for key in bank.keys()))
                self.assertGreater(len(list(bank.keys())),25)
                self.assertEqual(('number',65,'shadow','_PS_CORE.string_byte'),read())
                self.assertIsNone(guard(True))
                # Rebinding a global leaves the captured function reference intact.
                runtime.globals().type=runtime.eval("function() return 'rebound' end")
                self.assertEqual(('number',65,'shadow','_PS_CORE.string_byte'),read())
                self.assertIsNone(guard(True))
                # Every numeric capture remains covered by the integrity snapshot.
                tamper=runtime.eval('''function(bank,guard)
 for key in pairs(bank) do bank[key]=function() end;break end
 return pcall(guard,true)
end''')
                self.assertEqual((False,None),tamper(bank,guard))
        finally:
            random.setstate(previous)

    def test_environment_policies_and_late_hooks(self):
        from obfuscator.vm.environment import bind_environment
        template='return function(...) return _ENV_GUEST.answer,_ENV_NATIVE,_ENV_CHECK,_ENV_REFRESH end'
        for version,runtime_type in (('5.1',Lua51),('5.3',Lua53)):
            for policy in ('compatible','strict'):
                with self.subTest(version=version,policy=policy):
                    r=runtime_type(unpack_returned_tuples=True)
                    source,_=bind_environment(template,lua_version=version,policy=policy,compact=True)
                    proxy=r.execute('''local base=_G;local log={}
local proxy=setmetatable({answer=42},{__index=function(t,k) log[#log+1]=k;return base[k] end})
return proxy''')
                    load=r.eval('''function(source,env)
 if _VERSION=='Lua 5.1' then local c=assert(loadstring(source));setfenv(c,env);return c() end
 return assert(load(source,'=environment-test','t',env))()
end''')
                    factory=load(source,proxy)
                    invoke=r.eval('function(f) return pcall(f) end')
                    if policy=='strict':
                        self.assertEqual((False,None),invoke(factory))
                        continue
                    answer,native,check,refresh=factory()
                    self.assertEqual(42,answer)
                    self.assertTrue(r.eval('function(native) return native==_G end')(native))
                    r.eval('function(e) debug.getmetatable(e).__index=function() return nil end end')(proxy)
                    self.assertEqual((False,None),invoke(check))
                    # Failure remains latched even after restoring the table.
                    self.assertEqual((False,None),invoke(check))
            # Authorized changes refresh only the changed environment/object.
            r=runtime_type(unpack_returned_tuples=True)
            source,_=bind_environment(template,lua_version=version,policy='strict',compact=False)
            answer,native,check,refresh=r.execute(source)()
            r.eval('function(e,refresh) refresh(e,false);setmetatable(e,{});refresh(e,true) end')(native,refresh)
            self.assertIsNone(check())
            r.eval('function(e) debug.getmetatable(e).__newindex=function() end end')(native)
            self.assertEqual((False,None),r.eval('function(f) return pcall(f) end')(check))

    def test_internal_diagnostics_are_opaque_but_still_throw(self):
        from obfuscator.vm.runtime_security import _capture_source, _freeze_calls
        body = '''
local function invalid(code) error("unknown op "..tostring(code)) end
local function format() error("unsupported handler blob format") end
local function canonical() error("noncanonical blob uint32") end
local function invariant(ok) assert(ok,'bad MOV version');return 17 end
local function semantic() error("'for' step must be a number",0) end
local function shadow()
 local error=function(message) return message end
 return error("invalid blob")
end
return invalid,format,canonical,semantic,shadow,"error(\\"bad metadata mode\\")",invariant
'''
        for version, runtime_type in (('5.1', Lua51), ('5.3', Lua53)):
            source = _capture_source(native_unpack='unpack' if version=='5.1' else 'table.unpack',
                                     native_table_pack=version!='5.1') + body
            frozen = _freeze_calls(source)
            runtime = runtime_type(encoding=None, unpack_returned_tuples=True)
            invalid, format_error, canonical, semantic, shadow, literal, invariant = runtime.execute(frozen.encode())
            invoke = runtime.eval(b'function(f) return pcall(f,999) end')
            for function in (invalid, format_error, canonical):
                self.assertEqual((False, None), invoke(function))
            self.assertEqual((False, b"'for' step must be a number"), invoke(semantic))
            self.assertEqual(b'invalid blob', shadow())
            self.assertEqual(b'error("bad metadata mode")', literal)
            self.assertNotIn('unknown op ', frozen)
            self.assertNotIn('unsupported handler blob format', frozen)
            self.assertNotIn('noncanonical blob uint32', frozen)
            self.assertNotIn('bad MOV version', frozen)
            self.assertEqual((False,None),runtime.eval(b'function(f) return pcall(f,false) end')(invariant))
            self.assertEqual(17,invariant(True))

    def test_constant_envelopes_bind_runtime_identity(self):
        for data in (b'',b'\0\xff',('secret\0中文😀'*12).encode()):
            value=encode(data,123,456,seed=111)
            self.assertEqual(data,decode(value,123,456))
            with self.assertRaises(ValueError):decode(value,124,456)
            changed=rebind(value,123,456,987,654)
            self.assertEqual(len(value),len(changed))
            self.assertEqual(data,decode(changed,987,654))
            for version in ('5.1','5.3'):
                runtime,ps=kernel(version)
                obj=ps[b'constant'](runtime.table_from({2:value}))
                self.assertEqual(data,ps[b'open'](obj))
                self.assertTrue(ps[b'equal'](obj,data))
                self.assertEqual(len(data),ps[b'length'](obj))

    def test_equality_matches_native_bytes_for_prefix_and_suffix_changes(self):
        rng=random.Random(9237)
        for version in ('5.1','5.3'):
            runtime,ps=kernel(version)
            for size in (0,1,2,31,128):
                data=bytes(rng.randrange(256) for _ in range(size))
                value=ps[b'seal'](data)
                self.assertTrue(ps[b'equal'](value,data))
                if size:
                    for index in (0,size-1):
                        changed=bytearray(data);changed[index]^=1
                        self.assertFalse(ps[b'equal'](value,bytes(changed)))

    def test_ciphertext_and_cell_substitution_are_detected(self):
        for version in ('5.1','5.3'):
            runtime,ps=kernel(version)
            self.assertTrue(runtime.eval('''function(S)
                local p=S.seal('private-value');local box={}
                p=S.cell_set(box,p);assert(S.cell_get(box,p)==p)
                local ok=pcall(S.cell_get,box,'replacement');assert(not ok)
                assert(not pcall(S.guard,true));return true
            end''')(ps))
            runtime,ps=kernel(version)
            self.assertTrue(runtime.eval('''function(S)
                local p=S.seal('private-value');local found
                for i=1,20 do local n,v=debug.getupvalue(S.is,i);if not n then break end
                    if type(v)=='table' and v[p] then found=v[p];break end end
                assert(found);found[2][1]=(found[2][1]+1)%256
                assert(not pcall(S.open,p));return true
            end''')(ps))

    def test_constant_cache_substitution_is_detected(self):
        for version in ('5.1','5.3'):
            runtime,ps=kernel(version)
            constant=runtime.table_from({2:encode(b'private-value',123,456,seed=17)})
            ps[b'constant'](constant)
            constant[3]=ps[b'seal'](b'replacement')
            with self.assertRaises(Exception):ps[b'constant'](constant)
            runtime,ps=kernel(version)
            constant=runtime.table_from({3:b'plaintext-injection'})
            with self.assertRaises(Exception):ps[b'constant'](constant)

    def test_internal_join_substring_and_nil_semantics(self):
        for version in ('5.1','5.3'):
            runtime,ps=kernel(version)
            self.assertTrue(runtime.eval('''function(S)
                local a=S.seal('ab\0');local b=S.seal('中文')
                local c=S.join({a,b},2,S.seal('|'))
                assert(S.equal(c,'ab\0|中文'))
                assert(S.open(c)=='ab\0|中文')
                assert(S.join({a,b},2,false)==nil)
                local ok,s=S.native(string.sub,{c,2,-2},3)
                assert(ok and S.open(s)==string.sub('ab\0|中文',2,-2))
                return true
            end''')(ps))

    def test_guard_detects_captured_alias_and_helper_replacement(self):
        for version in ('5.1','5.3'):
            runtime,ps=kernel(version)
            self.assertTrue(runtime.eval('''function(S)
                local guard=S.guard;local concat=S.api.concat
                S.api.concat=function() return 'tampered' end
                assert(not pcall(guard,true))
                S.api.concat=concat;S.failed=false
                assert(not pcall(guard,true));return true
            end''')(ps))
            runtime,ps=kernel(version)
            self.assertTrue(runtime.eval('''function(S)
                local guard=S.guard;S.guard=function() end
                assert(not pcall(guard,true));return true
            end''')(ps))

    def test_reentry_guard_observes_late_hooks(self):
        for version in ('5.1','5.3'):
            runtime,ps=kernel(version)
            self.assertTrue(runtime.eval('''function(S)
                debug.sethook(function() end,'',100)
                local ok=pcall(S.guard,true);debug.sethook()
                assert(not ok);return true
            end''')(ps))

    def test_vm_string_semantics_on_all_backends_and_targets(self):
        from obfuscator.vm import VMPass
        from obfuscator.vm.targets.profile import TargetProfile
        from run_blob_form_regression import execute
        source='''local secret='runtime-private-923fccba'
        local supplied=KARITY_PROXY_VALUE;if supplied then assert(supplied==42) end
        local for_ok,for_error=pcall(function() for i=1,{} do end end)
        assert(not for_ok and for_error:find("'for' limit must be a number",1,true))
        local function invalid_for(a,b,c) for i=a,b,c do break end end
        local bad={{nil,1,1},{1,nil,1},{1,1,nil},{nil,nil,1},
                   {nil,1,nil},{1,nil,nil},{nil,nil,nil}}
        local fields=_VERSION=='Lua 5.1' and
            {'initial value','limit','step','initial value','initial value','limit','initial value'} or
            {'initial value','limit','step','limit','step','limit','limit'}
        local saved_error=error;error=function() return 'guest-error' end
        for n=1,#bad do
            local args=bad[n];local ok,message=pcall(invalid_for,args[1],args[2],args[3])
            assert(not ok and message:find("'for' "..fields[n]..' must be a number',1,true))
        end
        error=saved_error
        local ok,message=pcall(function() error('noncanonical blob uint32',0) end)
        assert(not ok and message=='noncanonical blob uint32')
        local function check(x) return x==secret end
        assert(check('runtime-private-923fccba') and not check('wrong'))
        local a='ab'..string.char(0,255)..'cd'
        assert(#a==6 and a:sub(2,-2)=='b'..string.char(0,255)..'c')
        assert(table.concat({a,'z'},'|')==a..'|z')
        assert('2'+3==5);local n=0;for i='1','3' do n=n+i end;assert(n==6)
        n=0;for i='1','3','1' do n=n+i end;assert(n==6)
        if math.type then
            local original_type=math.type;math.type=function() return 'guest-type' end
            local t={};t[1]=7;assert(math.type(t[1])=='guest-type')
            n=0;for i='1','3','1' do n=n+i end;assert(n==6)
            math.type=original_type
        end
        local t={};t[a]=a;assert(t[a]==a)
        local f=function() return a,nil,false end
        assert(select('#',f())==3)
        local co=coroutine.create(function() coroutine.yield(a);return a end)
        assert(select(2,coroutine.resume(co))==a)
        assert(select(2,coroutine.resume(co))==a)
        assert(not pcall(function() return table.concat({'a'},false) end))
        local oldtype,oldfloor,oldbyte,oldconcat=type,math.floor,string.byte,table.concat
        type=function() return 'guest-type' end
        math.floor=function() return 31 end
        string.byte=function() return 123 end
        table.concat=function() return 'guest-concat' end
        assert(type(9)=='guest-type' and math.floor(9)==31)
        assert(string.byte('x')==123 and table.concat({})=='guest-concat')
        local changed='still-protected';assert(changed:sub(1,5)=='still')
        type,math.floor,string.byte,table.concat=oldtype,oldfloor,oldbyte,oldconcat
        local env=getfenv and getfenv(1) or _ENV
        local previous=getmetatable(env)
        setmetatable(env,{__index=previous and previous.__index or function() return nil end})
        setmetatable(env,previous)
        print('runtime-security-semantics-ok')
        return function() return KARITY_PROXY_VALUE end'''
        for version in ('5.1','5.3'):
            expected=execute(version,source)
            for backend in ('classic','karity','mov'):
                with self.subTest(version=version,backend=backend):
                    random.seed(15991)
                    vm=VMPass(target=TargetProfile(version,backend),vm_options={
                        'backend':backend,'vm_count':1,'fake_handlers':False,
                        'mutate_handlers':False,'junk_instructions':False,
                        'opcode_synthesis':False,'opcode_splitting':False,'opcode_fusion':False,
                        'graph_execution_rate':0.0,'block_variant_rate':0.0,
                        'upvalue_virtualization':True,'table_virtualization':True,
                    },vm_output_passes=['rename_obf','minify'])
                    output=vm.run(source)
                    for token in ('_ENV_GUEST','_ENV_NATIVE','_ENV_CHECK','_ENV_REFRESH','ENVIRONMENT_READY'):
                        self.assertNotIn(token,output)
                    # The wrapper must bind its VM factory directly, without
                    # the old unused branding/random-string prefix local.
                    self.assertRegex(output,r'\Alocal [A-Za-z_]\w*=function\b')
                    for diagnostic in ('unknown op ', 'noncanonical blob uint32',
                                       'unsupported handler blob format', 'bad const tag ',
                                       'argument packet mismatch ', 'register vault',
                                       'MOV field overflow', 'invalid MOV field',
                                       'bad MOV instruction', 'bad MOV version', 'bad MOV alphabet',
                                       'bad MOV VM assignment', 'bad MOV entry count', 'bad MOV prototype count',
                                       'bad synthesis','runtime integrity mismatch','karityObfuscator/',
                                       "'for' initial value must be a number",
                                       "'for' limit must be a number", "'for' step must be a number"):
                        self.assertNotIn(diagnostic,output)
                    self.assertEqual(expected,execute(version,output))
                    # Exercise the complete target wrapper under a forwarding
                    # environment, including guest writes and a later reentry.
                    separator='===='
                    while ']'+separator+']' in output:separator+='='
                    literal='['+separator+'['+output+']'+separator+']'
                    harness='''local base=_G
local env=setmetatable({},{__index=function(t,k)
 if k=='KARITY_PROXY_VALUE' then return 42 end;return base[k]
end})
local source=__SOURCE
local chunk
if _VERSION=='Lua 5.1' then chunk=assert(loadstring(source));setfenv(chunk,env)
else chunk=assert(load(source,'@protected.lua','t',env)) end
local callback=chunk();assert(callback()==42)
debug.getmetatable(env).__index=function() return nil end
assert(not pcall(callback))
'''.replace('__SOURCE',literal)
                    self.assertEqual(expected,execute(version,harness))


    def test_capture_preserves_local_shadowing_and_early_initializers(self):
        from obfuscator.vm.runtime_security import _freeze_calls,_capture_source
        body="""local early=math.floor(3.9)
        local function shadow(type,string) return type(string.byte) end
        return early,shadow(function(v) return v end,{byte=17}),string.byte('A')"""
        for version,runtime in (('5.1',Lua51()),('5.3',Lua53())):
            frozen=_freeze_calls(_capture_source(native_unpack='unpack' if version=='5.1' else 'table.unpack',
                                                  native_table_pack=version!='5.1')+body)
            self.assertEqual((3,17,65),runtime.execute(frozen))

    def test_output_only_extraction_and_late_hook_regressions(self):
        from obfuscator.vm import VMPass
        from lua_runtime import lua_executable
        secret=b'AUDIT_PRIVATE_7c29af81c464'
        source="""local value='AUDIT_PRIVATE_7c29af81c464'
        local function dormant() return 'AUDIT_DORMANT_913ec05a7b62' end
        return {check=function(x) return x==value end,
                compute=function(a,b) return a*37+b*19,false end,dormant=dormant}"""
        random.seed(15401)
        vm=VMPass(vm_options={'backend':'karity','vm_count':1,
            'opcode_synthesis':False,'fake_handlers':False,'mutate_handlers':False,
            'junk_instructions':False,'graph_execution_rate':0.0,'block_variant_rate':0.0,
            'upvalue_virtualization':True,'table_virtualization':True},
            vm_output_passes=['rename_obf','minify'])
        output=vm.run(source)
        self.assertNotIn(secret,output.encode())
        with tempfile.TemporaryDirectory(prefix='karity-security-') as folder:
            folder=Path(folder);artifact=folder/'protected.lua';artifact.write_text(output,encoding='utf8')
            for mode in ('baseline','concat','native-masked','upvalues','upvalues-rewrite','hook-late'):
                with self.subTest(mode=mode):
                    capture=folder/(mode+'.captures')
                    result=subprocess.run([lua_executable(),str(ROOT/'test/fixtures/vm_security_observer.lua'),str(artifact),mode,str(capture),secret.decode()],capture_output=True,timeout=30)
                    self.assertNotIn(b'AUDIT_CANARY_FOUND',result.stderr)
                    if mode in ('concat','hook-late','upvalues-rewrite'):
                        self.assertNotEqual(0,result.returncode,result.stdout)
                        self.assertNotIn(b'AUDIT_REWRITE',result.stdout)
                    else:
                        self.assertEqual(0,result.returncode,result.stderr)
                        self.assertIn(b'AUDIT_RESULT',result.stdout)
                    self.assertNotIn(secret,capture.read_bytes() if capture.exists() else b'')


if __name__=='__main__':unittest.main()
