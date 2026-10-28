"""Native bootstrap metadata/hook protocol, isolated from guest hot paths."""
from pathlib import Path
import random
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from lupa.lua51 import LuaRuntime as Lua51
from lupa.lua53 import LuaRuntime as Lua53
from obfuscator.vm.runtime_probes import bootstrap_source
from obfuscator.vm.host_guards import GUARD_SOURCE, WRITE_BINDINGS


FACADE='''local facades={};local edit_info;local anchor=real_info(pcall,'Sf')
local function facade(fn)facades[fn]=true;return fn end
A.info=facade(function(first,second,third)
 local r
 if type(first)=='number' then r=real_info(first+1,second)else r=real_info(first,second,third)end
 if r and facades[first] then
  r.what='C';r.source=anchor.source;r.short_src=anchor.short_src
  r.linedefined=anchor.linedefined;r.lastlinedefined=anchor.lastlinedefined
 end
 if edit_info then r=edit_info(first,second,third,r)end
 return r
end)
'''


def fixture(setup=''):
    return '''local real_info,real_hook,real_sethook=debug.getinfo,debug.gethook,debug.sethook
local kind,raw,same=type,rawget,rawequal
local failed=false;local function fail()failed=true;error(nil,0)end
local periodic,binding_owners={},{};local A={info=debug.getinfo,hook=debug.gethook,pcall=pcall}
local diagnostic={hits=0}
local native={debug={sethook=debug.sethook},coroutine={create=coroutine.create,
 resume=coroutine.resume,yield=coroutine.yield,status=coroutine.status,running=coroutine.running}}
SETUP
local function probe()
BODY
end
return probe,function()return failed end,native,A,periodic,diagnostic
'''.replace('SETUP',setup).replace('BODY',bootstrap_source('native'))


GUARDED='''local ticks=0;local hook0=real_hook;local S={}
local owner={value=pcall};local trusted={{A,'info',A.info}}
local bindings={{owner,'value',owner.value}}
'''+GUARD_SOURCE+'''
diagnostic.guard=S.guard;diagnostic.owner=owner
diagnostic.write=function(t,k,v)t[k]=v
'''+WRITE_BINDINGS+'''
end
diagnostic.clear_index=function()for k in pairs(binding_owners)do binding_owners[k]=nil end end
'''


class RuntimeProbeTests(unittest.TestCase):
    def reject(self,setup,*,field=False,private_cleanup=True):
        for runtime_type in (Lua51,Lua53):
            lua=runtime_type(unpack_returned_tuples=True)
            spy='''native.coroutine.create=facade(function(f)
local t=coroutine.create(f);diagnostic.thread=t;return t end)
'''
            probe,failed,native,api,records,diagnostic=lua.execute(fixture(FACADE+spy+setup))
            self.assertEqual((False,None),lua.eval('function(f)return pcall(f)end')(probe))
            self.assertTrue(failed())
            if field:self.assertGreater(diagnostic['hits'],0)
            self.assertTrue(lua.eval('function()local h,m,c=debug.gethook();return h==nil and m=="" and c==0 end')())
            if diagnostic['thread'] is not None:
                if private_cleanup:
                    self.assertTrue(lua.eval('function(d)local h,m,c=debug.gethook(d.thread);return h==nil and m=="" and c==0 end')(diagnostic))
                lua.eval('function(d)debug.sethook(d.thread)end')(diagnostic)

    def test_consistent_facade_is_a_negative_control_not_native_authentication(self):
        for runtime_type in (Lua51,Lua53):
            lua=runtime_type(unpack_returned_tuples=True)
            probe,failed,*_=lua.execute(fixture(FACADE))
            self.assertIsNone(probe());self.assertFalse(failed())

    def test_inconsistent_info_options_function_and_thread_queries(self):
        self.reject('''edit_info=function(a,b,c,r)
 if r and not facades[a] and b=='Sf' then r.source=r.source..'changed';diagnostic.hits=diagnostic.hits+1 end
 return r
end''',field=True)
        self.reject('''edit_info=function(a,b,c,r)
 if type(a)=='thread' then diagnostic.hits=diagnostic.hits+1;return nil end
 return r
end''',field=True)
        self.reject('''edit_info=function(a,b,c,r)
 if r and type(a)=='thread' and type(b)=='number' then r.func=pcall;diagnostic.hits=diagnostic.hits+1 end
 return r
end''',field=True)
        self.reject('''edit_info=function(a,b,c,r)
 if r and type(a)=='number' then r.nups=r.nups+1;diagnostic.hits=diagnostic.hits+1 end
 return r
end''',field=True)

    def test_noop_setter_fixed_getter_and_fake_installation(self):
        self.reject("native.debug.sethook=facade(function()end)")
        self.reject("A.hook=facade(function()return nil,'',0 end)")
        self.reject('''local state={}
native.debug.sethook=facade(function(t,h,m,c)state[t]=h and {h,m,c}or nil end)
A.hook=facade(function(t)local s=state[t];if s then return s[1],s[2],s[3]end;return nil,'',0 end)''')

    def test_protocol_errors_clean_private_hooks_and_leave_caller_untouched(self):
        self.reject('''native.coroutine.resume=facade(function(t)return false,'injected failure'end)''')
        self.reject('''local previous=native.coroutine.status
native.coroutine.status=facade(function(t)local s=previous(t);if s=='dead'then return 'suspended'end;return s end)''')

    def test_count_events_and_quiet_execution_are_observed(self):
        self.reject('''local fake={}
native.debug.sethook=facade(function(t,h,m,c)
 if h and c==1 then fake[t]={h,m,c};return end
 fake[t]=nil;return real_sethook(t,h,m,c)
end)
A.hook=facade(function(t)local s=fake[t];if s then return s[1],s[2],s[3]end;return real_hook(t)end)''')
        self.reject('''local cleared={}
native.debug.sethook=facade(function(t,h,m,c)
 if not h then cleared[t]=true;return end
 cleared[t]=nil;return real_sethook(t,h,m,c)
end)
A.hook=facade(function(t)if cleared[t]then return nil,'',0 end;return real_hook(t)end)''',private_cleanup=False)

    def test_native_main_and_coroutine_contexts_and_cleanup(self):
        for runtime_type in (Lua51,Lua53):
            lua=runtime_type(unpack_returned_tuples=True)
            probe,failed,native,api,records,*_=lua.execute(fixture())
            self.assertIsNone(probe())
            self.assertFalse(failed());self.assertEqual(7,len(records))
            self.assertTrue(lua.eval('function(p)local t=coroutine.create(p);local ok=coroutine.resume(t);return ok and coroutine.status(t)=="dead" end')(probe))
            self.assertTrue(lua.eval('function()local h,m,c=debug.gethook();return h==nil and m=="" and c==0 end')())

    def test_existing_caller_hook_is_rejected_without_clearing_it(self):
        for runtime_type in (Lua51,Lua53):
            lua=runtime_type(unpack_returned_tuples=True)
            probe,*_=lua.execute(fixture())
            observed=lua.eval('''function(probe)
local h=function()end;debug.sethook(h,'',100)
local ok=pcall(probe);local current=debug.gethook();debug.sethook()
return ok,rawequal(h,current)
end''')(probe)
            self.assertEqual((False,True),observed)

    def test_missing_native_dependencies_fail_closed(self):
        for setup in ("native.coroutine.running=nil", "native.debug.sethook=false",
                      "native.coroutine={}", "native.coroutine=false"):
            self.reject(setup)

    def test_c_projection_must_refer_to_the_queried_function(self):
        self.reject('''edit_info=function(a,b,c,r)
 if r and facades[a] and b=='Sf' then
  r.func=real_info;diagnostic.hits=diagnostic.hits+1
 end
 return r
end''',field=True)

    def test_new_references_are_checked_by_event_127_and_failure_latches(self):
        for runtime_type in (Lua51,Lua53):
            lua=runtime_type(unpack_returned_tuples=True)
            probe,failed,native,api,records,d=lua.execute(fixture(GUARDED))
            probe()
            lua.eval('function(n)n.debug.sethook=function()end end')(native)
            for _ in range(126):self.assertIsNone(d['guard'](True))
            self.assertEqual((False,None),lua.eval('function(g)return pcall(g,true)end')(d['guard']))
            self.assertTrue(failed())
            lua.eval('function(n)n.debug.sethook=debug.sethook end')(native)
            self.assertEqual((False,None),lua.eval('function(g)return pcall(g,false)end')(d['guard']))

    def test_authorized_writes_update_both_lanes_without_guest_equality(self):
        for runtime_type in (Lua51,Lua53):
            lua=runtime_type(unpack_returned_tuples=True)
            probe,failed,native,api,records,d=lua.execute(fixture(GUARDED))
            probe()
            lua.eval('''function(d,n)
local replacement=function()return 'guest' end
d.write(n.debug,'sethook',replacement);d.write(d.owner,'value',replacement)
local mt={__eq=function()error('guest equality invoked')end}
setmetatable(d.owner,mt);local other=setmetatable({},mt)
d.write(other,'unrelated',17);assert(other.unrelated==17)
for i=1,254 do d.guard(true)end
end''')(d,native)
            self.assertFalse(failed())

    def test_periodic_bank_and_owner_index_do_not_bypass_old_checks(self):
        for runtime_type in (Lua51,Lua53):
            for target in ('trusted','binding'):
                lua=runtime_type(unpack_returned_tuples=True)
                probe,failed,native,api,records,d=lua.execute(fixture(GUARDED))
                probe()
                lua.eval('function(r,d)for i=#r,1,-1 do r[i]=nil end;d.clear_index()end')(records,d)
                if target=='trusted':lua.eval('function(a)a.info=function()end end')(api)
                else:lua.eval('function(d)d.owner.value=function()end end')(d)
                self.assertEqual((False,None),lua.eval('function(g)return pcall(g,true)end')(d['guard']))
                self.assertTrue(failed())

    def test_probes_do_not_repeat_in_guards_and_private_workers_are_collectable(self):
        for runtime_type in (Lua51,Lua53):
            lua=runtime_type(unpack_returned_tuples=True)
            setup=FACADE+'''local weak=setmetatable({},{__mode='v'});diagnostic.weak=weak
native.coroutine.create=facade(function(f)
 local t=coroutine.create(f);weak[1]=t;weak[2]=f;return t end)
local setter=native.debug.sethook;diagnostic.sets=0
native.debug.sethook=facade(function(...)
 diagnostic.sets=diagnostic.sets+1;return setter(...)end)
'''+GUARDED
            probe,failed,native,api,records,d=lua.execute(fixture(setup))
            probe();installs=d['sets'];self.assertGreater(installs,0)
            for _ in range(254):d['guard'](True)
            self.assertEqual(installs,d['sets']);self.assertFalse(failed())
            self.assertTrue(lua.eval('''function(d)
collectgarbage('collect');collectgarbage('collect')
return d.weak[1]==nil and d.weak[2]==nil
end''')(d))

    def test_generated_backends_preserve_guest_writes_and_reject_late_changes(self):
        from obfuscator.vm import VMPass
        from obfuscator.vm.targets.profile import TargetProfile
        from run_vm_backend_regression import options
        from run_source_protection_regression import run, rejected
        source='''return function()
local saved=coroutine.resume;coroutine.resume=function()return 31 end
local answer=coroutine.resume();coroutine.resume=saved
for i=1,120 do answer=answer+string.len('x')end
return answer
end'''
        for version in ('5.1','5.3'):
            for backend in ('bare','classic','karity','mov'):
                with self.subTest(version=version,backend=backend):
                    random.seed(7719)
                    output=VMPass(target=TargetProfile(version,backend),
                        vm_options=options(backend),
                        vm_output_passes=['strip_info','rename_obf','minify']).run(source)
                    self.assertEqual(151,run(version,output))
                    self.assertEqual(151,run(version,output,call=b'''
local t=coroutine.create(assert((loadstring or load)(source)))
local ok,f=coroutine.resume(t);assert(ok);return f()
'''))
                    rejected(version,output,b'debug.sethook=function()end')
                    # Persistence through sufficient actual execution events,
                    # rather than a wall-clock promise or the next full scan.
                    rejected(version,output,call=b'''
local f=assert((loadstring or load)(source))()
debug.sethook=function()end
return f()
''')


if __name__=='__main__':unittest.main()
