"""Real cross-function worker execution, lexical captures and lifetime contracts."""
from pathlib import Path
import random
import sys
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from obfuscator.pipeline import Pipeline
from obfuscator.passes.function_obfuscation import FunctionObfuscationPass
from obfuscator.passes.function_costs import measure
from obfuscator.passes.ts_utils import parse


def execute(source,version):
    if version=='5.1':
        from lupa.lua51 import LuaRuntime
    else:
        from lupa.lua53 import LuaRuntime
    lua=LuaRuntime(encoding=None)
    result=[]
    lua.globals()[b'print']=lambda *args: result.append(args)
    lua.execute(source.encode('utf-8'))
    return result


def build(source,version='5.3',seed=1700,**options):
    random.seed(seed)
    p=FunctionObfuscationPass(**options)
    p.lua_version=version
    pipeline=Pipeline(show_header=False)
    pipeline.add(p)
    output=pipeline.run(source)
    assert not parse(output).root.has_error
    return output,p


class FunctionMergeTests(unittest.TestCase):
    def compare(self,source,version='5.3',**options):
        output,p=build(source,version,**options)
        self.assertEqual(execute(source,version),execute(output,version))
        return output,p

    def test_common_worker_has_bodies_and_distinct_wrappers(self):
        source='''local function add(a,b) local x=a+b;return x,nil end
local function mul(a,b) local x=a*b;return x end
print(add(2,3),mul(4,5))'''
        output,p=self.compare(source,junk=False,inline=False)
        self.assertEqual(1,p.last_merge_group_count)
        self.assertEqual(2,p.last_merged_function_count)
        ctx=parse(output)
        wrappers=[n for n in ctx.root.named_children if n.type=='function_declaration']
        self.assertEqual(2,len(wrappers))
        callees=[]
        for node in wrappers:
            body=node.child_by_field_name('body')
            statements=[n for n in body.named_children if n.type!='comment']
            self.assertEqual(['return_statement'],[n.type for n in statements])
            call=next(n for n in ctx.walk() if n.type=='function_call'
                      and body.start_byte<=n.start_byte<n.end_byte<=body.end_byte)
            callees.append(ctx.plain_text(call.child_by_field_name('name')))
        self.assertEqual(callees[0],callees[1])
        # The shared function contains both original arithmetic operations and
        # their common dispatcher, rather than calling two old body closures.
        worker=next(n for n in ctx.walk() if n.type=='function_definition'
                    and not any(a.type=='function_definition' for a in ancestors(n)))
        text=ctx.plain_text(worker)
        self.assertIn('while ',text)
        self.assertIn('+',text)
        self.assertIn('*',text)
        self.assertGreater(next(r for r in p.last_profile if r['phase']=='function_merge')['stats']['cff_blocks'],4)

    def test_fixed_arguments_multret_nested_and_reentry(self):
        source=r'''
local function outer(base)
  local function first(a,b)
    local n=base+(a or 0);if b then n=n+b else n=n-1 end
    return n,nil,a,b
  end
  local function second(a,b)
    local n=base*(a or 1);for i=1,3 do n=n+i end
    return n,nil,a,b
  end
  return first(3),second(4),first(nil,nil,99),second()
end
local function recurse(n)
  if n<=1 then return 1 end
  return n*recurse(n-1)
end
local function sum(n)
  return recurse(n)+recurse(n-1)
end
print(outer(7));print(recurse(7),sum(5));print(outer(3))
'''
        for version in ('5.1','5.3'):
            for seed in (1701,1702):
                _,p=self.compare(source,version,seed=seed,inline=False)
                self.assertGreaterEqual(p.last_merge_group_count,2)
                self.assertEqual(p.last_candidate_count,p.last_processed_source_count)

    def test_yields_errors_and_evaluation_order(self):
        source=r'''
local function first(a,b)
  local x=a+b;coroutine.yield(x,nil);return x+1,nil,b,nil
end
local function second(a,b)
  local x=a*b;coroutine.yield(x,nil);return x-1,nil,b,nil
end
local function show(...)print(select('#',...),...)end
local a,b=coroutine.create(first),coroutine.create(second)
show(coroutine.resume(a,3,4));show(coroutine.resume(b,5,6))
show(coroutine.resume(a));show(coroutine.resume(b))
local calls={}
local function one(a,b) calls[#calls+1]='one';if a then error(b,0) end;return a,b end
local function two(a,b) calls[#calls+1]='two';if a then error(b,0) end;return a,b end
local function value(n)calls[#calls+1]=n;return n end
show(one(value(1),value(2)));show(pcall(one,true,'expected-one'))
show(pcall(two,true,'expected-two'));print(table.concat(calls,','))
'''
        # Avoid an uncaught error for the evaluation-order call.
        source=source.replace('show(one(value(1),value(2)))','show(pcall(one,value(1),value(2)))')
        for version in ('5.1','5.3'):
            _,p=self.compare(source,version,inline=False)
            if version=='5.3':self.assertGreaterEqual(p.last_merge_group_count,2)
            else:self.assertEqual(0,p.last_merge_group_count)  # coroutine/pcall expose the function values

    def test_wrapper_and_capture_collection(self):
        source=r'''
local weak=setmetatable({},{__mode='v'});local kept
do
  local shared={value=7}
  local function first(n) return shared.value+n end
  local function second(n) return shared.value*n end
  assert(first~=second and first==first)
  weak[1],weak[2],weak[3]=first,second,shared;kept=first
end
collectgarbage('collect');collectgarbage('collect')
assert(weak[1] and weak[2]==nil and weak[3] and kept(3)==10)
kept=nil;collectgarbage('collect');collectgarbage('collect')
assert(weak[1]==nil and weak[3]==nil)
print('wrapper-gc-ok')
'''
        _,p=self.compare(source,inline=False)
        self.assertEqual(1,p.last_merge_group_count)
        different=r'''
local weak=setmetatable({},{__mode='v'});local kept
do local a,b={value=1},{value=2}
local function first(n)return a.value+n end
local function second(n)return b.value+n end
kept=first;weak[1]=b
end
collectgarbage('collect');collectgarbage('collect');assert(weak[1]==nil)
print(kept(4))
'''
        _,p=self.compare(different,inline=False)
        self.assertEqual(0,p.last_merge_group_count)
        self.assertTrue(any(r.get('reason')=='different-captures' for r in p.last_profile))

    def test_visibility_shadowing_and_exclusions(self):
        visibility=r'''
later=function(n)return n+100 end
local function first(n)return later(n) end
local function later(n)return math.abs(n) end
print(first(3),later(-3))
'''
        _,p=self.compare(visibility,inline=False)
        self.assertEqual(0,p.last_merge_group_count)
        self.assertTrue(any(r.get('reason')=='declaration-visibility' for r in p.last_profile))
        source=r'''
local function first(...)return ... end
local function second(...)return ... end
print(first(1,nil,3));print(second(4,nil,6))
'''
        _,p=self.compare(source)
        self.assertEqual(0,p.last_merge_group_count)
        self.assertTrue(any(r.get('reason')=='vararg-owner' for r in p.last_profile))
        shadow='local function f(a)local x=a+1;return x end;local function f(a)local x=a*2;return x end;print(f(3))'
        self.compare(shadow,inline=False)
        env=r'''local function f(n)return n+1 end
local function g(n)return n*2 end
local saved=f;setfenv(saved,{})
print(f(3),g(4),getfenv(saved)==getfenv(g))'''
        _,p=self.compare(env,'5.1',inline=False)
        self.assertEqual(0,p.last_merge_group_count)

    def test_explicit_disable_limits_selection_and_provenance(self):
        source='local function f(a)local b=a+1;return b end;local function g(a)local b=a*2;return b end;print(f(3),g(4))'
        for options in ({'merge':False},{'merge_max_groups':0},{'cff':False,'junk':False,'wrapper':False}):
            _,p=self.compare(source,inline=False,**options)
            self.assertEqual(0,p.last_merge_group_count)
        from obfuscator.registry import build_pipeline_from_config,validate_config,ConfigError
        for key,value in (('merge','true'),('merge_max_functions',1),('merge_max_groups',-1),('merge_max_functions',True)):
            with self.assertRaises(ConfigError):validate_config({'passes':['function_obf'],'function_obf_options':{key:value}})
        selected='''--@FUNCTION_OBF(merge, junk=false)
local function f(a)local b=a+1;return b end
--@FUNCTION_OBF(merge, junk=false)
local function g(a)local b=a*2;return b end
print(f(3),g(4))'''
        random.seed(1703)
        pipe=build_pipeline_from_config({'passes':['function_obf'],'selection_modes':{'function_obf':'marked'}},Pipeline,show_header=False)
        output=pipe.run(selected)
        self.assertEqual(execute(selected,'5.3'),execute(output,'5.3'))
        p=next(p for p in pipe._passes if isinstance(p,FunctionObfuscationPass))
        self.assertEqual(1,p.last_merge_group_count)
        self.assertEqual(p.last_processed_source_count,2)
        output,p=build(source,inline=False)
        self.assertNotIn('KarityNumericOrigin',output)
        self.assertTrue(getattr(output,'protected',()))
        disabled,_=build(source,seed=1704,inline=False,merge=False)
        zero,_=build(source,seed=1704,inline=False,merge_max_groups=0)
        self.assertEqual(disabled,zero)
        again,_=build(source,seed=1700,inline=False)
        self.assertEqual(output,again)

    def test_fallthrough_nil_tail_and_mutable_captures(self):
        source=r'''
local total=0
local function first(a,b)total=total+a;if b then return total,nil,b,nil end end
local function second(a,b)total=total-a;if b then return total,nil,b,nil end end
local function show(...)print(select('#',...),...)end
show(first(3));show(second(1));show(first(5,9));show(second(2,8))
print(total)
'''
        for version in ('5.1','5.3'):
            _,p=self.compare(source,version,inline=False)
            self.assertEqual(1,p.last_merge_group_count)

    def test_pooling_budget_preserves_individual_fallback(self):
        values=','.join('v'+str(i) for i in range(85))
        locals_='local '+values+'\n'
        source=('local function first(a)\n'+locals_+'v0=a+1;return function()return v0 end end\n'
                'local function second(a)\n'+locals_+'v0=a*2;return function()return v0 end end\n'
                'local f,g=first(3),second(4);print(f(),g())')
        _,p=self.compare(source,inline=False)
        self.assertEqual(0,p.last_merge_group_count)
        self.assertTrue(any(r.get('outcome')=='fallback' for r in p.last_profile))
        self.assertEqual(p.last_candidate_count,p.last_processed_source_count)

    def test_independent_call_frames_closures_and_multiple_groups(self):
        source=r'''
local function factory(base)
  local function first(a) local value=base+a;return function(n)value=value+n;return value end end
  local function second(a) local value=base*a;return function(n)value=value-n;return value end end
  return first(3),second(4)
end
local function identity(a)local x=a;return x end
local function twice(a)local x=a*2;return x end
local f,g=factory(7);local h,i=factory(3)
print(f(2),g(2),h(2),i(2));print(f(1),g(1),identity(9),twice(9))
'''
        _,p=self.compare(source,inline=False)
        self.assertGreaterEqual(p.last_merge_group_count,2)
        self.assertEqual(p.last_candidate_count,p.last_processed_source_count)

    def test_source_vm_and_packer_integration(self):
        from obfuscator.registry import build_pipeline_from_config
        from obfuscator.toolchain import LuaToolchain
        source='''local function first(a,b)local x=a+b;return x,nil,b,nil end
local function second(a,b)local x=a*b;return x,nil,b,nil end
return {first,second}'''
        harness='''local m=assert(loadfile(arg[1]))();assert(m[1]~=m[2]);
local function show(...)print(select('#',...),...)end
show(m[1](3,4));show(m[2](5,6));show(m[1](9,10))'''
        with tempfile.TemporaryDirectory() as folder:
            directory=Path(folder)
            run=directory/'harness.lua';run.write_text(harness,encoding='utf-8')
            def native(path):
                if version=='5.1':
                    # Use the standard 5.1 C runtime: an executable named
                    # lua51 on PATH may actually be LuaJIT with a different dump.
                    return execute(run.read_text(encoding='utf-8').replace('arg[1]',
                        '[=['+path.as_posix()+']=]'),version)
                result=subprocess.run([LuaToolchain(lua_version=version).lua(),str(run),str(path)],capture_output=True,timeout=90)
                self.assertEqual(0,result.returncode,result.stderr[-1500:])
                return result.stdout
            for version in ('5.1','5.3'):
                # Lua 5.1's direct-call-only contract deliberately excludes the
                # escaped table members used to check Lua 5.3 callable identity.
                current_source=(source.replace('return {first,second}',
                    'print(first(3,4));print(second(5,6));return first(9,10)') if version=='5.1' else source)
                current_harness=('local function show(...)print(select("#",...),...)end;show(assert(loadfile(arg[1]))())'
                                 if version=='5.1' else harness)
                run.write_text(current_harness,encoding='utf-8')
                original=directory/'original.lua';original.write_text(current_source,encoding='utf-8')
                expected=native(original)
                cases=([['function_obf'],['function_obf','vm']] if version=='5.1' else
                       [['function_obf'],['function_obf','pack'],['function_obf','vm'],['function_obf','vm','pack']])
                for index,passes in enumerate(cases):
                    random.seed(1705)
                    pipe=build_pipeline_from_config({'passes':passes,'signature':{'mode':'none'},
                        'target':{'lua_version':version},
                        'function_obf_options':{'merge':True,'junk':False,'inline':False},
                        'vm_options':{'fake_handlers':False,'mutate_handlers':False,'junk_instructions':False,
                                      'graph_execution_rate':0,'block_variant_rate':0,'cross_instruction_rate':0},
                        'vm_output_passes':(['rename_obf','string_encode','minify'] if version=='5.1'
                                            else ['rename_obf','string_encode','number_obf','minify']),
                        'packer_output_passes':['minify']},Pipeline,show_header=False)
                    output=pipe.run(current_source)
                    p=next(p for p in pipe._passes if isinstance(p,FunctionObfuscationPass))
                    self.assertEqual(1,p.last_merge_group_count)
                    path=directory/f'output-{index}.lua';path.write_text(output,encoding='utf-8')
                    self.assertEqual(expected,native(path),(version,passes))

    def test_group_bounds_selection_policies_and_nested_varargs(self):
        source='\n'.join(f'local function f{i}(a)return a+{i} end' for i in range(8))
        source+='\nprint('+','.join(f'f{i}(3)' for i in range(8))+')'
        for maximum,limit,expected in ((2,64,4),(8,64,1),(2,1,1)):
            _,p=self.compare(source,inline=False,merge_max_functions=maximum,merge_max_groups=limit)
            self.assertEqual(expected,p.last_merge_group_count)
        from obfuscator.registry import build_pipeline_from_config
        selected='''--@FUNCTION_OBF(merge, junk=false)
local function first(a)return a+1 end
--@FUNCTION_OBF(merge, junk=true)
local function second(a)return a*2 end
print(first(3),second(4))'''
        pipe=build_pipeline_from_config({'passes':['function_obf'],
            'selection_modes':{'function_obf':'marked'}},Pipeline,show_header=False)
        output=pipe.run(selected)
        self.assertEqual(execute(selected,'5.3'),execute(output,'5.3'))
        p=next(p for p in pipe._passes if isinstance(p,FunctionObfuscationPass))
        self.assertEqual(0,p.last_merge_group_count)
        nested='''local _z0=7
local function first(a)return function(...)return _z0+a,... end end
local function second(a)return function(...)return _z0*a,... end end
local x,y=first(3),second(4);print(x(1,nil,3));print(y(4,nil,6))'''
        _,p=self.compare(nested,inline=False)
        self.assertEqual(1,p.last_merge_group_count)
        for prefix in ('local _ENV={};',''):
            env=('local function first(a)'+prefix+'return a+1 end\n'
                 'local function second(_ENV)return 2 end\nprint(first(3),second({}))')
            _,p=self.compare(env,inline=False)
            self.assertEqual(0,p.last_merge_group_count)

    def test_selected_literal_mosaic_owns_common_worker_constants(self):
        from obfuscator.registry import build_pipeline_from_config
        from obfuscator.profiling import Profiler
        source='''--@MEME_STRINGS_START
local function first(a)local b=a+1;return b end
local function second(a)local b=a*2;return b end
--@MEME_STRINGS_END
print(first(3),second(4))'''
        pipe=build_pipeline_from_config({'passes':['function_obf','meme_strings'],
            'function_obf_options':{'inline':False,'junk':False},
            'selection_modes':{'meme_strings':'marked'},
            'literal_mosaic':{'generated_meme_rate':1.0}},Pipeline,show_header=False)
        profiler=Profiler()
        output=pipe.run(source,profiler=profiler)
        self.assertEqual(execute(source,'5.3'),execute(output,'5.3'))
        p=next(p for p in pipe._passes if isinstance(p,FunctionObfuscationPass))
        self.assertEqual(1,p.last_merge_group_count)
        self.assertGreater(profiler.as_dict()['literal_mosaic']['strategies'].get('meme_generated',0),0)


def ancestors(node):
    parent=node.parent
    while parent is not None:
        yield parent;parent=parent.parent


if __name__=='__main__':unittest.main()
