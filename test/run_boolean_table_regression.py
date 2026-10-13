"""Literal dataflow, table ordering/arity, and provenance regressions."""
from pathlib import Path
import random
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lupa.lua51 import LuaRuntime as Lua51
from lupa.lua53 import LuaRuntime as Lua53
from obfuscator import Pipeline, build_pipeline_from_config
from obfuscator.passes.boolean_expressions import BooleanExpressionEngine
from obfuscator.passes.boolean_obfuscation import BooleanObfuscationPass
from obfuscator.passes.table_obfuscation import TableObfuscationPass
from obfuscator.passes.number_obfuscation import NumberObfuscationPass
from obfuscator.passes.function_obfuscation import FunctionObfuscationPass
from obfuscator.passes.numeric_provenance import protected_number
from obfuscator.passes.ts_utils import parse
from obfuscator.names import NameAllocator
from obfuscator.registry import ConfigError, validate_config
from lua_runtime import lua_executable

PREFIX = '''local results={}
local print=function(...) local row={} for i=1,select('#',...) do
row[i]=tostring(select(i,...)) end results[#results+1]=table.concat(row,',') end
'''
SUFFIX = "\nreturn table.concat(results,'|')"


def output(source, runtime=Lua53):
    return runtime(unpack_returned_tuples=True).execute(PREFIX+source+SUFFIX)


def transform(source, *passes):
    pipeline = Pipeline(show_header=False)
    for pass_ in passes:
        pipeline.add(pass_)
    return pipeline.run(source)


class Literals(unittest.TestCase):
    def test_predicate_families_and_boolean_type(self):
        engine = BooleanExpressionEngine()
        families = set()
        lua = Lua53()
        for seed in range(120):
            for value in (False, True):
                random.seed(seed)
                expr = engine.generate(value)
                families.add(engine.last_strategy)
                self.assertEqual(lua.eval(expr), value)
                self.assertEqual(lua.eval('type('+expr+')'), 'boolean')
                self.assertLess(len(expr), 480)
                random.seed(seed)
                expr = engine.generate(value, dataflow=True, allocator=NameAllocator())
                self.assertEqual(lua.eval(expr), value)
                self.assertEqual(lua.eval('select("#",'+expr+')'), 1)
        self.assertEqual(families, {'sum', 'difference', 'product', 'xor', 'mask', 'mba'})

    def test_boolean_contexts_and_number_provenance(self):
        source = '''local function f(...) return false,true,nil,... end
local a={true,false}; print(type(a[1]),a[1],a[2])
local calls=0; local function side() calls=calls+1; return 'called' end
print(false and side(),true or side(),false or side(),true and 7,calls)
print(f(3,nil)); print(select('#',f(3,nil)))'''
        for mode in ('expression', 'dataflow', 'mixed'):
            random.seed(73)
            boolean = BooleanObfuscationPass(mode=mode)
            first = transform(source, boolean)
            self.assertEqual(output(first), output(source))
            ctx = parse(first)
            generated = [n for n in ctx.walk() if n.type == 'number'
                         and protected_number(first, ctx.cs(n), ctx.ce(n)+1)]
            self.assertTrue(generated)
            number = NumberObfuscationPass()
            edits = number.run(first, parse(first))
            self.assertTrue(edits)  # Original 3/7/0/1 retain NumberObf coverage.
            self.assertTrue(all(not protected_number(first,r.start,r.end+1) for r in edits))
            combined = transform(first, number)
            self.assertEqual(output(combined), output(source))

    def test_boolean_cff_dataflow(self):
        random.seed(123)
        source = 'local function f() return true,false,nil end print(f());print(select("#",f()))'
        cff = FunctionObfuscationPass(cff=True, junk=False, nested=True, loop_unroll=False)
        result = transform(source, BooleanObfuscationPass(mode='dataflow'), cff)
        self.assertEqual(output(result), output(source))
        self.assertGreater(cff.last_transformed_count, 1)
        self.assertTrue(any('reconstruction_statements' in str(d) for d in cff.last_profile))

    def test_boolean_mosaic_scopes(self):
        source='print(true,false,type(true),true and 7,false or 3)'
        for seed in range(12):
            for operations in (0,1,3):
                random.seed(seed)
                config={'passes':['boolean_obf','number_obf','meme_strings'],
                        'literal_mosaic':{'max_operations':operations,'generated_meme_rate':1},
                        'signature':{'mode':'none'}}
                result=build_pipeline_from_config(config,Pipeline,show_header=False).run(source)
                self.assertEqual(output(result),output(source))

    def test_tables_semantics(self):
        fixtures = [
            'local t={a=1,b=2,c=false};print(t.a,t.b,t.c,#t)',
            'local a=9;local t={a,a=3,b=4};print(t[1],t.a,t.b,#t)',
            'local t={1,nil,nil,4,nil};print(#t,t[1],t[4],t[5])',
            'local t={a=1,a=2,["a"]=3};print(t.a)',
            'local t={1,2,[1]=8};print(t[1],t[2],#t)',
            'local k="a";local t={[k]=1,a=2};print(t.a)',
            'local t={[1.0]=1,[0x1]=2};print(t[1],#t)',
            'local function f() return 1,nil,3,nil end local t={f()};print(#t,t[1],t[3])',
            'local function f(...) return {...} end local t=f(1,nil,3,nil);print(#t,t[3])',
            'local n=0;local function f() n=n+1;return n end local t={f(),a=f(),f()};print(t[1],t[2],t.a,n)',
            'local t={a={b=2,c=3},d=4};print(t.a.b,t.a.c,t.d)',
            'local t={[true]=1,[false]=2};print(t[true],t[false],#t)',
            'local t={"hi",true,7,a=3,b=4};print(t[1],t[2],t[3],t.a,t.b,#t)',
            'local o=setmetatable({},{__add=function() print("add"); return 3 end});local t={o+o,a=2};print(t[1],t.a)',
            'local t={a=function() return 3,nil end,b=2};print(t.a(),t.b)',
        ]
        for runtime in (Lua51, Lua53):
            for source in fixtures:
                for seed in range(4):
                    random.seed(seed)
                    result = transform(source, TableObfuscationPass(mode='reconstruct'))
                    self.assertEqual(output(result,runtime), output(source,runtime), source)

    def test_globals_are_observable(self):
        source = '''local calls=0
local _ENV=setmetatable({}, {__index=function(_,k) calls=calls+1;return calls end})
local t={a=left,b=right}; return t.a,t.b,calls'''
        p = TableObfuscationPass(mode='reconstruct')
        result = transform(source,p)
        self.assertEqual(Lua53().execute(result),Lua53().execute(source))
        self.assertIn('local t={a=left,b=right}',result)
        self.assertGreaterEqual(p.last_profile[0]['preserved_unsafe_or_colliding'],1)

    def test_nested_selected_and_budget(self):
        source = 'local t={a={b=1,c=2},d=3};print(t.a.b,t.a.c,t.d)'
        p=TableObfuscationPass(mode='reconstruct',max_fields=1)
        result=transform(source,p)
        self.assertEqual(output(result),output(source))
        self.assertEqual(p.last_profile[0]['reconstruction_field_budget'],2)
        source = 'local t=TABLE_OBF({a=1,b=2}); print(t.a,t.b,BOOLEAN_OBF(false))'
        config={'passes':[], 'table_obf_options':{'mode':'reconstruct'},
                'boolean_obf_options':{'mode':'dataflow'},'signature':{'mode':'none'}}
        p=build_pipeline_from_config(config,Pipeline,show_header=False)
        result=p.run(source)
        self.assertEqual(output(result),output(source.replace('TABLE_OBF(','(').replace('BOOLEAN_OBF(','(')))
        self.assertNotIn('TABLE_OBF',result)
        self.assertTrue(any(d['status']=='applied' and d['feature']=='table_obf' for d in p.last_selection_report))

    def test_table_keys_and_cff(self):
        random.seed(58)
        source = 'local t={hello=1,world=2};print(t.hello,t.world)'
        t=TableObfuscationPass(mode='reconstruct',string_keys=True)
        cff=FunctionObfuscationPass(cff=True,junk=False,nested=True,loop_unroll=False)
        result=transform(source,t,cff,NumberObfuscationPass())
        self.assertEqual(output(result),output(source))
        self.assertEqual(t.last_profile[0]['reconstruction_programs'],1)
        self.assertNotIn('"hello"',result)
        self.assertGreaterEqual(cff.last_transformed_count,3)
        self.assertTrue(any('reconstruction_statements' in str(d) for d in cff.last_profile))

    def test_invalid_options(self):
        for config in ({'boolean_obf_options':{'mode':'unknown'}},
                       {'boolean_obf_options':{'mode':[]}},
                       {'table_obf_options':{'mode':[]}},
                       {'table_obf_options':{'max_fields':True}},
                       {'table_obf_options':{'string_keys':1}}):
            with self.assertRaises(ConfigError):validate_config(config)

    def test_upvalue_budget_and_nested_edits(self):
        names=[f'v{i}' for i in range(61)]
        source='local '+','.join(names)+'='+','.join(str(i) for i in range(61))+';'
        source+='local t={child={'+','.join(f'k{i}={name}' for i,name in enumerate(names))+'},other=1};'
        source+='print(t.child.k60,t.other)'
        p=TableObfuscationPass(mode='reconstruct',max_fields=64)
        result=transform(source,p)
        self.assertEqual(output(result,Lua51),output(source,Lua51))
        self.assertEqual(p.last_profile[0]['reconstruction_upvalue_budget'],2)
        # A preserved parent must still contain transformed selected children.
        source='local t={a={x=1,y=2},b=(function() return {u=3,v=4} end)()};print(t.a.x,t.b.v)'
        p=TableObfuscationPass(mode='reconstruct')
        result=transform(source,p)
        self.assertEqual(output(result),output(source))
        self.assertEqual(p.last_profile[0]['reconstruction_programs'],2)

    def test_dense_array_reconstruction(self):
        source='local t={1,2,3,4};print(#t,t[1],t[4])'
        p=TableObfuscationPass(mode='reconstruct')
        result=transform(source,p)
        self.assertEqual(p.last_profile[0]['reconstruction_programs'],1)
        for runtime in (Lua51,Lua53):self.assertEqual(output(result,runtime),output(source,runtime))
        ctx=parse(result)
        indices=[n for n in ctx.walk() if n.type=='number' and protected_number(result,ctx.cs(n),ctx.ce(n)+1)]
        self.assertEqual(len(indices),4)

    def test_vm_backends(self):
        source='''local function f(x,...) local t={a=x,b=3};local v={...}
return t.a+t.b,true,false,v[1],nil end
local a,b,c,d,e=f(4,9);assert(a==7 and b==true and c==false and d==9 and e==nil)
assert(select('#',f(4,9))==5)'''
        for backend in ('classic','karity','mov'):
            random.seed(2851)
            config={'passes':['boolean_obf','table_obf','vm'],
                    'boolean_obf_options':{'mode':'mixed'},'table_obf_options':{'mode':'reconstruct'},
                    'vm_output_passes':['boolean_obf','table_obf','number_obf','minify'],
                    'vm_options':{'backend':backend,'fake_handlers':False,'junk_instructions':False,
                                  'mutate_handlers':False,'vm_count':1},'signature':{'mode':'none'}}
            pipeline=build_pipeline_from_config(config,Pipeline,show_header=False)
            generated=pipeline.run(source)
            executed=subprocess.run([lua_executable(), '-'],input=generated.encode(),capture_output=True,timeout=120)
            self.assertEqual(executed.returncode,0,(backend,executed.stderr.decode(errors='replace')))

    def test_lua51_vm_table_output(self):
        source='local t={1,2,3,a=4};assert(#t==3 and t[2]+t.a==6)'
        for backend in ('classic','karity','mov'):
            random.seed(2853)
            config={'passes':['table_obf','vm'],'target':{'lua_version':'5.1'},
                    'vm_output_passes':['table_obf','minify'],
                    'vm_options':{'backend':backend,'vm_count':1,'fake_handlers':False,
                                  'mutate_handlers':False,'junk_instructions':False},
                    'signature':{'mode':'none'}}
            result=build_pipeline_from_config(config,Pipeline,show_header=False).run(source)
            Lua51().execute(result)


if __name__ == '__main__':
    unittest.main()
