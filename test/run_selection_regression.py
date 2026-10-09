"""Selective source protection and native/VM boundary differential regressions."""
from pathlib import Path
import random
import json
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lua_runtime import lua_executable
from obfuscator import build_pipeline_from_config, Pipeline
from obfuscator.selection import SelectionPlan, SelectionError
from obfuscator.registry import resolve_config_profile


def build(source, **config):
    random.seed(19071)
    pipeline = build_pipeline_from_config({"passes": [], "signature": {"mode": "none"}, **config}, Pipeline)
    return pipeline.run(source), pipeline.last_selection_report


def run(source):
    result = subprocess.run([lua_executable(), "-"], input=source.encode(), capture_output=True, timeout=90)
    if result.returncode:
        raise AssertionError(result.stderr.decode(errors="replace"))
    return result.stdout


VM = {"backend": "classic", "fake_handlers": False, "mutate_handlers": False,
      "junk_instructions": False, "blob_form": "string"}


class Selections(unittest.TestCase):
    def equivalent(self, source, **config):
        output, report = build(source, **config)
        plain = SelectionPlan(source).source
        self.assertEqual(run(plain), run(output))
        return output, report

    def test_macros_and_unmarked_literals(self):
        source = '''local plain="keep"
local s=STRING_OBF("한글\\000hi")
local n=NUMBER_OBF(-123)
local b=BOOLEAN_OBF(false)
local t=TABLE_OBF({1, 2, key=STRING_OBF("secret")})
print(plain, #s, n, b, t[1], t[2], t.key)
'''
        output, report = self.equivalent(source)
        self.assertIn('plain="keep"', output)
        self.assertNotIn('STRING_OBF(', output)
        self.assertNotIn('"secret"', output)
        self.assertEqual(4, sum(r["status"] == "applied" for r in report))
        self.assertEqual("skipped", next(r["status"] for r in report if r["feature"] == "table_obf"))

    def test_table_macro(self):
        output, report = self.equivalent('local t=TABLE_OBF({1,2,3,key="literal"}); print(t[1],t[2],t[3],t.key)')
        self.assertIn('[1]=1', output)
        self.assertEqual("applied", report[0]["status"])

    def test_tokens_and_comments(self):
        source = '''local text=[=[
@VM
STRING_OBF("untouched")
]=]
-- STRING_OBF("comment")
--[=[ @FUNCTION_OBF(no_such_option) ]=]
print(text)
'''
        output, _ = self.equivalent(source, passes=["remove_comment"])
        self.assertIn('@VM\nSTRING_OBF("untouched")', output)

    def test_marked_and_all(self):
        source = 'local a="plain"; local b=STRING_OBF("secret"); print(a,b)'
        marked, _ = self.equivalent(source, passes=["string_obf"], selection_modes={"string_obf": "marked"})
        self.assertIn('a="plain"', marked)
        all_output, _ = self.equivalent(source, passes=["string_obf"])
        self.assertNotIn('a="plain"', all_output)

    def test_function_features(self):
        source = '''-- @FUNCTION_OBF(cff, wrapper, junk=false, nested=false)
local function selected(x)
 local y=x+1
 if y>3 then y=y*2 end
 return y
end
local function plain(x) return x+1 end
print(selected(4),plain(5))
'''
        output, report = self.equivalent(source)
        self.assertIn('local function plain(x) return x+1 end', output)
        self.assertNotIn('local y=x+1', output)
        self.assertIn("applied", [r["status"] for r in report])

    def test_function_body_directives_and_wrapper_disabled(self):
        source = '''local function f(x)
 @FUNCTION_OBF_START(cff=true, junk=false, inline=false, wrapper=false)
 local y=x+2
 if y>0 then y=y*3 end
 return y
 @FUNCTION_OBF_END
end
print(f(3))
'''
        output, _ = self.equivalent(source)
        self.assertIn('function f(x)', output)

    def test_no_obf_keeps_shared_binding_names(self):
        source = '''local shared=2
-- @NO_OBF_START
-- preserve this comment and literal
local keep="keep"
shared=shared+3
-- @NO_OBF_END
local hidden=STRING_OBF("hide")
print(shared,keep,hidden)
'''
        output, _ = self.equivalent(source, passes=["strip_info", "remove_comment", "string_obf", "rename_obf"],
                                    selection_modes={"string_obf": "marked"})
        self.assertIn('shared=shared+3', output)
        self.assertIn('local keep="keep"', output)
        self.assertIn('preserve this comment', output)

    def test_positions_follow_prepasses(self):
        source = '''-- lots of comments before annotation
-- @FUNCTION_OBF(cff, junk=false)
local function selected(long_argument)
 local long_local=long_argument+2
 if long_local>3 then long_local=long_local*2 end
 return long_local
end
local s=STRING_OBF("secret")
print(selected(5),s)
'''
        self.equivalent(source, passes=["strip_info", "remove_comment", "rename_obf"])

    def test_invalid_requests(self):
        invalid = [
            'local x=STRING_OBF(getValue())', 'local x=NUMBER_OBF(1+2)',
            'local x=BOOLEAN_OBF(1)', 'local x=TABLE_OBF(t)',
            'local STRING_OBF=function(x) return x end',
            '@VM_START\nif true then\n@VM_END\nprint(1) end',
            '@NO_OBF_START\nif true then\n@NO_OBF_END\nprint(1) end',
            '@NO_VM_END', '@VM_START\nlocal function f() end',
            '@FUNCTION_OBF(unknown)\nlocal function f() return 1 end',
            '@FUNCTION_OBF(cff=true,cff=false)\nlocal function f() return 1 end',
            'print(1)\n@VM',
            '@VM(vm_count=None)\nprint(1)',
            '@VM(profile=None)\nprint(1)',
            '@VM_START(vm_count=None)\nprint(1)\n@VM_END',
        ]
        for source in invalid:
            with self.subTest(source=source), self.assertRaises((SelectionError, ValueError)):
                build(source, vm_options=VM)

    def test_selected_vm_live_captures_recursion_and_varargs(self):
        source = '''local counter=1
@VM_START
local function selected(n,...)
 counter=counter+1
 if n>0 then return selected(n-1,...) end
 return counter,...
end
@VM_END
local function native() counter=counter+10 end
native()
print(selected(2,"a",nil,"b"))
print(counter)
'''
        output, _ = self.equivalent(source, vm_options=VM)
        self.assertIn('local function native() counter=counter+10 end', output)

    def test_multiple_vm_functions_and_methods(self):
        source = '''local shared=0
local obj={}
@VM_START(junk_rate=0.0)
function obj:inc(v) shared=shared+v; self.last=shared; return shared end
local f=function() shared=shared+1; return shared end
@VM_END
print(obj:inc(4), f(), obj.last, shared)
'''
        self.equivalent(source, vm_options=VM)

    def test_whole_vm_native_function_exclusion(self):
        source = '''@VM
local shared=1
@NO_VM
local function native(v,...)
 shared=shared+v
 return shared,...
end
local function virtual(v) shared=shared+v; return native(4,"x",nil,"y") end
print(virtual(2))
print(shared)
'''
        self.equivalent(source, passes=["vm"], vm_options=VM)

    def test_vm_environment_reassignment(self):
        source = '''local original=_ENV
local _ENV=setmetatable({value=3},{__index=original})
@VM_START
local function f() value=value+2; return value,_ENV end
@VM_END
local old=_ENV
_ENV=setmetatable({value=20},{__index=original})
local v,e=f()
print(v,e==_ENV,old.value)
'''
        self.equivalent(source, vm_options=VM)

    def test_real_backends_and_signature(self):
        source = '''local shared=1
-- @VM_START
local function f(v) shared=shared+v; return shared end
-- @VM_END
print(f(4),shared)
'''
        for backend in ("karity", "mov"):
            with self.subTest(backend=backend):
                self.equivalent(source, vm_options={**VM, "backend": backend}, signature={"mode": "default"},
                                vm_output_passes=["rename_obf", "minify"])
                native = '''@VM
local shared=1
@NO_VM
local function f(v) shared=shared+v; return shared end
print(f(4),shared)
'''
                self.equivalent(native, vm_options={**VM, "backend": backend}, signature={"mode": "default"},
                                vm_output_passes=["rename_obf", "minify"])

    def test_whole_vm_nested_native_and_recursion(self):
        source = '''@VM
local function outer(self)
 local counter=1
 @NO_VM
 local function inner(n)
  counter=counter+1
  if n>0 then return inner(n-1) end
  self.value=counter
  return counter
 end
 return inner
end
local obj={}
local f=outer(obj)
print(f(2),f(1),obj.value)
'''
        self.equivalent(source, passes=["vm"], vm_options=VM, signature={"mode": "default"})

    def test_selected_nested_method_self_and_captured_declaration(self):
        source = '''local object={}
function object:outer()
 @VM_START
 local function inner(v)
  function object:update(v) self.value=v end
  object:update(v)
  return self.value
 end
 @VM_END
 return inner
end
local f=object:outer()
print(f(7),object.value)
'''
        self.equivalent(source, vm_options=VM)

    def test_function_before_macro_pass_and_reuse(self):
        source = '''@FUNCTION_OBF(cff,junk=false)
local function f(v)
 local text=STRING_OBF("secret")
 if v then return text end
 return "plain"
end
print(f(true))
'''
        self.equivalent(source, passes=["function_obf", "string_obf"], selection_modes={"string_obf": "marked"})
        pipeline = build_pipeline_from_config({"passes": ["string_obf"], "selection_modes": {"string_obf": "marked"},
                                               "signature": {"mode": "none"}}, Pipeline)
        a = pipeline.run('print(STRING_OBF("hidden"))')
        b = pipeline.run('print("plain")')
        self.assertNotIn('"hidden"', a)
        self.assertIn('"plain"', b)
        self.assertEqual([], pipeline.last_selection_report)

    def test_compressed_region_keeps_keyword_separator(self):
        from obfuscator.names import NameAllocator
        from obfuscator.passes.ts_utils import parse
        from obfuscator.selection import Span, _apply
        from obfuscator.statement_regions import lower_region, transport_prelude
        from obfuscator.passes.base import Replacement
        for body in ('local x=1; print(x)', 'print(1)'):
            source = 'if true then ' + body + ' else print("bad") end'
            span = Span(source.index(' ' + body), source.index(' else'), 'vm')
            allocator = NameAllocator.for_source(source)
            _, transport = transport_prelude(allocator, '5.3')
            region = lower_region(source, parse(source), span, allocator, transport=transport)
            temporary = _apply(source, [*region.outside, Replacement(span.start, span.end - 1,
                               region.setup + region.helper + region.left + region.name + '()' + region.right)])
            self.assertEqual(run(source), run(temporary))

    def test_existing_profiles_for_vm_selection(self):
        config = resolve_config_profile({"profile": "source", "profiles": {
            "source": {"passes": []}, "fast-vm": {"vm_options": VM}}})
        source = '@VM_START(profile="fast-vm")\nlocal function f() return 7 end\n@VM_END\nprint(f())'
        self.equivalent(source, **config)

    def test_no_obf_overrides_macros(self):
        source = '@NO_OBF_START\nlocal x=STRING_OBF("keep")\n@NO_OBF_END\nprint(x)'
        output, report = self.equivalent(source)
        self.assertIn('"keep"', output)
        self.assertTrue(all(r["status"] == "excluded" for r in report))

    def test_runtime_globals_do_not_capture_source_locals(self):
        source = '''local type=7
local string={label="local string"}
local setmetatable=9
@VM_START
local function f(v) return type+v,string.label,setmetatable end
@VM_END
print(f(2))
'''
        self.equivalent(source, vm_options=VM)

    def test_cli_example_and_error_before_output(self):
        source = (ROOT / "examples/selective.lua").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "output.lua"
            report_path = Path(directory) / "selection.json"
            command = [sys.executable, str(ROOT / "main.py"), str(ROOT / "examples/selective.lua"),
                       "-c", str(ROOT / "config.selective.example.json"), "-o", str(output_path),
                       "--selection-report", str(report_path), "--seed", "117"]
            result = subprocess.run(command, capture_output=True, timeout=90)
            self.assertEqual(0, result.returncode, result.stderr.decode(errors="replace"))
            output = output_path.read_text(encoding="utf-8")
            self.assertEqual(run(SelectionPlan(source).source), run(output))
            report = json.loads(report_path.read_text(encoding="utf-8"))["selections"]
            self.assertIn("vm", {r["feature"] for r in report})
            self.assertTrue(all(r["line"] > 0 for r in report))
            invalid = Path(directory) / "bad.lua"
            invalid.write_text('@VM_START\nif true then\n@VM_END\nprint(1) end', encoding="utf-8")
            rejected_path = Path(directory) / "rejected.lua"
            command[2] = str(invalid)
            command[6] = str(rejected_path)
            result = subprocess.run(command, capture_output=True, timeout=90)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("complete statements", result.stderr.decode(errors="replace"))
            self.assertNotIn("Traceback", result.stderr.decode(errors="replace"))
            self.assertFalse(rejected_path.exists())

    def test_file_vm_options_without_configured_pass(self):
        _, report = self.equivalent('@VM(backend="classic", fake_handlers=false, mutate_handlers=false)\nprint(7)')
        self.assertEqual("applied", report[0]["status"])

    def test_native_source_minification_preserves_exclusions(self):
        source = '''local outside = "a"
@NO_OBF_START
-- keep this
local readable = "b"
@NO_OBF_END
print(outside,readable)
'''
        output, _ = self.equivalent(source, passes=["minify"])
        self.assertIn('-- keep this\nlocal readable = "b"', output)

    def test_vm_region_anonymous_function_with_nested_closure(self):
        source = '''@VM_START
local f=function(v) return function(w) return v+w end end
@VM_END
print(f(2)(3))
'''
        self.equivalent(source, vm_options=VM)

    def test_nested_vm_options_inherit_and_override(self):
        source = '''@VM_START(junk_rate=0.0)
local function outer()
 @VM_START
 local function inner(v) return v+1 end
 @VM_END
 return inner
end
@VM_END
print(outer()(5))
'''
        self.equivalent(source, vm_options=VM)
        self.equivalent(source.replace('@VM_START\n', '@VM_START(junk_rate=0.5)\n'), vm_options=VM)

    def test_nested_native_function_boundary(self):
        source = '''@VM_START
local function outer()
 @NO_VM
 local function inner() return 1 end
 return inner()
end
@VM_END
print(outer())
'''
        self.equivalent(source, vm_options=VM)

    def test_disabled_function_features_report_skipped(self):
        source = '@FUNCTION_OBF(cff=false,junk=false,inline=false,wrapper=false)\nlocal function f(v) return v+1 end\nprint(f(3))'
        output, report = self.equivalent(source)
        self.assertIn('local function f(v) return v+1 end', output)
        self.assertEqual("skipped", report[0]["status"])

    def test_excluded_macro_does_not_enable_incompatible_pass(self):
        source = '@NO_OBF_START\nlocal s=STRING_OBF("plain")\n@NO_OBF_END\nprint(s)'
        output, report = build(source, target={"lua_version": "5.1"})
        self.assertIn('"plain"', output)
        self.assertEqual("excluded", report[0]["status"])

    def test_statement_vm_preserves_shadowing_and_shared_closures(self):
        source = '''local x=4
local previous=function() return x end
@VM_START
local x=x+1
local a,b=2,3
local empty
local function bump() x=x+a+b; return x end
local read=function() return x end
x=x*2
@VM_END
print(previous(),x,bump(),read(),x,empty)
x=100
print(read(),bump(),previous())
'''
        _, report = self.equivalent(source, vm_options=VM)
        self.assertEqual("applied", report[0]["status"])

    def test_statement_control_flow_and_varargs_across_backends(self):
        source = '''local function f(limit,...)
local total=0
for i=1,5 do
@VM_START
local delta=i+1
total=total+delta
for j=1,3 do if j==2 then break end total=total+j end
if total>limit then break end
@VM_END
total=total+1
end
@VM_START
if limit<4 then return total,... end
@VM_END
return total,nil,9,nil
end
print(f(2,"한글",nil,3,nil));print(f(100))
'''
        for backend in ("classic", "karity", "mov"):
            for seed in (23, 91):
                with self.subTest(backend=backend, seed=seed):
                    self.equivalent(source, vm_options={**VM, "backend": backend},
                                    passes=["remove_comment", "rename_obf"],
                                    rename_options={"seed": seed}, signature={"mode": "default"},
                                    vm_output_passes=["rename_obf", "minify"])

    def test_statement_native_exclusions_in_root_and_selected_functions(self):
        source = '''local total=1
@VM_START
local function protected(n,...)
@NO_VM_START
local delta=n+total
total=delta
if n>3 then return total,... end
@NO_VM_END
return delta,total
end
@VM_END
print(protected(2));print(protected(5,1,nil,3,nil));print(total)
'''
        for whole in (False, True):
            for backend in ("classic", "karity", "mov"):
                with self.subTest(whole=whole, backend=backend):
                    text = "@VM\n" + source if whole else source
                    _, report = self.equivalent(text, vm_options={**VM, "backend": backend},
                                               vm_output_passes=["rename_obf", "minify"])
                    self.assertIn("partial", [r["status"] for r in report])

    def test_partial_source_function_regions_preserve_control_and_unmarked_code(self):
        source = '''local function f(limit,...)
local untouched="outside"
local total=0
for i=1,5 do
@FUNCTION_OBF_START(cff, junk=false)
local step=i+1
total=total+step
if total>limit then break end
@FUNCTION_OBF_END
total=total+1
end
@FUNCTION_OBF_START(cff, junk=false)
if limit<4 then return total,... end
@FUNCTION_OBF_END
return untouched,total,nil,7,nil
end
print(f(2,1,nil,3,nil));print(f(100))
'''
        for version in ("5.1", "5.3"):
            for mode in ("cff", "split", "mixed"):
                with self.subTest(version=version, mode=mode):
                    output, report = build(source, target={"lua_version": version},
                                           function_obf_options={"boundary_mode": mode})
                    from run_function_lua51_regression import execute, Lua51, Lua53
                    lua = Lua51 if version == "5.1" else Lua53
                    self.assertEqual(execute(lua, SelectionPlan(source).source), execute(lua, output))
                    self.assertIn('local untouched="outside"', output)
                    self.assertEqual(["applied", "applied"], [r["status"] for r in report])

    def test_regions_in_repeat_and_lexical_environment(self):
        source = '''local original=_ENV
local value=7
local n=0
repeat
@VM_START
local done=n>1
n=n+1
@VM_END
until done
@VM_START
local _ENV=setmetatable({value=11,self=31},{__index=original})
local captured=value
local global_self=self
local read=function() return value end
value=19
@VM_END
print(n,captured,read(),value,global_self,self)
_ENV.value=23
print(read())
'''
        self.equivalent(source, vm_options=VM)

    def test_method_self_is_local_to_each_method_inside_region(self):
        source = '''local object={value=5}
function object:run()
@VM_START
local other={value=9}
function other:read() return self.value end
local inherited=function() return self.value end
local result=other:read()+inherited()
@VM_END
return result,other:read()
end
print(object:run())
'''
        self.equivalent(source, vm_options=VM)

    def test_cross_boundary_gotos_and_empty_regions_fail(self):
        invalid = [
            '@VM_START\ngoto outside\n@VM_END\n::outside::\nprint(1)',
            'goto inside\n@VM_START\n::inside::\nprint(1)\n@VM_END',
            'local function f()\n@FUNCTION_OBF_START\ngoto outside\n@FUNCTION_OBF_END\n::outside:: return 1 end',
            '@VM_START\n-- empty\n@VM_END',
        ]
        for source in invalid:
            with self.subTest(source=source), self.assertRaises(SelectionError):
                build(source, vm_options=VM)


    def test_partial_source_exports_live_shadowed_locals(self):
        source = '''local function outer(x)
local prior=function() return x end
@FUNCTION_OBF_START(cff, junk=false)
local x=x+1
local y,z=2,3
local empty
local function next_value() x=x+y+z; return x end
local read=function() return x end
x=x*2
@FUNCTION_OBF_END
print(prior(),next_value(),read(),empty)
x=100
return read(),next_value(),prior()
end
print(outer(4))
'''
        for mode in ("cff", "mixed", "split"):
            self.equivalent(source, function_obf_options={"boundary_mode": mode}, passes=["remove_comment", "rename_obf"])

    def test_vm_internal_goto_stays_in_domain(self):
        source = '''local sum=0
@VM_START
local n=0
::again::
n=n+1
sum=sum+n
if n<3 then goto again end
@VM_END
print(sum,n)
'''
        self.equivalent(source, vm_options=VM)


    def test_region_transport_ignores_shadowed_builtins(self):
        source = '''local function f(n,...)
local select,unpack,table,getfenv=1,2,3,4
@FUNCTION_OBF_START(cff, junk=false)
if n>3 then return ... end
n=n+select+unpack+table+getfenv
@FUNCTION_OBF_END
return n
end
print(f(1));print(f(5,1,nil,3,nil))
'''
        from run_function_lua51_regression import execute, Lua51, Lua53
        for version, lua in (("5.1", Lua51), ("5.3", Lua53)):
            output, _ = build(source, target={"lua_version": version})
            self.assertEqual(execute(lua, SelectionPlan(source).source), execute(lua, output))
        self.equivalent(source.replace("FUNCTION_OBF", "VM").replace("(cff, junk=false)", ""), vm_options=VM)

    def test_fully_excluded_statement_vm_reports_without_runtime(self):
        source = '''@NO_VM_START
@VM_START
local value=7
print(value)
@VM_END
@NO_VM_END
'''
        for version in ("5.1", "5.3"):
            for passes in ([], ["vm"]):
                with self.subTest(version=version, passes=passes), patch(
                        "obfuscator.selective_vm._vm_build", side_effect=AssertionError("unexpected VM build")):
                    output, report = self.equivalent(source, passes=passes, vm_options=VM,
                                                     selection_modes={"vm": "marked"},
                                                     target={"lua_version": version})
                    self.assertEqual(SelectionPlan(source).source, output)
                    self.assertEqual(2, len(report))
                    self.assertTrue(all(r["status"] == "excluded" for r in report))

    def test_partial_source_keeps_nested_vm_and_excluded_export_provenance(self):
        source = '''local function f(n)
local plain=n+1
@FUNCTION_OBF_START(cff, junk=false)
local y=plain*3
@VM_START
y=y+2
@VM_END
@FUNCTION_OBF_END
return y
end
print(f(2))
'''
        _, report = self.equivalent(source, vm_options=VM)
        self.assertIn("skipped", [r["status"] for r in report if r["feature"] == "function_obf"])
        source = '''local function f(n)
local prior=n
@FUNCTION_OBF_START(cff, junk=false)
local visible=n+1
n=n*2
@FUNCTION_OBF_END
@NO_OBF_START
print(visible)
@NO_OBF_END
return n,prior
end
print(f(3))
'''
        output, report = self.equivalent(source)
        self.assertIn("print(visible)", output)
        self.assertEqual("skipped", report[0]["status"])


    def test_equal_effective_vm_options_share_one_runtime(self):
        source = '''local shared=0
@VM_START
local function first(v) shared=shared+v; return shared end
@VM_END
@VM_START(junk_rate=0.15)
local function second(v) shared=shared+v; return first(v) end
@VM_END
@VM_START
local function third(v) shared=shared+v; return second(v) end
@VM_END
print(first(1),second(2),third(3),shared)
'''
        from obfuscator import selective_vm
        for backend in ("classic", "karity", "mov"):
            with self.subTest(backend=backend), patch.object(selective_vm, "_vm_build", wraps=selective_vm._vm_build) as compile_vm:
                self.equivalent(source, vm_options={**VM, "backend": backend},
                                signature={"mode": "default"}, vm_output_passes=["rename_obf", "minify"])
                self.assertEqual(1, compile_vm.call_count)

    def test_different_vm_options_and_backends_remain_separate(self):
        source = '''local shared=0
@VM_START
local function first(v) shared=shared+v; return shared end
@VM_END
@VM_START(junk_rate=0.5)
local function second(v) shared=shared+v; return first(v) end
@VM_END
@VM_START(backend="mov")
local function third(v) shared=shared+v; return second(v) end
@VM_END
@VM_START
local function fourth(v) shared=shared+v; return third(v) end
@VM_END
print(fourth(3),shared)
'''
        from obfuscator import selective_vm
        with patch.object(selective_vm, "_vm_build", wraps=selective_vm._vm_build) as compile_vm:
            self.equivalent(source, vm_options=VM, signature={"mode": "default"},
                            vm_output_passes=["rename_obf", "minify"])
            self.assertEqual(3, compile_vm.call_count)

    def test_shared_vm_mutual_recursion_and_coroutines(self):
        source = '''local shared=0
local first,second
@VM_START
first=function(n,...)
 shared=shared+1
 if n>0 then return second(n-1,...) end
 return shared,...
end
@VM_END
@VM_START
second=function(n,...)
 shared=shared+2
 if n>0 then return first(n-1,...) end
 return shared,...
end
@VM_END
@VM_START
local function worker(label)
 for i=1,2 do
  shared=shared+10
  coroutine.yield(label,shared,nil,i)
 end
 return shared,nil,label,nil
end
@VM_END
print(first(6,"x",nil,7,nil))
local a=coroutine.create(function() return worker("a") end)
local b=coroutine.create(function() return worker("b") end)
for i=1,3 do print(coroutine.resume(a));print(coroutine.resume(b)) end
print(shared)
'''
        for backend in ("classic", "karity", "mov"):
            with self.subTest(backend=backend):
                self.equivalent(source, vm_options={**VM, "backend": backend, "mutate_handlers": True,
                                                   "fake_handlers": True, "junk_instructions": True, "junk_rate": 0.05},
                                vm_output_passes=["rename_obf", "minify"])


    def test_vm_boundaries_work_in_minimal_custom_environments(self):
        source = '''local original=_ENV
local function run(initial)
 local _ENV={value=initial}
 @VM_START
 local function read() return value end
 local result=value+1
 @NO_VM_START
 result=result+2
 @NO_VM_END
 @VM_END
 value=value+10
 return result,read(),_ENV.value
end
original.print(run(7));original.print(run(12))
'''
        for backend in ("classic", "karity", "mov"):
            for whole in (False, True):
                with self.subTest(backend=backend, whole=whole):
                    text = "@VM\n" + source if whole else source
                    self.equivalent(text, vm_options={**VM, "backend": backend}, vm_output_passes=["rename_obf", "minify"])


    def test_shared_runtime_with_vm_distribution_and_protection_options(self):
        source = '''local shared=0
@VM_START
local function first(n,...)
 shared=shared+n
 @NO_VM_START
 shared=shared+3
 @NO_VM_END
 return shared,...
end
@VM_END
@VM_START
local function second(n,...)
 shared=shared+n
 return first(n,...)
end
@VM_END
print(first(2,1,nil,3,nil));print(second(5,false,nil));print(shared)
'''
        from obfuscator import selective_vm
        for backend in ("classic", "karity", "mov"):
            with self.subTest(backend=backend), patch.object(selective_vm, "_vm_build", wraps=selective_vm._vm_build) as compile_vm:
                self.equivalent(source, vm_options={**VM, "backend": backend, "vm_count": 2,
                    "integrity_constants": True, "semantic_state_threading": True,
                    "argument_virtualization": True, "upvalue_virtualization": True,
                    "table_virtualization": True, "branch_virtualization": True},
                    signature={"mode": "default"}, vm_output_passes=["rename_obf", "minify"])
                self.assertEqual(1, compile_vm.call_count)


    def test_partial_function_options_inherit_disabled_parent_features(self):
        source = '''@FUNCTION_OBF(cff=false,junk=false,inline=false,wrapper=false)
local function f(n)
 local prior=n
 @FUNCTION_OBF_START
 local result=n*3
 if result>5 then result=result+2 end
 @FUNCTION_OBF_END
 return prior,result
end
print(f(3))
'''
        output, report = self.equivalent(source)
        self.assertEqual(SelectionPlan(source).source, output)
        self.assertEqual(["skipped", "skipped"], [r["status"] for r in report])
        text = source.replace('@FUNCTION_OBF_START\n', '@FUNCTION_OBF_START(cff, junk=false)\n')
        output, report = self.equivalent(text)
        self.assertNotIn('local result=n*3', output)
        self.assertIn("applied", [r["status"] for r in report])

    def test_disabled_partial_marker_blocks_enclosing_all_mode_rewrite(self):
        source = '''local function f(n)
 local prior=n
 @FUNCTION_OBF_START(cff=false,junk=false,inline=false,wrapper=false)
 local result=n*3
 if result>5 then result=result+2 end
 @FUNCTION_OBF_END
 return prior,result
end
local function g(n) local x=n+2; if x>3 then x=x*2 end return x end
print(f(3));print(g(4))
'''
        output, report = self.equivalent(source, passes=["function_obf"])
        self.assertIn('local result=n*3', output)
        self.assertNotIn('local x=n+2', output)
        self.assertEqual("skipped", report[0]["status"])


    def test_native_only_marked_vm_allows_manual_source_minification(self):
        from obfuscator.vm.vm_pass import VMPass
        from obfuscator.passes.minify import MinifyPass
        pipeline = Pipeline().add(VMPass(vm_options=VM)).add(MinifyPass())
        pipeline.selection_config = {"selection_modes": {"vm": "marked"}}
        for source in ('local value = 2\nprint( value )\n',
                       '@NO_VM_START\n@VM_START\nlocal value = 2\nprint( value )\n@VM_END\n@NO_VM_END\n'):
            output = pipeline.run(source)
            self.assertEqual(run(SelectionPlan(source).source), run(output))
            self.assertNotEqual(SelectionPlan(source).source, output)
        with self.assertRaisesRegex(SelectionError, "invalidate integrity"):
            pipeline.run('@VM_START\nprint(2)\n@VM_END\n')

    def test_exclusion_only_marked_vm_reports_without_runtime(self):
        sources = ('@NO_VM_START\nprint(2)\n@NO_VM_END\n',
                   '@NO_OBF_START\nprint(2)\n@NO_OBF_END\n',
                   '@NO_VM\nlocal function f() return 2 end\nprint(f())\n')
        for source in sources:
            for version in ("5.1", "5.3"):
                with self.subTest(source=source, version=version):
                    output, report = self.equivalent(source, passes=["vm"], vm_options=VM,
                                                     selection_modes={"vm": "marked"},
                                                     target={"lua_version": version})
                    self.assertEqual(SelectionPlan(source).source, output)
                    self.assertEqual(1, len(report))
                    self.assertEqual("excluded", report[0]["status"])

    def test_manual_function_pass_defaults_apply_to_regions_and_nesting(self):
        from obfuscator.passes.function_obfuscation import FunctionObfuscationPass
        source = '''local function f(n)
 local prior=n+1
 @FUNCTION_OBF_START
 local result=prior*3
 if result>5 then result=result+2 end
 @FUNCTION_OBF_END
 return result
end
print(f(3))
'''
        pass_ = FunctionObfuscationPass(cff=False, junk=False, inline=False, wrapper=False)
        pipeline = Pipeline(show_header=False).add(pass_)
        output = pipeline.run(source)
        self.assertEqual(SelectionPlan(source).source, output)
        self.assertEqual("disabled function features", pipeline.last_selection_report[0]["reason"])
        selected = source.replace('@FUNCTION_OBF_START\n', '@FUNCTION_OBF_START(cff, junk=false)\n')
        output = pipeline.run(selected)
        self.assertEqual(run(SelectionPlan(selected).source), run(output))
        self.assertEqual("applied", pipeline.last_selection_report[0]["status"])
        self.assertTrue(all(value is False for value in pass_.features.values()))
        self.assertEqual(SelectionPlan(source).source, pipeline.run(source))

        source = '''@FUNCTION_OBF
local function f(n)
 local function inner(x) local y=x+1; if y>3 then y=y*2 end return y end
 local result=inner(n)
 if result>10 then result=result+2 end
 return result
end
print(f(3))
'''
        pass_ = FunctionObfuscationPass(nested=False, junk=False)
        pipeline = Pipeline(show_header=False).add(pass_)
        output = pipeline.run(source)
        self.assertEqual(run(SelectionPlan(source).source), run(output))
        self.assertEqual(0, pass_.last_nested_transformed_count)
        self.assertGreater(pass_.last_transformed_count, 0)


if __name__ == "__main__":
    unittest.main()
