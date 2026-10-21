"""Native semantics, visual pattern, selection and protected-output routing."""
from pathlib import Path
import random
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lupa.lua51 import LuaRuntime as Lua51
from lupa.lua53 import LuaRuntime as Lua53
from obfuscator.passes.semicolon import SemiColonPass
from obfuscator.passes.minify import MinifyPass
from obfuscator.pipeline import Pipeline
from obfuscator.registry import PASS_REGISTRY, build_pipeline_from_config, get_pass_contexts
from obfuscator.vm import VMPass
from obfuscator.vm.targets.profile import TargetProfile
from run_blob_form_regression import execute


CASES = (
    'local a=1 local b=2 a=a+b return a,b',
    'local a=1; local b=2; return a+b;',
    'local s="한글 ;;; --" -- keep ;;;\nlocal t=[=[;;;\ntext]=] return s,t',
    'local function f(...) local a={...};return a[1],... end return f(3,nil,5)',
    'local n=0 for i=1,5 do if i==3 then break end n=n+i end return n',
    'local n=0 repeat local a=1 n=n+a until n==3 while n<5 do n=n+1 end return n',
    'local n=0 if false then n=1 elseif true then n=2 else n=3 end return n',
    'local t={x=1;2,3};function t:f() do self.x=self.x+1 end return self.x end return t:f()',
    'local f=function() local x=1 return function() x=x+1 return x end end return f()()',
    'return (function() local a=1 return a end)()',
    '-- just a comment ;;;\n',
)


class SemiColonTests(unittest.TestCase):
    def test_pattern_and_literals(self):
        source = 'local a=1 local b=2 a=a+b print(a) local c=4'
        self.assertEqual('local a=1; local b=2;;; a=a+b;; print(a); local c=4;',
                         SemiColonPass().run(source))
        self.assertEqual('local a=1; local b=2; a=a+b; print(a); local c=4;',
                         SemiColonPass('5.1').run(source))
        for source in CASES:
            for version, runtime in (('5.1', Lua51), ('5.3', Lua53)):
                with self.subTest(version=version, source=source):
                    pass_ = SemiColonPass(version)
                    output = pass_.run(source)
                    self.assertEqual(source.count('\n'), output.count('\n'))
                    self.assertEqual(output, pass_.run(output))
                    lua = runtime(unpack_returned_tuples=True)
                    self.assertEqual(lua.execute(source), lua.execute(output))
                    self.assertEqual(lua.execute(source), lua.execute(MinifyPass().run(output)))
        for literal in ('"한글 ;;; --"', '-- keep ;;;', '[=[;;;\ntext]=]'):
            self.assertIn(literal, SemiColonPass().run(CASES[2]))
        source = 'local x=0 ::again:: x=x+1 if x<3 then goto again end return x'
        self.assertEqual(3, Lua53().execute(SemiColonPass().run(source)))
        self.assertTrue(SemiColonPass().run('#!/usr/bin/lua\nlocal a=1\nreturn a').startswith('#!/usr/bin/lua\n'))

    def test_selection_and_registration(self):
        self.assertIs(PASS_REGISTRY['semicolon']['cls'], SemiColonPass)
        self.assertEqual(3, len(get_pass_contexts('semicolon')))
        source = ('local a=1\n--@NO_OBF_START\nlocal keep = "readable" -- keep\n'
                  '--@NO_OBF_END\na=a+2\nreturn a,keep')
        pipeline = build_pipeline_from_config({'passes': ['semicolon'], 'signature': {'mode': 'none'}}, Pipeline)
        output = pipeline.run(source)
        self.assertIn('local keep = "readable" -- keep', output)
        self.assertIn('local a=1;', output)
        self.assertEqual((3, 'readable'), Lua53(unpack_returned_tuples=True).execute(output))
        for version in ('5.1', '5.3'):
            pipeline = build_pipeline_from_config({'passes': ['semicolon'],
                'target': {'lua_version': version}}, Pipeline, show_header=False)
            output = pipeline.run('local a=1 local b=2 a=a+b return a')
            self.assertEqual(version == '5.3', ';;;' in output)

    def test_vm_output_integrity(self):
        source = 'local n=3 local function f(x) n=n+x return n end assert(f(4)==7) print("semicolon-ok")'
        for version in ('5.1', '5.3'):
            expected = execute(version, source)
            for backend in ('classic', 'karity', 'mov', 'bare'):
                with self.subTest(version=version, backend=backend):
                    random.seed(941)
                    vm = VMPass(target=TargetProfile(version, backend), vm_options={
                        'backend': backend, 'vm_count': 1, 'fake_handlers': False,
                        'mutate_handlers': False, 'junk_instructions': False,
                        'integrity_constants': True, 'integrity_constant_rate': 1.0,
                    }, vm_output_passes=['strip_info', 'minify', 'semicolon'])
                    output = vm.run(source)
                    self.assertEqual(expected, execute(version, output))
                    if version == '5.3':
                        self.assertIn(';;;', output)

    def test_finalizer_routing_and_packer(self):
        source = 'local n=4 print("routed-"..n)'
        for passes in (['vm', 'semicolon', 'minify'], ['pack', 'semicolon', 'minify']):
            random.seed(941)
            pipeline = build_pipeline_from_config({'passes': passes,
                'vm_options': {'backend': 'classic', 'vm_count': 1},
                'signature': {'mode': 'none'}}, Pipeline)
            self.assertEqual(1, len(pipeline._post_passes))
            output = pipeline.run(source)
            self.assertIn(';;;', output)
            self.assertEqual(execute('5.3', source), execute('5.3', output))
        # An implicit VM requested by source markers needs the same routing.
        pipeline = build_pipeline_from_config({'passes': ['semicolon', 'minify'],
            'signature': {'mode': 'none'}, 'vm_options': {'backend': 'classic', 'vm_count': 1}}, Pipeline)
        source = '--@VM_START\nlocal n=4 print("marked-"..n)\n--@VM_END\n'
        self.assertEqual(execute('5.3', source), execute('5.3', pipeline.run(source)))


if __name__ == '__main__':
    unittest.main()
