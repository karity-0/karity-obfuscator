"""Mixed literal spelling against native Lua 5.1/5.3 byte semantics."""
from pathlib import Path
import random
import re
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lupa.lua51 import LuaRuntime as Lua51
from lupa.lua53 import LuaRuntime as Lua53
from obfuscator import Pipeline, build_pipeline_from_config
from obfuscator.passes.string_encode import _encode_bytes, StringEncodePass
from obfuscator.passes.string_obfuscation import parse_lua_string
from obfuscator.passes.string_mosaic import StringMosaic, StringPolicy, lua_string
from obfuscator.passes.ts_utils import parse
from obfuscator.vm import VMPass
from obfuscator.vm.targets.profile import TargetProfile
from obfuscator.vm.output_emitter import emit_vm_literals
from run_blob_form_regression import execute


class StringEncodeTests(unittest.TestCase):
    def test_all_bytes_and_utf8_forms(self):
        samples = (b'', bytes(range(256)), b'\x00123\xff\xfe\x80\xc0\xaf\xed\xa0\x80\xf4\x90\x80\x80',
                   '한글🙂中文é\x00\n\t"\\'.encode(), b'\xc2\xe1\x80\xf0\x90\x80', b'1'*8192)
        for version, runtime_type in (('5.1', Lua51), ('5.3', Lua53)):
            lua = runtime_type(encoding=None)
            forms = (None, 'decimal', 'short', 'hex', 'unicode') if version == '5.3' else (None, 'decimal', 'short')
            for mode in forms:
                for seed in range(8):
                    for data in samples:
                        random.seed(seed)
                        encoded = _encode_bytes(data, version, mode=mode)
                        self.assertEqual(data, lua.eval(encoded.encode()), (version, mode, seed))
                        self.assertEqual(data, parse_lua_string(encoded, version))
                        self.assertNotIn('\n', encoded)
                        if version == '5.1':
                            self.assertIsNone(re.search(r'\\[xuz]', encoded))
            outputs = set()
            for seed in range(16):
                random.seed(seed); result = _encode_bytes('한글123🙂'.encode(), version)
                random.seed(seed); self.assertEqual(result, _encode_bytes('한글123🙂'.encode(), version))
                outputs.add(result)
            self.assertGreater(len(outputs), 1)
        with self.assertRaises(ValueError):
            _encode_bytes(b'abc', '5.1', mode='unicode')

    def test_mosaic_fragments_minification_and_contexts(self):
        from obfuscator.passes.minify import MinifyPass
        samples = (b'', bytes(range(256)), '한글🙂'.encode(), b'\n', b'\n\ntext',
                   b'  \t\ntext\r\nlast', b']', b']===', b']]' + b']=]' + b']==]' + b']===]' + b']====]',
                   b'-- comments '+bytes([34,39,92])+b' plus 123', b'Karity Obfuscator'*128)
        for version, runtime_type in (('5.1', Lua51), ('5.3', Lua53)):
            lua = runtime_type(encoding=None)
            shapes = set()
            for seed in range(64):
                for data in samples:
                    random.seed(seed)
                    generator = StringMosaic(StringPolicy(lua_version=version))
                    tokens = generator.fragments(data)
                    self.assertLessEqual(len(tokens), 4)
                    self.assertEqual(data, b''.join(parse_lua_string(t, version) for t in tokens))
                    shapes.update('long'+str(t.index('[', 1)-1) if t.startswith('[') else t[0] for t in tokens)
                    random.seed(seed)
                    expression = generator.expression(data)
                    for source in ('return ' + expression,
                                   'local function f(x,...)return x,select("#",...) end;return f ' + expression,
                                   'local t={[' + expression + ']=9};return ' + expression + ',t[' + expression + ']',
                                   'return ' + expression + '.."end"'):
                        expected = lua.execute(source.encode())
                        compact = MinifyPass().run(source)
                        self.assertEqual(expected, lua.execute(compact.encode()), (version,seed))
                    self.assertEqual(data, lua.eval(expression.encode()))
                    safe = lua_string(data, lua_version=version, enabled=True, line_safe=True)
                    self.assertNotIn('\n', safe)
                    self.assertEqual(data, lua.eval(safe.encode()))
                    literal = generator.expression(data, literal_only=True)
                    self.assertIn(literal[0], '\'"')
                    self.assertEqual(data, lua.eval(literal.encode()))
            self.assertTrue({'long0','long1','long2','long3','long4', '"', "'"} <= shapes, shapes)
            lua = runtime_type(encoding=None)
            for seed in range(128):
                random.seed(seed)
                output = build_pipeline_from_config({'passes':['string_encode','minify'],
                    'target':{'lua_version':version}}, Pipeline, show_header=False).run(
                    'local function f(x)return x end;local t={["key"]="value"};return f "a",t["key"],#"abcd","x".."y"')
                self.assertEqual((b'a',b'value',4,b'xy'),lua.execute(output.encode()))

    def test_mosaic_newlines_and_scoped_policy(self):
        from obfuscator.passes.minify import MinifyPass
        from obfuscator.passes.literal_mosaic import LiteralMosaic, use_mosaic, boundary
        lua = Lua53(encoding=None)
        outputs = []
        for seed in range(128):
            random.seed(seed)
            outputs.append(StringMosaic().expression(b'Karity Obfuscator'))
        self.assertTrue(any('\\z\n' in s or '\\z\r\n' in s for s in outputs))
        self.assertTrue(any('[[\n' in s or '[=[\n' in s or '[==[\n' in s for s in outputs))
        for output in outputs:
            self.assertEqual(b'Karity Obfuscator', lua.eval(MinifyPass().run(output).encode()))
        service = LiteralMosaic(['string_encode'],lua_version='5.1')
        with use_mosaic(service):
            self.assertTrue(service.strings().policy.enabled)
            self.assertEqual('5.1',service.strings().policy.lua_version)
            # Output activation does not leak from source stages.
            self.assertFalse(boundary([],lua_version='5.3').strings().policy.enabled)
        self.assertFalse(LiteralMosaic().strings().policy.enabled)
        self.assertEqual('"hello"', lua_string(b'hello'))

    def test_generated_strings_and_later_stages(self):
        from obfuscator.passes.literal_mosaic import LiteralMosaic, use_mosaic
        from obfuscator.passes.meme_expressions import MemeExpressionEngine
        from obfuscator.passes.meme_strings import MemeStringsPass
        from obfuscator.vm.output_emitter import _split_generated_numbers, StringLiteral
        from obfuscator.passes.function_obfuscation import _rand_str_lit
        # Generated strings participate even when String Encode already ran.
        with use_mosaic(LiteralMosaic(['string_encode','meme_strings'])):
            for seed in range(32):
                random.seed(seed)
                expression = MemeExpressionEngine._length('67 RLO\u202e quote"')
                self.assertEqual(len('67 RLO\u202e quote"'.encode()), Lua53().eval(expression))
                self.assertTrue(any(isinstance(part,StringLiteral) for part in _split_generated_numbers(expression)))
                literal = _rand_str_lit(6)
                self.assertEqual(6,len(Lua53().eval(literal)))
        source='return "hi",123'
        for stages in (['string_encode','meme_strings','number_obf'],
                       ['meme_strings','string_encode','number_obf'],
                       ['string_obf','meme_strings','string_encode','number_obf'],
                       ['string_encode','string_flow_obf','number_obf']):
            for seed in range(8):
                random.seed(seed)
                with patch.object(MemeStringsPass,'replacement_rate',1.0):
                    output,_=emit_vm_literals(source,stages)
                self.assertEqual(('hi',123),Lua53().execute(output),(stages,seed))
        for version,runtime in (('5.1',Lua51),('5.3',Lua53)):
            source='local function f(n)if n>2 then return n+1 end;return n*2 end;return f(2),f(3)'
            for seed in range(8):
                random.seed(seed)
                output=build_pipeline_from_config({'passes':['string_encode','function_obf','minify'],
                    'target':{'lua_version':version}},Pipeline,show_header=False).run(source)
                self.assertEqual((4,4),runtime().execute(output))

    def test_original_literal_semantics_and_decode_cache(self):
        literals = [r'"\00123\255\092\034"', '"quote\\\"\\n"', '[=[\r\nfirst\rsecond\n\rthird]=]',
                    '"first\\\r\nsecond"', "'literal'", '"한글🙂"', '"\\1٢"']
        for version, runtime_type in (('5.1', Lua51), ('5.3', Lua53)):
            lua = runtime_type(encoding=None)
            extra = [r'"\x41"', r'"\u{D800}"', r'"\z  \tA"']
            for literal in literals + extra:
                source = 'return ' + literal
                random.seed(44)
                transformed = build_pipeline_from_config({'passes': ['string_encode'],
                    'target': {'lua_version': version}}, Pipeline, show_header=False).run(source)
                self.assertEqual(lua.execute(source.encode()), lua.execute(transformed.encode()), (version, literal))
                self.assertNotIn('string.char', transformed)
                self.assertNotIn('function', transformed)
            source = 'return "repeat","repeat","repeat"'
            with patch('obfuscator.passes.string_encode.parse_lua_string', wraps=parse_lua_string) as decode:
                StringEncodePass(version).run(source, parse(source))
                self.assertEqual(1, decode.call_count)
        for literal in (r'"\x4"', r'"\999"', r'"\q"', r'"\u{}"', r'"\u{110000}"'):
            with self.assertRaises(ValueError):
                parse_lua_string(literal, '5.3')

    def test_selection_shorthand_and_pass_order(self):
        source = '-- comment "keep"\nlocal function f(s)return s end\nlocal t={["key"]=f "a"};return t["key"]'
        for names in (['string_encode','minify'], ['number_obf','string_encode','minify'],
                      ['string_encode','string_obf','minify'], ['string_obf','string_encode','minify'],
                      ['string_encode','string_flow_obf','minify'], ['string_flow_obf','string_encode','minify']):
            random.seed(5)
            output = build_pipeline_from_config({'passes': names}, Pipeline, show_header=False).run(source)
            self.assertEqual('a', Lua53().execute(output))
        source = '--@NO_OBF_START\nlocal readable="plain"\n--@NO_OBF_END\nreturn readable,"encoded"'
        output = build_pipeline_from_config({'passes':['string_encode']}, Pipeline, show_header=False).run(source)
        self.assertIn('"plain"', output); self.assertNotIn('"encoded"', output)
        output, details = emit_vm_literals('return "7"', ['string_encode','number_obf'])
        self.assertEqual('7', Lua53().execute(output))
        self.assertEqual(0, next(d['replacements'] for d in details if d['phase']=='vm_output:number_obf'))

    def test_all_backend_targets_and_late_line_strings(self):
        source = 'print("encode-runtime-ok")'
        for version in ('5.1','5.3'):
            expected = execute(version, source)
            for backend in ('classic','karity','mov','bare'):
                random.seed(881)
                seen = []
                original = StringMosaic.fragments
                def observe(generator, data, **kwargs):
                    seen.append(data)
                    return original(generator, data, **kwargs)
                with patch.object(StringMosaic, 'fragments', observe):
                    output = VMPass(target=TargetProfile(version,backend), vm_options={
                        'backend':backend,'vm_count':1,'fake_handlers':False,
                        'mutate_handlers':False,'junk_instructions':False,
                    }, vm_output_passes=['string_encode','strip_info','rename_obf','minify']).run(source)
                self.assertEqual(expected, execute(version, output), (version, backend))
                # The late reader reaches the policy even if this build happens
                # to choose plain quotes or long brackets for its pattern.
                self.assertIn(b'^.*:(%d+): ', seen)
                if version == '5.1':
                    self.assertIsNone(re.search(r'\\[xuz]', output))
        from obfuscator.passes.packer import PackerPass
        random.seed(881)
        output = PackerPass(packer_output_passes=['string_encode','strip_info','rename_obf','minify']).run(source)
        self.assertEqual(execute('5.3', source), execute('5.3', output))


if __name__ == '__main__':
    unittest.main()
