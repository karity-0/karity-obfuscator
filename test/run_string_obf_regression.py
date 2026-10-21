"""Exercise reconstruction data flow, expression semantics and pass layering."""
from __future__ import annotations

import json
import random
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from lupa.lua53 import LuaRuntime

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from obfuscator import Pipeline, build_pipeline_from_config
from obfuscator.passes import string_reconstruction as reconstruction
from obfuscator.passes.function_obfuscation import FunctionObfuscationPass
from obfuscator.passes.number_obfuscation import NumberObfuscationPass
from obfuscator.passes.rename_obfuscation import RenameObfuscationPass
from obfuscator.passes.string_obfuscation import parse_lua_string, _encode_flow as _encode
from obfuscator.passes.string_flow_obfuscation import StringFlowObfuscationPass as StringObfuscationPass
from obfuscator.passes.ts_utils import parse
from obfuscator.vm.output_emitter import emit_vm_literals
from lua_runtime import lua_executable


def execute(source: str) -> tuple[int, bytes, bytes]:
    result = subprocess.run([lua_executable(), "-"], input=source.encode(),
                            capture_output=True, timeout=60)
    return result.returncode, result.stdout.replace(b"\r\n", b"\n"), result.stderr


class StringReconstructionTests(unittest.TestCase):
    def test_all_bytes_lengths_strategies_and_seeds(self):
        lua = LuaRuntime(encoding=None)
        sizes = (0, 1, 2, 3, 11, 16, 17, 31, 32, 33, 256, 1025, 8192)
        for strategy in ("numeric", "partial", "mixed"):
            for seed in range(16):
                random.seed(seed)
                for size in sizes:
                    data = bytes((i * 37 + seed) % 256 for i in range(size))
                    choose = random.choice

                    def force_strategy(items):
                        return strategy if items == ("numeric", "partial", "mixed") else choose(items)

                    with patch.object(reconstruction.random, "choice", side_effect=force_strategy):
                        code = _encode(data)
                    self.assertEqual(lua.eval(code.encode()), data, (strategy, seed, size))

    def test_operations_in_runtime(self):
        lua = LuaRuntime()
        for operation in reconstruction._OPERATIONS:
            for seed in range(32):
                rng = random.Random(seed)
                step = reconstruction._Step(0, operation, rng.randrange(1, 1 << 24),
                                            rng.randrange(1, 256), rng.randrange(1, 24))
                shared, expected = rng.randrange(1 << 24), rng.randrange(1 << 24)
                value = step.inverse(expected, step.key(shared))
                code = f"local x={value};local s={shared};local k,t;" + ";".join(step.emit("x", "k", "s", "t"))
                self.assertEqual(lua.execute(code + ";return x"), expected, (operation, seed))

    def test_expression_positions_and_literal_bytes(self):
        source = r'''
local function results() return "same", "same", 9 end
local function count(...) return select("#", ...), ... end
local a,b,c=results()
local t={"element", ["key"]="value"}
local f=function(...) return count("arg", ...) end
local trace={}
local function side(n) trace[#trace+1]=n;return n end
local unused=false and "never" or "fallback"
local repeated=0
for i=1,4 do if "condition"=="condition" then repeated=repeated+1 end end
local string,table=string,table
local _ENV=_ENV
print(a,b,c,t["key"],#t,f(1,2))
print(side(1), "between", side(2), unused, repeated)
print(#({results()}))
io.write "shorthand"
io.write("\000\255\128", "한글🙂", "\u{1F642}", "\x41\065", [=[
long
text]=])
'''
        # Exercise Lua's CR/CRLF normalization as well as quoted continuation.
        source += ('\nio.write([=[\r\nfirst\rsecond\n\rthird]=], "line\\\r\ncontinued", '
                   '[=[\n\rfirst\rsecond]=], "\\u{D800}")')
        expected = execute(source)
        self.assertEqual(expected[0], 0, expected[2])
        for seed in range(12):
            random.seed(seed)
            output = Pipeline(show_header=False).add(StringObfuscationPass()).run(source)
            self.assertEqual(execute(output), expected, seed)
            self.assertFalse(parse(output).root.has_error)

    def test_newline_decoding_without_windows_text_input_translation(self):
        lua = LuaRuntime(encoding=None)
        # Windows stdin translates CRLF before Lua sees the source. A binary
        # Lupa input compares decoding against Lua's actual lexer instead.
        for newlines in ("\r", "\n", "\r\n", "\n\r", "\r\n\r", "\n\r\n"):
            for literal in (f"[=[{newlines}first{newlines}second]=]",
                            '"first\\' + newlines[:2] + 'second"' if len(newlines) <= 2 else '"\\u{D800}"'):
                self.assertEqual(parse_lua_string(literal), lua.eval(literal.encode()), repr(literal))

    def test_macro_activation_selection_and_no_obf(self):
        source = 'local plain="visible";local a=STRING_FLOW_OBF("hidden");return plain,a'
        for passes in ([], ["string_flow_obf"]):
            pipeline = build_pipeline_from_config({"passes": passes, "signature": {"mode": "none"},
                                                  "selection_modes": {"string_flow_obf": "marked"}}, Pipeline)
            output = pipeline.run(source)
            self.assertIn('"visible"', output)
            self.assertNotIn('"hidden"', output)
            self.assertNotIn("STRING_FLOW_OBF", output)
            self.assertEqual(LuaRuntime().execute(output), ("visible", "hidden"))
        excluded = '--@NO_OBF_START\nlocal s=STRING_FLOW_OBF("keep")\n--@NO_OBF_END\nreturn s'
        pipeline = build_pipeline_from_config({"passes": ["string_flow_obf"], "signature": {"mode": "none"}}, Pipeline)
        self.assertEqual(LuaRuntime().execute(pipeline.run(excluded)), "keep")

    def test_unique_occurrences_seed_and_bounded_graph(self):
        random.seed(12)
        first = _encode(b"same")
        second = _encode(b"same")
        self.assertNotEqual(first, second)
        random.seed(12)
        self.assertEqual(_encode(b"same"), first)
        for seed in range(24):
            for length in (1, 8, 16, 17, 32):
                random.seed(seed)
                tree = parse("return " + _encode(bytes(range(length))))
                statements = sum(n.type in {"assignment_statement", "return_statement", "for_statement"}
                                 for n in tree.walk())
                self.assertLess(statements, 200, (seed, length))
        sizes = []
        for length in (512, 8192, 65536):
            random.seed(45)
            code = _encode(bytes(i % 256 for i in range(length)))
            tree = parse("return " + code)
            self.assertFalse(tree.root.has_error)
            local_count = sum(n.type == "variable_declaration" for n in tree.walk())
            statements = sum(n.type in {"assignment_statement", "return_statement", "for_statement"}
                             for n in tree.walk())
            self.assertLess(local_count, 24)
            self.assertLess(statements, 100)
            self.assertLess(len(code), length * 30 + 12000)
            sizes.append(statements)
        self.assertLess(max(sizes) - min(sizes), 16)

    def test_number_cff_rename_and_vm_emitter_layering(self):
        source = 'local s="layered bytes\\000\\255";print(s,#s);print(string.char(65,66))'
        expected = execute(source)
        for seed in range(6):
            random.seed(seed)
            function_pass = FunctionObfuscationPass(boundary_mode="cff", inline=False, wrapper=False)
            pipeline = (Pipeline(show_header=False).add(StringObfuscationPass())
                        .add(NumberObfuscationPass()).add(function_pass).add(RenameObfuscationPass()))
            output = pipeline.run(source)
            self.assertEqual(execute(output), expected, seed)
            self.assertGreater(function_pass.last_transformed_count, 0)
            random.seed(seed)
            output, details = emit_vm_literals(source, ["string_flow_obf", "number_obf"])
            self.assertEqual(execute(output), expected, seed)
            self.assertEqual(sum(d.get("parse_count", 0) for d in details), 1)
            numbers = NumberObfuscationPass().run("return string.char(65,66)", parse("return string.char(65,66)"))
            self.assertEqual(len(numbers), 2)
        # No decoding exemption remains in the emitter's source capture path.
        output, details = emit_vm_literals("print(string.char(65,66))", ["number_obf"])
        self.assertEqual(next(d["replacements"] for d in details if d["phase"] == "vm_output:number_obf"), 2)
        self.assertEqual(execute(output), (0, b"AB\n", b""))

    def test_long_program_with_cff_and_vm_backends(self):
        source = 'local s="' + 'abcdef' * 20 + '";print(#s,s)'
        expected = execute(source)
        for seed in range(3):
            random.seed(seed)
            pipeline = (Pipeline(show_header=False).add(StringObfuscationPass())
                        .add(NumberObfuscationPass())
                        .add(FunctionObfuscationPass(boundary_mode="cff", inline=False, wrapper=False))
                        .add(RenameObfuscationPass()))
            self.assertEqual(execute(pipeline.run(source)), expected, seed)
        for backend in ("classic", "karity", "mov"):
            random.seed(24)
            pipeline = build_pipeline_from_config({
                "passes": ["vm"], "vm_output_passes": ["minify"],
                "signature": {"mode": "none"},
                "vm_options": {"backend": backend, "dispatcher_type": "ifelseif",
                               "blob_form": "string", "vm_count": 1, "fake_handlers": False,
                               "mutate_handlers": False, "junk_instructions": False, "junk_rate": 0.0,
                               "graph_execution_rate": 0.0, "cross_instruction_rate": 0.0,
                               "runtime_polymorphism_rate": 0.0},
            }, Pipeline)
            output = pipeline.run('local s=STRING_FLOW_OBF("a\\000b");print(s,#s)')
            self.assertEqual(execute(output), (0, b"a\0b\t3\n", b""), backend)

    def test_profile_source_order_and_composition(self):
        profiles = json.loads((ROOT / "config.example.json").read_text(encoding="utf-8"))["profiles"]
        source = 'local function f(n) return "hi", n+1 end;print(f(41))'
        for name in ("high", "max"):
            options = profiles[name].copy()
            passes = options["passes"]
            self.assertLess(passes.index("string_flow_obf"), passes.index("function_obf"))
            options["passes"] = [p for p in passes if p not in {"vm", "pack"}]
            options["signature"] = {"mode": "none"}
            random.seed(321)
            output = build_pipeline_from_config(options, Pipeline).run(source)
            self.assertEqual(execute(output), (0, b"hi\t42\n", b""), name)


class CompactStringTests(unittest.TestCase):
    def test_all_byte_operations_and_large_literals(self):
        from obfuscator.passes.string_obfuscation import _BYTE_OPERATIONS, _byte_expression, _encode as compact
        lua = LuaRuntime(encoding=None)
        for operation in _BYTE_OPERATIONS:
            for value in range(256):
                random.seed(value)
                self.assertEqual(value, lua.eval(_byte_expression(value, operation).encode()))
        for length in (0, 1, 16, 17, 64, 65, 1024, 8192, 65536):
            random.seed(54)
            data = bytes(i % 256 for i in range(length))
            code = compact(data)
            self.assertEqual(data, lua.eval(code.encode()))
            self.assertNotIn('function', code)
            self.assertEqual(length > 64, 'table.concat' in code)

    def test_markers_options_and_strategy_precedence(self):
        from obfuscator.registry import PASS_REGISTRY, get_pass_contexts
        from obfuscator.passes.string_obfuscation import StringObfuscationPass as Compact
        from obfuscator.passes.string_flow_obfuscation import StringFlowObfuscationPass
        self.assertIs(PASS_REGISTRY['string_obf']['cls'], Compact)
        self.assertIs(PASS_REGISTRY['string_flow_obf']['cls'], StringFlowObfuscationPass)
        self.assertEqual(3, len(get_pass_contexts('string_flow_obf')))
        for other, macro, flow in (('string_obf', 'STRING_FLOW_OBF', True),
                                    ('string_flow_obf', 'STRING_OBF', False)):
            config = {'passes': [other], 'signature': {'mode': 'none'}}
            source = 'return ' + macro + '("hidden")'
            output = build_pipeline_from_config(config, Pipeline).run(source)
            self.assertNotIn('"hidden"', output)
            self.assertEqual(flow, 'function' in output)
            self.assertEqual('hidden', LuaRuntime().execute(output))
        source = '--@NO_OBF_START\nlocal s="readable"\n--@NO_OBF_END\nreturn s'
        output = build_pipeline_from_config({'passes': ['string_obf'], 'signature': {'mode': 'none'}}, Pipeline).run(source)
        self.assertIn('"readable"', output)
        tuned = build_pipeline_from_config({'passes': ['string_flow_obf'],
            'string_flow_obf_options': {'steps_min': 4, 'steps_max': 5},
            'signature': {'mode': 'none'}}, Pipeline).run('return "tuned"')
        self.assertEqual('tuned', LuaRuntime().execute(tuned))

    def test_expression_semantics_and_mosaic(self):
        from obfuscator.profiling import Profiler
        source = '''local function packet(...)return select('#',...),... end
local skipped=false and "not evaluated"
local t={["key"]="한글\\000\\255"}
local function f(...)return packet("a",...),t["key"] end
print(f(nil,false,nil));io.write [=[long
text]=]'''
        expected = execute(source)
        for name in ('string_obf', 'string_flow_obf'):
            config = {'passes': [name, 'number_obf', 'meme_strings', 'minify'],
                'signature': {'mode': 'none'}, 'literal_mosaic': {'diversity_metrics': True,
                    'generated_meme_rate': 1.0}}
            random.seed(44)
            profiler = Profiler()
            output = build_pipeline_from_config(config, Pipeline).run(source, profiler=profiler)
            self.assertEqual(expected, execute(output))
            metrics = profiler.as_dict()['literal_mosaic']
            self.assertGreater(metrics['strategies'].get('meme_generated', 0), 0)
            numeric = next(r for r in profiler.records if r.name == 'NumberObfuscationPass')
            self.assertGreater(numeric.details[0]['protected_generated_numbers'], 0)

    def test_both_strategies_in_all_vm_outputs_and_packer(self):
        from run_blob_form_regression import execute as run_vm
        from obfuscator.vm import VMPass
        from obfuscator.vm.targets.profile import TargetProfile
        from obfuscator.passes.packer import _obfuscate_packer_output
        source = 'print("split-strings-ok")'
        for name in ('string_obf', 'string_flow_obf'):
            for backend in ('classic', 'karity', 'mov', 'bare'):
                random.seed(330)
                output = VMPass(target=TargetProfile('5.3', backend), vm_options={
                    'backend': backend, 'vm_count': 1, 'fake_handlers': False,
                    'mutate_handlers': False, 'junk_instructions': False,
                }, vm_output_passes=[name, 'minify']).run(source)
                self.assertEqual(run_vm('5.3', source), run_vm('5.3', output))
                self.assertNotIn('string.char', output)
            output = _obfuscate_packer_output(source, [name, 'minify'])
            self.assertEqual(execute(source), execute(output))


if __name__ == "__main__":
    unittest.main()
