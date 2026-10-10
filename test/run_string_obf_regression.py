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
from obfuscator.passes.string_obfuscation import StringObfuscationPass, _encode, parse_lua_string
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
        source = 'local plain="visible";local a=STRING_OBF("hidden");return plain,a'
        for passes in ([], ["string_obf"]):
            pipeline = build_pipeline_from_config({"passes": passes, "signature": {"mode": "none"},
                                                  "selection_modes": {"string_obf": "marked"}}, Pipeline)
            output = pipeline.run(source)
            self.assertIn('"visible"', output)
            self.assertNotIn('"hidden"', output)
            self.assertNotIn("STRING_OBF", output)
            self.assertEqual(LuaRuntime().execute(output), ("visible", "hidden"))
        excluded = '-- @NO_OBF_START\nlocal s=STRING_OBF("keep")\n-- @NO_OBF_END\nreturn s'
        pipeline = build_pipeline_from_config({"passes": ["string_obf"], "signature": {"mode": "none"}}, Pipeline)
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
            output, details = emit_vm_literals(source, ["string_obf", "number_obf"])
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
            output = pipeline.run('local s=STRING_OBF("a\\000b");print(s,#s)')
            self.assertEqual(execute(output), (0, b"a\0b\t3\n", b""), backend)

    def test_profile_source_order_and_composition(self):
        profiles = json.loads((ROOT / "config.example.json").read_text(encoding="utf-8"))["profiles"]
        source = 'local function f(n) return "hi", n+1 end;print(f(41))'
        for name in ("high", "max"):
            options = profiles[name].copy()
            passes = options["passes"]
            self.assertLess(passes.index("string_obf"), passes.index("function_obf"))
            options["passes"] = [p for p in passes if p not in {"vm", "pack"}]
            options["signature"] = {"mode": "none"}
            random.seed(321)
            output = build_pipeline_from_config(options, Pipeline).run(source)
            self.assertEqual(execute(output), (0, b"hi\t42\n", b""), name)


if __name__ == "__main__":
    unittest.main()
