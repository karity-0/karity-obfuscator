from __future__ import annotations

import argparse
import copy
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from main import apply_cli_overrides, build_pipeline
from obfuscator.registry import ConfigError, resolve_config_profile, validate_config
from obfuscator.toolchain import LuaToolchain, LIBRARY_DUMP_FUNCTION
from obfuscator.parser import Lua53Parser
from obfuscator.vm.vm_pass import _compile


class ToolchainTests(unittest.TestCase):
    def test_late_minifier_preserves_config_and_protected_stages(self):
        config = {"passes": ["vm", "minify", "pack", "minify"],
                  "vm_output_passes": ["minify"], "packer_output_passes": []}
        original = copy.deepcopy(config)
        for _ in range(2):
            pipeline = build_pipeline(config)
            vm, pack = pipeline._post_passes
            self.assertEqual(vm.vm_output_passes, ["minify"])
            self.assertEqual(pack.packer_output_passes, ["minify"])
        self.assertEqual(config, original)

    def test_profile_and_cli_precedence(self):
        config = resolve_config_profile({
            "lua_executable": "common", "luac_executable": "compiler",
            "profile": "dev", "profiles": {"dev": {"lua_executable": "profile"}},
        })
        args = argparse.Namespace(passes=None, vm_output_passes=None,
                                  packer_output_passes=None, vm_option=[],
                                  lua_executable="cli")
        result = apply_cli_overrides(config, args)
        self.assertEqual(result["lua_executable"], "cli")
        self.assertEqual(result["luac_executable"], "compiler")
        self.assertEqual(config["lua_executable"], "profile")

    def test_validation(self):
        for key in ("lua_executable", "luac_executable", "lua_library"):
            for value in (False, 12, [], {}, "", "  ", "bad\0path"):
                with self.subTest(key=key, value=value), self.assertRaises(ConfigError):
                    validate_config({key: value})
            validate_config({key: None})

    def test_lazy_resolution_and_isolation(self):
        with patch("obfuscator.toolchain._BIN", ROOT / "missing-bin"), patch(
            "obfuscator.toolchain.shutil.which", return_value=None
        ):
            pipeline = build_pipeline({"passes": [], "lua_executable": "missing-lua"})
            self.assertIn("print(42)", pipeline.run("print(42)"))
            other = build_pipeline({"passes": [], "lua_executable": "other-lua"})
            self.assertEqual(pipeline.toolchain.lua_executable, "missing-lua")
            self.assertEqual(other.toolchain.lua_executable, "other-lua")
            with self.assertRaisesRegex(FileNotFoundError, "lua_executable"):
                pipeline.toolchain.lua()
            with self.assertRaisesRegex(FileNotFoundError, "luac_executable"):
                LuaToolchain().luac()

    def test_path_search_and_library(self):
        with tempfile.TemporaryDirectory(prefix="lua tools ") as folder:
            path = Path(folder) / "custom library.dll"
            path.write_bytes(b"test")
            self.assertEqual(LuaToolchain(lua_library=str(path)).library(), str(path.resolve()))
            self.assertIsNone(LuaToolchain().library())
            with self.assertRaisesRegex(FileNotFoundError, "lua_library"):
                LuaToolchain(lua_library=str(path) + "-missing").library()
            with patch("obfuscator.toolchain.shutil.which", return_value=str(path)):
                self.assertEqual(LuaToolchain(lua_executable="custom-lua").lua(), str(path))
                with self.assertRaises(FileNotFoundError):
                    LuaToolchain(lua_executable=str(path) + "-missing").lua()
            with patch("obfuscator.toolchain._BIN", Path(folder)), patch(
                "obfuscator.toolchain.shutil.which", return_value=str(path)
            ):
                self.assertEqual(LuaToolchain().lua(), str(path))
                bundled = Path(folder) / ("lua.exe" if os.name == "nt" else "lua")
                bundled.write_bytes(b"test")
                self.assertEqual(LuaToolchain().lua(), str(bundled))

    def test_reject_incompatible_bytecode(self):
        def fake_compile(command, **kwargs):
            Path(command[2]).write_bytes(b"\x1bLua\x54\x00")
            return subprocess.CompletedProcess(command, 0)
        with patch.object(LuaToolchain, "luac", return_value="compiler"), patch(
            "obfuscator.vm.vm_pass.subprocess.run", side_effect=fake_compile
        ):
            with self.assertRaisesRegex(RuntimeError, "Lua 5.3 bytecode"):
                _compile("return 1")

    def test_external_tools_build_and_execute(self):
        default = LuaToolchain()
        with tempfile.TemporaryDirectory(prefix="lua external tools ") as folder:
            suffix = ".exe" if os.name == "nt" else ""
            lua = Path(folder) / ("custom lua" + suffix)
            luac = Path(folder) / ("custom compiler" + suffix)
            shutil.copy2(default.lua(), lua)
            shutil.copy2(default.luac(), luac)
            # Support distributions whose interpreter depends on adjacent DLLs.
            for dll in Path(default.lua()).parent.glob("*.dll"):
                shutil.copy2(dll, Path(folder) / dll.name)
            real_run = subprocess.run
            for passes in (["pack"], ["vm"], ["vm", "pack"],
                           ["vm", "minify"], ["pack", "minify"],
                           ["vm", "minify", "pack", "minify"]):
                config = {"passes": passes, "signature": {"mode": "none"},
                          "lua_executable": str(lua), "luac_executable": str(luac),
                          "vm_options": {"backend": "classic"}}
                with patch("subprocess.run", wraps=real_run) as calls:
                    output = build_pipeline(config).run("print(6 * 7)")
                commands = [call.args[0][0] for call in calls.call_args_list]
                self.assertIn(str(lua.resolve()), commands)
                if "vm" in passes:
                    self.assertIn(str(luac.resolve()), commands)
                else:
                    self.assertNotIn(str(luac.resolve()), commands)
                result = real_run([str(lua), "-"], input=output, text=True,
                                  capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), "42")


class LibraryFailureTests(unittest.TestCase):
    def test_missing_library_does_not_use_executables(self):
        for passes in (["vm"], ["pack"]):
            pipeline = build_pipeline({"passes": passes, "lua_library": "missing/library.dll"})
            with patch.object(LuaToolchain, "lua", side_effect=AssertionError("fallback")), patch.object(
                LuaToolchain, "luac", side_effect=AssertionError("fallback")
            ), self.assertRaisesRegex(FileNotFoundError, "lua_library"):
                pipeline.run("return 1")

    def test_bad_library_and_worker_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            library = Path(folder) / "bad library.dll"
            library.write_bytes(b"not a library")
            toolchain = LuaToolchain(lua_library=str(library))
            with self.assertRaisesRegex(RuntimeError, "cannot load lua_library"):
                toolchain.run_library("return 1", "compile")
            with patch("obfuscator.toolchain.subprocess.run", side_effect=subprocess.TimeoutExpired("worker", 120)):
                with self.assertRaisesRegex(RuntimeError, "timed out"):
                    toolchain.run_library("return 1")
            with patch("obfuscator.toolchain.subprocess.run", return_value=subprocess.CompletedProcess([], -1, b"", b"crash")):
                with self.assertRaisesRegex(RuntimeError, "crash"):
                    toolchain.run_library("return 1")


LIBRARY = os.environ.get("KARITY_TEST_LUA_LIBRARY", "")


def lua_literal(text):
    equals = "="
    while "]" + equals + "]" in text:
        equals += "="
    return "[" + equals + "[" + text + "]" + equals + "]"


@unittest.skipUnless(Path(LIBRARY).is_file(), "set KARITY_TEST_LUA_LIBRARY to test a Lua 5.3 library")
class LibraryIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tools = LuaToolchain(lua_library=LIBRARY, lua_executable="missing-lua", luac_executable="missing-luac")

    def test_gui_library_config_is_applied(self):
        import obfuscator_gui
        config = {"passes": ["vm", "minify"], "lua_library": LIBRARY,
                  "lua_executable": "missing-lua", "luac_executable": "missing-luac",
                  "vm_options": {"backend": "classic"}}
        with tempfile.TemporaryDirectory() as folder, patch.object(
            obfuscator_gui, "CONFIG_PATH", Path(folder) / "gui.json"
        ):
            api = obfuscator_gui.Api()
            api.save_config({"config": config})
            saved = __import__("json").loads(obfuscator_gui.CONFIG_PATH.read_text(encoding="utf-8"))
            self.assertEqual(saved["config"]["lua_library"], LIBRARY)
            result = api.run_obfuscation({"config": saved["config"], "script": "result=42"})
            self.assertTrue(result["ok"], result.get("error"))
            self.tools.run_library("assert(load(" + lua_literal(result["output"]) + "))(); assert(result==42)")

    def test_compile_without_executing_source(self):
        bytecode = _compile('error("must not execute"); return function(x) return x+1 end', self.tools)
        proto = Lua53Parser(bytecode).parse()
        self.assertTrue(proto.protos)
        self.assertEqual(bytecode[:6], b"\x1bLua\x53\x00")

    def test_lua_errors(self):
        for script, operation, message in (("local =", "compile", "lua_library"),
                                            ('error("runtime-test")', "execute", "runtime-test"),
                                            ("return 1", "dump", "did not return a function")):
            with self.subTest(operation=operation), self.assertRaisesRegex(RuntimeError, message):
                self.tools.run_library(script, operation)

    def test_deterministic_dump_and_restore_mode(self):
        wrapper = 'return function(x) return x .. "end" end'
        expected = self.tools.run_library(wrapper, "dump")
        self.assertEqual(expected, self.tools.run_library(wrapper, "dump"))
        expected_literal = '"' + ''.join('\\%03d' % b for b in expected) + '"'
        self.tools.run_library(
            "local stable=" + LIBRARY_DUMP_FUNCTION + ";"
            "local f=assert(load(" + lua_literal(wrapper) + "))();"
            "local before=string.byte(string.dump(f,true),6);"
            "assert(stable(f,true)==" + expected_literal + ");"
            "assert(string.byte(string.dump(f,true),6)==before);"
            "assert(stable(f,true)==" + expected_literal + ")"
        )

    def test_normalized_constants_nested_protos_and_debug_info(self):
        source = '''local outer=17
return function(...)
 local args={...}
 local values={nil,true,false,0,8,-19,0x7fffffffffffffff,0x8000000000000000,3.25,"short",LONG}
 return function(i) return values[i],outer,args end
end'''.replace('LONG', '"' + 'long constant ' * 30 + '"')
        expected = self.tools.run_library(source, "compile")
        literal = '"' + ''.join('\\%03d' % b for b in expected) + '"'
        self.tools.run_library(
            "local stable=" + LIBRARY_DUMP_FUNCTION + ";"
            "local f=assert(load(" + lua_literal(source) + ",'=karity'));"
            "for i=1,8 do assert(stable(f,false)==" + literal + ") end"
        )

    def test_build_and_execute_backends(self):
        source = """local function outer(n)
local x=n
return function(...) local t={...}; for _,v in ipairs(t) do x=x+v end; return x end
end
local f=outer(10)
result=f(2,3)+f(4)
text="?? test"
"""
        for backend, passes in (("classic", ["pack"]), ("classic", ["vm"]),
                                ("classic", ["vm", "pack"]), ("karity", ["vm", "pack"]),
                                ("mov", ["vm", "pack"]), ("classic", ["vm", "minify"]),
                                ("karity", ["vm", "minify"]), ("mov", ["vm", "minify"]),
                                ("classic", ["vm", "minify", "pack", "minify"])):
            with self.subTest(backend=backend, passes=passes):
                pipeline = build_pipeline({
                    "passes": passes, "lua_library": LIBRARY,
                    "lua_executable": "missing-lua", "luac_executable": "missing-luac",
                    "signature": {"mode": "custom", "custom": "DLL test\nsecond line"},
                    "vm_options": {"backend": backend},
                    "vm_output_passes": [] if "minify" in passes else ["minify"],
                    "packer_output_passes": [] if "minify" in passes else ["minify"],
                })
                output = pipeline.run(source)
                self.tools.run_library("assert(load(" + lua_literal(output) + "))();"
                                       'assert(result==34); assert(text=="?? test")')


if __name__ == "__main__":
    unittest.main()
