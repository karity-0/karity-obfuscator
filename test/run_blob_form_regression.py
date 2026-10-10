"""Unicode cipher storage, shared planning, CLI and native VM round trips."""
from pathlib import Path
import random
import subprocess
import sys
import tempfile
from typing import get_args
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lupa.lua51 import LuaRuntime as Lua51
from lupa.lua53 import LuaRuntime as Lua53
from lua_runtime import lua_executable
from obfuscator.config_types import BlobForm
from obfuscator.registry import VALID_BLOB_FORMS, VM_OPTION_DOCS, validate_config
from obfuscator.toolchain import LuaToolchain
from obfuscator.vm.blob_formats import BLOB_FORMS, unicode_blob_codec
from obfuscator.vm.protection import ProtectionPlanner, protect
from obfuscator.vm.targets.lua53 import Lua53Target
from obfuscator.vm.targets.profile import TargetProfile
from obfuscator.vm.vm_pass import VMPass
from obfuscator_gui import _vm_option_meta


OPTIONS = {
    "fake_handlers": False, "mutate_handlers": False, "junk_instructions": False,
    "graph_execution_rate": 0.0, "cross_instruction_rate": 0.0,
    "runtime_polymorphism_rate": 0.0, "block_variant_rate": 0.0,
    "helper_diversity_rate": 0.0, "semantic_diversity_rate": 0.0,
    "integrity_constants": True, "integrity_constant_rate": 1.0, "vm_count": 2,
}
SOURCE = '''local text=string.char(0,1,127,128,254,255).."中文😀"
local function make(n)
 return function(...) n=n+select("#",...); return n,text,... end
end
local f=make(4)
local n,copy,a,b=f(false,nil)
assert(n==6 and copy==text and a==false and b==nil)
assert(#copy==16 and string.byte(copy,1)==0 and string.byte(copy,6)==255)
assert(select("#",f("x",nil))==4)
print("blob-form-ok")
'''


def execute(version, source):
    if version == "5.1":
        runtime = Lua51(encoding=None)
        printed = []
        runtime.globals()[b"print"] = lambda value: printed.append(value)
        runtime.execute(source.encode("utf-8"))
        return printed
    result = subprocess.run([lua_executable(), "-"], input=source.encode("utf-8"),
                            capture_output=True, timeout=90)
    if result.returncode:
        raise AssertionError(result.stderr.decode(errors="replace"))
    return result.stdout


class BlobForms(unittest.TestCase):
    def test_codec_all_bytes_and_buffer_boundaries(self):
        for form in ("emoji", "chinese"):
            random.seed(9370)
            codec = unicode_blob_codec(form)
            self.assertEqual(256, len(set(codec.alphabet)))
            self.assertTrue(all(len(symbol.encode()) == codec.width for symbol in codec.alphabet))
            for runtime_type in (Lua51, Lua53):
                runtime = runtime_type(encoding=None)
                for size in (0, 1, 3, 256, 4095, 4096, 4097, 8449):
                    with self.subTest(form=form, runtime=runtime_type, size=size):
                        data = (bytes(range(256)) * ((size + 255) // 256))[:size]
                        literal = codec.literal(data)
                        self.assertEqual(size * codec.width, len(literal[1:-1].encode()))
                        source = "local blob=" + literal + ";return " + codec.decoder()
                        self.assertEqual(data, runtime.execute(source.encode()))

    def test_alphabets_change_between_builds(self):
        for form in ("emoji", "chinese"):
            random.seed(1)
            first = unicode_blob_codec(form)
            random.seed(2)
            second = unicode_blob_codec(form)
            self.assertNotEqual(first.alphabet, second.alphabet)
        with self.assertRaises(ValueError):
            unicode_blob_codec("string")

    def test_configuration_and_gui_share_forms(self):
        choices = set(BLOB_FORMS) | {"random"}
        self.assertEqual(choices, VALID_BLOB_FORMS)
        self.assertEqual(choices, set(get_args(BlobForm.__value__)))
        self.assertEqual(choices, {value for value, _ in VM_OPTION_DOCS["blob_form"]["values"]})
        metadata = next(item for item in _vm_option_meta() if item["name"] == "blob_form")
        self.assertEqual(choices, {item["value"] for item in metadata["values"]})
        self.assertEqual({"classic", "karity", "mov"}, set(metadata["supported_backends"]))
        for form in choices:
            for backend in ("classic", "karity", "mov"):
                validate_config({"passes": ["vm"], "vm_options": {"backend": backend, "blob_form": form}})

    def test_random_planning_includes_unicode_forms(self):
        target = Lua53Target()
        ir = target.build_ir(target.compile("print(42)", LuaToolchain()))
        selected = set()
        for seed in range(64):
            random.seed(seed)
            planner = ProtectionPlanner({"blob_form": "random"})
            plan = planner.build(ir)
            protect(ir, plan)
            self.assertEqual(plan.dump(), planner.build(ir).dump())
            selected.add(plan.functions[ir.root.id]["blob_form"])
        self.assertEqual(set(BLOB_FORMS), selected)

    def test_both_forms_on_every_backend_and_target(self):
        prefix = "-- Unicode storage 中文 😀\n-- integrity prefix\n"
        for version in ("5.1", "5.3"):
            expected = execute(version, SOURCE)
            for backend in ("classic", "karity", "mov"):
                for form in ("emoji", "chinese"):
                    with self.subTest(version=version, backend=backend, form=form):
                        random.seed(9451)
                        vm = VMPass(target=TargetProfile(version, backend),
                                    vm_options={**OPTIONS, "blob_form": form},
                                    vm_output_passes=["rename_obf", "minify"], output_prefix=prefix)
                        output = vm.run(SOURCE)
                        self.assertFalse(output.isascii())
                        self.assertEqual(form, vm.last_protection_plan.functions[
                            vm.last_source_ir.root.id]["blob_form"])
                        self.assertEqual(expected, execute(version, prefix + output))

    def test_unicode_decoder_with_literal_output_passes(self):
        expected = execute("5.3", SOURCE)
        for form in ("emoji", "chinese"):
            with self.subTest(form=form):
                random.seed(9541)
                output = VMPass(vm_options={**OPTIONS, "backend": "classic", "blob_form": form},
                                vm_output_passes=["string_obf", "number_obf", "rename_obf", "minify"]).run(SOURCE)
                self.assertEqual(expected, execute("5.3", output))

    def test_existing_forms_with_prefix_on_lua51(self):
        source = 'print("prefix-ok")'
        prefix = "-- Unicode signature 中文 😀\n-- second line\n"
        for form in ("string", "table", "numeric"):
            with self.subTest(form=form):
                random.seed(9511)
                vm = VMPass(target=TargetProfile("5.1", "classic"),
                            vm_options={**OPTIONS, "blob_form": form}, output_prefix=prefix,
                            vm_output_passes=["rename_obf", "minify"])
                self.assertEqual(execute("5.1", source), execute("5.1", prefix + vm.run(source)))

    def test_cli_forms_with_and_without_packing(self):
        expected = execute("5.3", SOURCE)
        with tempfile.TemporaryDirectory(prefix="karity-unicode-blob-") as folder:
            source = Path(folder) / "source.lua"
            output = Path(folder) / "output.lua"
            source.write_text(SOURCE, encoding="utf-8")
            for form in ("emoji", "chinese"):
                for packed in (False, True):
                    with self.subTest(form=form, packed=packed):
                        command = [sys.executable, str(ROOT / "main.py"), str(source), "-o", str(output),
                                   "--config", str(ROOT / "config.example.json"), "--profile", "dev",
                                   "--passes", "vm,pack" if packed else "vm", "--seed", "9641",
                                   "--vm-output-passes", "rename_obf,minify",
                                   "--packer-output-passes", "minify", "--vm-option", "backend=classic"]
                        for key, value in {**OPTIONS, "blob_form": form}.items():
                            command.extend(("--vm-option", key + "=" + str(value).lower()))
                        result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=90)
                        self.assertEqual(0, result.returncode, result.stderr.decode(errors="replace"))
                        self.assertEqual(expected, execute("5.3", output.read_text(encoding="utf-8")))


if __name__ == "__main__":
    unittest.main()
