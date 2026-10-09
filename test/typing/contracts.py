"""Checked examples of configuration keys and preserved generic return types."""
from typing import assert_type

from obfuscator.config_types import BackendPolicy, ObfuscatorConfig, VMOptions
from obfuscator.data_types import LuaConstant
from obfuscator.passes import RemoveCommentPass
from obfuscator.pipeline import Pipeline
from obfuscator.registry import build_pipeline_from_config
from obfuscator.vm.backends import get_backend
from obfuscator.vm.backends.base import BackendContext
from obfuscator.vm.ir.model import IRValue


class CustomPipeline(Pipeline):
    def custom_operation(self) -> str:
        return "custom"


config: ObfuscatorConfig = {
    "passes": ["remove_comment"],
    "vm_options": {"backend": "karity", "vm_count": 2, "junk_rate": 0.2,
                   "requirements": {"handler_aliases": "required"}},
    "function_obf_options": {"boundary_mode": "mixed", "nested": True},
    "target": {"lua_version": "5.3", "environment": "standalone"},
    "signature": {"mode": "none"},
    "selection_modes": {"vm": "marked"},
    "profiles": {"dev": {"passes": ["minify"]}},
}
pipeline = build_pipeline_from_config(config, CustomPipeline)
assert_type(pipeline, CustomPipeline)
assert_type(pipeline.add(RemoveCommentPass()), CustomPipeline)
assert_type(pipeline.custom_operation(), str)

constants: list[LuaConstant] = [None, True, 1, 2.5, "text", b"\xff"]
value = IRValue("constant", "constant", 0, literal=constants[0])
assert_type(value.literal, LuaConstant)
options: VMOptions = config["vm_options"]
context = BackendContext(options)
assert_type(context.options, VMOptions)
assert_type(get_backend("karity")._policy(options), BackendPolicy)
