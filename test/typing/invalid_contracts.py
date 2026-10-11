"""Intentional static errors: run_typing_regression.py must observe each category."""
from obfuscator.config_types import ObfuscatorConfig, VMOptions
from obfuscator.data_types import LuaConstant
from obfuscator.registry import build_pipeline_from_config

misspelled: VMOptions = {"junk_raet": 0.2}
wrong_value: VMOptions = {"vm_count": "two"}
wrong_target: ObfuscatorConfig = {"target": {"lua_version": "5.4"}}
wrong_nested_key: ObfuscatorConfig = {"function_obf_options": {"nestd": True}}
wrong_constant: LuaConstant = object()
wrong_pipeline = build_pipeline_from_config({}, str)
