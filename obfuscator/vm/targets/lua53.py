"""Native Lua 5.3 frontend and output boundary."""
from .capabilities import Capability as C, TargetRequirements


class Lua53Target:
    lua_version = "5.3"
    library_dump_normalization = True
    requirements = TargetRequirements({C.NATIVE_BITOPS, C.INTEGER_ARITHMETIC, C.ENV_TABLE})
    capabilities = {"native_bitops": True, "env_model": "lexical", "integer_semantics": "int64",
                    "loader_api": "load", "unpack_api": "table.unpack"}

    def compile(self, script, toolchain):
        from ..backends.runtime_emitter import _compile
        return _compile(script, toolchain)

    def build_ir(self, bytecode):
        from ...parser import Lua53Parser
        from ..frontends.lua53 import build_semantic_ir
        return build_semantic_ir(Lua53Parser(bytecode).parse())

    def prepare_runtime(self, source, lowered):
        return source

    def lower_source(self, source):
        return source

    def bind_lines(self, source, context):
        from ..vm_variants import apply_line_state
        finalizer = None
        if "minify" in context.output_passes:
            from ...passes.minify import MinifyPass
            finalizer = MinifyPass().run
        return apply_line_state(source, context.output_prefix, finalizer=finalizer,
                                output_passes=context.output_passes)

    def dump_function(self, source, header, decoy_name, decoy_value, toolchain):
        from ..backends.runtime_emitter import _dump_function_stripped
        return _dump_function_stripped(source, header, decoy_name, decoy_value, toolchain)

    def wrap(self, source, decoy_name, decoy_value, vm_name, blob, tail):
        body = source[len("return "):]
        return (f'local {decoy_name}="{decoy_value}"local {vm_name}={body};'
                f'return ({vm_name}(1032,413,258,104,953,283,120))'
                f'({blob},"{tail}",{vm_name})')
