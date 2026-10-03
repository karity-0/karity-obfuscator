"""Native Lua 5.3 frontend and output boundary."""
from .capabilities import Capability as C, TargetRequirements


class Lua53Target:
    lua_version = "5.3"
    user_number_model = "integer-binary64"
    library_dump_normalization = True
    requirements = TargetRequirements({C.NATIVE_BITOPS, C.INTEGER_ARITHMETIC, C.ENV_TABLE})
    capabilities = {"native_bitops": True, "env_model": "lexical", "integer_semantics": "int64",
                    "loader_api": "load", "unpack_api": "table.unpack"}

    def runtime_template(self, name):
        from pathlib import Path
        root=Path(__file__).parents[1]
        if name not in ('vm.lua','classic_exec.lua','mov_exec.lua'):
            raise ValueError(f'unknown runtime template: {name}')
        return (root/name if name=='vm.lua' else root/'runtimes'/name).read_text(encoding='utf-8')

    def direct_runtime_entry(self):
        return '_EX[proto.vm_id+1](proto,{env_box,environment=env_box.v},table.pack())'

    def value_packet_api(self):
        return 'table.pack', 'table.unpack'

    def runtime_entry_symbol(self):
        return 'run'

    def blob_decode_call(self):
        return 'from_base36(blob)'

    def graph_runtime_options(self):
        return {
            'preserve_native_numbers': False,
            'private_state_native': False,
            'native_graph_control': False,
        }

    def compile(self, script, toolchain):
        from ..backends.runtime_emitter import _compile
        return _compile(script, toolchain)

    def build_ir(self, bytecode):
        from ...parser import Lua53Parser
        from ..frontends.lua53 import build_semantic_ir
        return build_semantic_ir(Lua53Parser(bytecode).parse())

    def prepare_runtime(self, source, lowered):
        return source

    def apply_keystream(self, source):
        from ..vm_variants import apply_keystream
        return apply_keystream(source)

    def apply_tamper(self, source):
        from ..vm_variants import apply_tamper
        return apply_tamper(source)

    def finalize_runtime(self, source):
        return source

    def numeric_blob_decoder(self, source):
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
