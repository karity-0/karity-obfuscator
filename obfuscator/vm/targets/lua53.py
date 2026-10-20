"""Native Lua 5.3 frontend and output boundary."""
import re
from .capabilities import Capability as C, TargetRequirements


class Lua53Target:
    lua_version = "5.3"
    user_number_model = "integer-binary64"
    library_dump_normalization = True
    requirements = TargetRequirements({C.NATIVE_BITOPS, C.INTEGER_ARITHMETIC, C.ENV_TABLE})
    capabilities = {"native_bitops": True, "env_model": "lexical", "integer_semantics": "int64",
                    "loader_api": "load", "unpack_api": "table.unpack"}

    def function_cost_policy(self):
        from ...passes.function_costs import CostPolicy
        return CostPolicy(lua_version='5.3')

    def runtime_template(self, name):
        from pathlib import Path
        root=Path(__file__).parents[1]
        if name not in ('vm.lua','classic_exec.lua','mov_exec.lua'):
            raise ValueError(f'unknown runtime template: {name}')
        return (root/name if name=='vm.lua' else root/'runtimes'/name).read_text(encoding='utf-8')

    def direct_runtime_entry(self):
        return '_EX[proto.vm_id+1](proto,{env_box,environment=env_box.v},_root_args)'

    def value_packet_api(self):
        return 'table.pack', 'table.unpack'

    def security_runtime_options(self):
        return {'native_unpack': 'table.unpack', 'globals_name': '_ENV', 'native_table_pack': True}

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
        passes = context.output_passes if context is not None else ()
        prefix = context.output_prefix if context is not None else ''
        finalizer = None
        if "minify" in passes:
            from ...passes.minify import MinifyPass
            finalizer = MinifyPass().run
        anchor = '--[[ENVIRONMENT_READY]]' if '--[[ENVIRONMENT_READY]]' in source else 'return function(...)'
        result, state, lines = apply_line_state(source, prefix, finalizer=finalizer,
                                output_passes=passes,
                                insertion_anchor=anchor,
                                environment_source=getattr(self, 'line_environment', None),
                                qualify_globals=getattr(self, "isolate_runtime_globals", False))
        return result.replace('--[[ENVIRONMENT_READY]]', ''), state, lines

    def dump_function(self, source, header, toolchain):
        from ..backends.runtime_emitter import _dump_function_stripped
        return _dump_function_stripped(source, header, toolchain)

    def wrap(self, source, vm_name, blob, *, forward_args=False):
        returned = re.match(r'\Areturn\b', source)
        if returned is None:
            raise ValueError('Lua 5.3 VM source must return its runtime function')
        body = source[returned.end():].lstrip()
        arguments=",{n=select('#',...),...}" if forward_args else ''
        return (f'local {vm_name}={body};'
                f'return ({vm_name}(1032,413,258,104,953,283,120))'
                f'({blob},{vm_name}{arguments})')
