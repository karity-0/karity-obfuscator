"""Lua 5.1 target adapter for the shared backend runtime representations."""
from pathlib import Path
import re
from .lua51_syntax import translate
from .capabilities import Capability as C, TargetRequirements
from .dump51 import normalize_dump
from .tools51 import run as run_tool

_ROOT = Path(__file__).parent
_HELPER = "_target51"


class Lua51Target:
    lua_version = "5.1"
    library_dump_normalization = False
    requirements = TargetRequirements({C.GETFENV, C.TEXT_CHUNK_LOAD})
    capabilities = {"native_bitops": False, "env_model": "function", "integer_semantics": "binary64",
                    "loader_api": "loadstring", "unpack_api": "unpack"}

    def compile(self, script, toolchain=None):
        bytecode = run_tool(script, "compile", toolchain)
        normalize_dump(bytecode)  # Reject non-binary64 or nonstandard compiler ABIs.
        return bytecode

    def build_ir(self, bytecode):
        from ...parser51 import Lua51Parser
        from ..frontends.lua51 import build_semantic_ir
        return build_semantic_ir(Lua51Parser(bytecode).parse())

    def prepare_runtime(self, source, lowered):
        source=source.replace("local env_box={v=_ENV}", "local env_box={v=getfenv(1)}")
        source=source.replace("{env_box,environment=env_box.v}", "{env_box,environment=self_func}")
        source=source.replace("local function get_environment(upvals) return upvals.environment end",
                              "local function get_environment(upvals) return getfenv(upvals.environment) end")
        source=source.replace("values.environment=get_environment(parent)",
                              "setfenv(fn,get_environment(parent));values.environment=fn")
        source=source.replace("local function _source_value(v) return v end",
                              'local function _source_value(v) if math.type(v)=="integer" then return v+0.0 end;return v end')
        source=source.replace("local function rset(i,v)",
                              "local function rset(i,v) if i<proto.max_stack_size then v=_source_value(v) end")
        source=source.replace("_mdigits[_ma]=d; _mstrings[_ma]=nil; regs[_ma]=nil",
                              "_mdigits[_ma]=d; _mstrings[_ma]=nil; regs[_ma]=nil; "
                              "if _ma<proto.max_stack_size then rset(_ma,_source_value(rget(_ma))) end")
        source=source.replace("local function _source_value(v)",
                              "local function _source_call(fn,upvals,...) return _target51.invoke(fn,upvals.environment,...) end\n"
                              "local function _source_value(v)")
        source=source.replace("fn(table.unpack(ca,1,ca_n))", "_source_call(fn,upvals,table.unpack(ca,1,ca_n))")
        source=source.replace("fn(table.unpack(args,1,count))", "_source_call(fn,upvals,table.unpack(args,1,count))")
        return source

    def lower_source(self, source):
        integer = (_ROOT / "int64.lua").read_text(encoding="utf-8")
        normalizer = (_ROOT / "dump51.lua").read_text(encoding="utf-8")
        shim = (_ROOT / "lua51_shim.lua").read_text(encoding="utf-8")
        prelude = ("local I=(function()\n" + integer + "\nend)()\n"
                   "local N=(function()\n" + normalizer + "\nend)()\n"
                   "local _target51=(function()\n" + shim + "\nend)()\n"
                   "local math,string,table,type,tostring,tonumber,select,error,rawget,rawset="
                   "_target51.math,_target51.string,_target51.table,_target51.type,_target51.tostring,"
                   "_target51.tonumber,_target51.select,_target51.error,_target51.rawget,_target51.rawset\nlocal debug,getfenv=_target51.debug,_target51.getfenv\n")
        # Output passes may localize runtime APIs through lexical _ENV.
        # Source function environments still use the native getfenv API.
        prelude += ("local _ENV=setmetatable({_target51=_target51,math=math,string=string,table=table,"
                    "type=type,tostring=tostring,tonumber=tonumber,select=select,error=error,"
                    "rawget=rawget,rawset=rawset,debug=debug,getfenv=getfenv},{__index=_G})\n")
        translated = translate(source, _HELPER)
        anchor = re.match(r"return\s+function\s*\([^)]*\)", translated)
        if anchor:
            # Include the integer/API/dump helpers in the self-hashed function.
            prelude += "\n--[[TARGET51_PRELUDE_END]]\n"
            return translated[:anchor.end()] + "\n" + prelude + translated[anchor.end():]
        return prelude + translated

    def bind_lines(self, source, context):
        from ..vm_variants import apply_line_state
        result, state, lines = apply_line_state(source, "", finalizer=lambda code: translate(code, _HELPER),
                                               output_passes=(), insertion_anchor="--[[TARGET51_PRELUDE_END]]")
        return result.replace("--[[TARGET51_PRELUDE_END]]", ""), state, lines

    def dump_function(self, source, header, decoy_name, decoy_value, toolchain):
        return normalize_dump(run_tool(source, "dump", toolchain))

    def wrap(self, source, decoy_name, decoy_value, vm_name, blob, tail):
        literal='"'+''.join(f"\\{byte:03d}" for byte in source.encode("utf-8"))+'"'
        return (f'local {vm_name}=setfenv(assert(loadstring({literal},"=KarityVM51")),getfenv(1))();'
                f'return ({vm_name}(1032,413,258,104,953,283,120))({blob},"{tail}",{vm_name})')
