"""Wire the MOV executor to the existing Lua host semantics and blob wrapper."""
from pathlib import Path

from .ir import Op
from .layout import VMKit


def build_runtime(classic: str, kits: list[VMKit]) -> str:
    template = (Path(__file__).parents[1] / "runtimes" / "mov_exec.lua").read_text(encoding="utf-8")

    def section(start: str, end: str) -> str:
        return template.split(f"--<<{start}>>", 1)[1].split(f"--<<{end}>>", 1)[0]

    # Reuse host handlers, not the classic fetch/dispatch loop. They are reached
    # only by explicit HOST records (including non-integer arithmetic fallback).
    from ..vm_obfuscation import _find_chain
    a, b = _find_chain(classic)
    handlers = classic[a:b]
    # A VM tail call returns a frame transition, consumed by the outer
    # trampoline. Native functions still use Lua's normal call semantics.
    handlers = handlers.replace(
        "local res = table.pack(fn(table.unpack(ca,1,ca_n)))",
        """local target=_mov_closures[fn]
            if target then ca.n=ca_n; return {mov_tail=target,args=ca} end
            local res = table.pack(fn(table.unpack(ca,1,ca_n)))""",
    )
    handlers = handlers.replace("elseif op==30 then pc=pc+sBx",
                                'elseif op==30 then error("unexpected MOV host jump")')
    # SETLIST's extra word is data, not an independently executed instruction.
    handlers = handlers.replace(
        "local base=(C-1)*50; local cnt=B==0 and (top-A) or B",
        """if C==0 then
                local ei=code[pc]~_ksm(pc); pc=pc+1
                C=(((ei>>_SH_A)&0xFF)<<18)|(((ei>>_SH_B)&0x1FF)<<9)|((ei>>_SH_C)&0x1FF)
            end
            local base=(C-1)*50; local cnt=B==0 and (top-A) or B""",
    )
    loop = section("LOOP", "END").replace("--<<HOST_HANDLERS>>", handlers)
    loop_start = classic.index("    for i in setmetatable(")
    loop_end = classic.index("    return {r={},n=0}", b)
    runtime = classic[:loop_start] + section("FRAME", "LOOP") + loop + classic[loop_end:]
    reg_start = runtime.index("    --<<RGET>>")
    reg_end = runtime.index("    --<<ENDRSET>>") + len("    --<<ENDRSET>>")
    runtime = runtime[:reg_start] + section("REGISTERS", "FRAME") + runtime[reg_end:]
    runtime = runtime.replace("get=function() return regs[slot] end", "get=function() return rget(slot) end")
    runtime = runtime.replace("set=function(v) regs[slot]=v end", "set=function(v) rset(slot,v) end")
    runtime = runtime.replace(
        """return function(...)
            local w=_EX[sub.vm_id+1](sub, new_uv, table.pack(...))
            return table.unpack(w.r, 1, w.n)
        end""",
        """local fn=function(...)
            local w=_EX[sub.vm_id+1](sub, new_uv, table.pack(...))
            return table.unpack(w.r, 1, w.n)
        end
        _mov_closures[fn]={sub,new_uv}
        return fn""",
    )
    start = runtime.index("--<<EXEC>>") + len("--<<EXEC>>")
    end = runtime.index("--<<ENDEXEC>>")
    body = runtime[start:end]
    definitions = []
    for vm_id, kit in enumerate(kits, 1):
        definition = body.replace("exec = function", f"_mov_dispatch[{vm_id}] = function", 1)
        for op in Op:
            definition = definition.replace(f"__MOV_{op.name}__", str(kit.opcodes[op]))
        definitions.append(definition)
    runtime = runtime[:start] + "\n".join(definitions) + runtime[end:]
    runtime = runtime.replace("local exec, _EX", "local _EX; local _mov_dispatch={}", 1)
    runtime = runtime.replace("_EX={exec}", """local function _mov_invoke(proto,upvals,args)
        while true do
            local w=_mov_dispatch[proto.vm_id+1](proto,upvals,args)
            if not w.mov_tail then return w end
            proto=w.mov_tail[1]; upvals=w.mov_tail[2]; args=w.args
        end
    end
    _EX={}
    for i=1,""" + str(len(kits)) + " do _EX[i]=_mov_invoke end")
    runtime = section("SHARED", "REGISTERS") + runtime
    return runtime
