"""Lua compiler measurements and conservative CFF scheduling limits.

Both Lua 5.1 and 5.3 use 18-bit Bx with a signed bias of 131071. Reserve
three quarters of that distance for lexical pooling and subsequent literal
passes. This is a per-control-flow limit, not a source-file byte threshold.
"""
from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass
from threading import local

from .numeric_provenance import CURRENT, CodeText, protected_number


MAX_JUMP = ((1 << 18)-1)//2
# NumberObf: depth<=3 (7 arithmetic nodes), or <=8 float-chain terms plus
# conversion/bitwise wrappers. Meme: <=2 arithmetic levels with string lengths.
# Include loads/temporaries rather than assuming compiler constant folding.
POST_LITERAL_COST = 2 * (8 + 7) * (2 ** 2 + 1)
_runtimes = local()


@dataclass(frozen=True)
class CostPolicy:
    lua_version: str = '5.3'
    max_jump: int = MAX_JUMP//4
    max_instructions: int = MAX_JUMP//2
    compact_pass: bool = False
    avoid_helper_captures: bool = False


POLICY = ContextVar('function_cost_policy',default=CostPolicy())


def measure(body, *, version=None):
    version = version or POLICY.get().lua_version
    runtimes = getattr(_runtimes,'compilers',{})
    if version not in runtimes:
        if version == '5.1':
            from lupa.lua51 import LuaRuntime
            loader='loadstring'
        else:
            from lupa.lua53 import LuaRuntime
            loader='load'
        lua=LuaRuntime(encoding=None)
        compiler=lua.eval(('function(s) local f,e='+loader+'(s); '
                          'if not f then return nil,e end return string.dump(f) end').encode())
        runtimes[version]=(lua,compiler)
        _runtimes.compilers=runtimes
    transport=CURRENT.get()
    source=transport.clean(body) if transport is not None else body
    result=runtimes[version][1](('return function(...)\n'+source+'\nend').encode())
    if isinstance(result,tuple):
        return {'error':result[1].decode('utf-8',errors='replace')}
    if version == '5.1':
        from ..parser51 import parse_bytes
        jump_ops=(22,31,32)
    else:
        from ..parser import parse_bytes
        jump_ops=(30,39,40,42)
    root=parse_bytes(result).protos[0]
    def row(proto,path):
        jumps=[(abs((w >> 14)-MAX_JUMP),pc) for pc,w in enumerate(proto.code) if w & 63 in jump_ops]
        distance, pc = max(jumps,default=(0,0))
        return {'path':path,'instructions':len(proto.code),
                'max_jump':distance, 'jump_pc':pc, 'jump_line':proto.lineinfo[pc]-1 if proto.lineinfo else None,
                'source_lines':[proto.line_defined-1,proto.last_line_defined-1],
                'stack':proto.max_stack_size,'upvalues':len(proto.upvalues)}
    rows=[]
    def walk(proto,path):
        rows.append(row(proto,path))
        for i,child in enumerate(proto.protos):walk(child,path+'.'+str(i))
    walk(root,'0')
    return {'functions':rows,'instructions':len(root.code),
            'max_jump':rows[0]['max_jump'],'total_instructions':sum(r['instructions'] for r in rows)}


def source_number_count(body):
    transport=CURRENT.get()
    if transport is None:
        return 0
    ctx,regions,_=transport.regions(body)
    source_regions=CodeText(body,[(a,b) for a,b,generated in regions if not generated])
    total=0
    for node in ctx.walk():
        if node.type!='number':continue
        # Ignore child prototypes: their jumps are measured independently.
        ancestor=node.parent
        nested=False
        while ancestor is not None:
            if ancestor.type in ('function_definition','function_declaration'):
                nested=True; break
            ancestor=ancestor.parent
        if not nested and protected_number(source_regions,ctx.cs(node),ctx.ce(node)+1):
            total += 1
    return total


def projected_cost(body, report=None):
    report=measure(body) if report is None else report
    if 'error' in report:
        return MAX_JUMP+1
    return report['instructions'] + source_number_count(body)*POST_LITERAL_COST


def has_owner_return(body):
    from .ts_utils import parse
    ctx=parse(body)
    stack=list(ctx.root.named_children)
    while stack:
        node=stack.pop()
        if node.type in ('function_definition','function_declaration'):
            continue
        if node.type=='return_statement':
            return True
        stack.extend(node.named_children)
    return False
