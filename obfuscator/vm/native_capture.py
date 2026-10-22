"""Capture only referenced host APIs into one randomized, shared numeric bank."""
import random


def bind_native_calls(source, *, environment='_BN', bank='_BCore', forced=()):
    from ..passes.ts_utils import parse
    from ..passes.rename_ts import resolve_bindings
    from .runtime_security import _CORE_GLOBALS, _CORE_MEMBERS
    marker='--<<BARE_NATIVE_CAPTURE>>'
    boundary=source.index(marker)
    ctx=parse(source)
    free={}
    globals_=set(_CORE_GLOBALS)|{'unpack','getfenv','setfenv'}
    libraries=set(_CORE_MEMBERS)
    resolve_bindings(ctx,free_environments=free,collect_literals=False,
        identifier_filter=lambda n:ctx.plain_text(n) in globals_|libraries)
    accesses=[]
    paths={tuple(name.split('.')) for name in forced}
    stack=[ctx.root]
    while stack:
        node=stack.pop()
        path=None
        if ctx.cs(node)>=boundary:
            if node.type=='dot_index_expression':
                owner,key=node.named_children
                if owner.id in free and ctx.plain_text(owner) in libraries:
                    path=(ctx.plain_text(owner),ctx.plain_text(key))
            elif node.type=='identifier' and node.id in free and ctx.plain_text(node) in globals_:
                path=(ctx.plain_text(node),)
        if path:
            paths.add(path);accesses.append((node,path))
        else:stack.extend(node.named_children)
    ordered=sorted(paths)
    slots=dict(zip(ordered,random.sample(range(31,4096),len(ordered))))
    def read(path):
        value=environment
        for key in path:value=f'_BapiRead({value},{key!r})'
        return value
    entries=[f'[{slots[path]}]={read(path)}' for path in ordered]
    random.shuffle(entries)
    capture=('local _BapiRaw=rawget\n'
        'local function _BapiRead(t,k) local v=_BapiRaw(t,k);if v==nil then return t[k] end;return v end\n'
        'local '+bank+'={'+','.join(entries)+'}\n')
    for node,path in sorted(accesses,key=lambda x:x[0].start_byte,reverse=True):
        source=source[:ctx.cs(node)]+f'{bank}[{slots[path]}]'+source[ctx.ce(node)+1:]
    source=source.replace(marker,capture)
    bindings=[]
    for path in ordered:
        owner=read(path[:-1])
        bindings.append('{'+owner+','+repr(path[-1])+','+bank+'['+str(slots[path])+']}')
    return source.replace('__BARE_NATIVE_BINDINGS__','{'+','.join(bindings)+'}'),tuple('.'.join(p) for p in ordered)
