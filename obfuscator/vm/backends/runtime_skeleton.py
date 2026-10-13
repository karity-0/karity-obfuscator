"""Share audited, identical leaf utilities across generated VM executors.

This is not a general function deduplicator. Frame state, key schedules,
dispatch, graph banks and protection helpers are deliberately outside its
allowlist. Decoder/read_proto already live outside the executor template.
"""
from __future__ import annotations

import time

from ...names import NameAllocator
from ...passes.numeric_provenance import join_code
from ...passes.rename_ts import resolve_bindings
from ...passes.ts_utils import parse


_AUDITED = {
    '_rmix': 'local function _rmix(x) return _pmix(x) end',
    '_rslot': 'local function _rslot(slot) return ((slot&0x3FF)) end',
    '_acount': 'local function _acount(q) return q and (q.n or #q) or 0 end',
    '_aget': 'local function _aget(q,i) if q then return q[i] end; return nil end',
    '_carry': 'local function _carry(v) return v end',
}


def _signature(ctx, node):
    if node.type == 'comment':
        return None
    children = [n for c in node.children if (n := _signature(ctx,c)) is not None]
    if not children:
        return (node.type, ctx.plain_text(node))
    return (node.type, tuple(children))


_SIGNATURES = {}


def _declaration(binding):
    name = binding.nodes[0]
    parent = name.parent
    return parent if (parent.type=='function_declaration' and parent.children[0].type=='local'
                      and parent.child_by_field_name('name').id==name.id) else None


def _executor(node):
    parent=node.parent
    while parent is not None:
        if parent.type in {'function_definition','function_declaration'}:
            if parent.type!='function_definition':
                return None
            assignment=parent.parent
            while assignment is not None and assignment.type=='expression_list':
                assignment=assignment.parent
            if assignment is None or assignment.type!='assignment_statement':
                return None
            return assignment
        parent=parent.parent
    return None


def _render(source, edits):
    parts=[];end=0
    for a,b,text in sorted(edits,key=lambda e:(e[0],e[1])):
        if a<end:
            raise RuntimeError('overlapping shared runtime helper edits')
        parts.extend((source[end:a],text));end=b
    return join_code((*parts,source[end:]))


def share_runtime_helpers(source, candidates, *, ctx=None, bindings=None, removals=()):
    started=time.perf_counter()
    ctx=ctx or parse(source)
    if ctx.root.has_error:
        return source, {'skeleton_deferred':'unrecognized runtime syntax'}
    names=set(candidates) & _AUDITED.keys()
    if bindings is None:
        bindings,_,_,_,_=resolve_bindings(ctx,collect_literals=False,
            identifier_filter=lambda n:ctx.plain_text(n) in names | {'_pmix'})
    removed_ranges=[]
    for a,b in sorted(removals):
        if not removed_ranges or a>=removed_ranges[-1][1]:
            removed_ranges.append((a,b))
    edits=[(a,b,'\n') for a,b in removed_ranges]
    live=lambda n:not any(a<=ctx.cs(n)<b for a,b in removed_ranges)
    groups={name:[] for name in names}
    for binding in bindings:
        if binding.original not in groups:
            continue
        declaration=_declaration(binding)
        if declaration is not None and not live(declaration):
            continue
        owner=_executor(declaration) if declaration is not None else None
        if owner is None or owner.parent.type not in {'chunk', 'block'}:
            continue
        variables=next((n for n in owner.named_children if n.type=='variable_list'),None)
        owner_name=ctx.plain_text(variables) if variables is not None else ''
        if not (owner_name.startswith('_ex') and owner_name[3:].isdigit()):
            continue
        if binding.original not in _SIGNATURES:
            audit=parse(_AUDITED[binding.original])
            _SIGNATURES[binding.original]=_signature(audit,audit.root.named_children[0])
        if _signature(ctx,declaration)!=_SIGNATURES[binding.original]:
            continue
        if any(n.parent.type!='function_call' or n.parent.child_by_field_name('name').id!=n.id
               for n in binding.nodes[1:] if live(n)):
            # Preserve callback identity and indirect/protection references.
            continue
        groups[binding.original].append((binding,declaration,owner))
    groups={name:items for name,items in groups.items() if len(items)>1}
    # Executor clones are sibling assignments in one compiler-owned block.
    # An earlier insertion inside another do/if/function scope is not visible
    # to later executors. Preserve unfamiliar layouts rather than crossing it.
    scopes={owner.parent.id for items in groups.values() for _,_,owner in items}
    if len(scopes)>1:
        groups={}
    if not groups:
        return _render(source,edits), {'skeleton_shared_helpers':[], 'skeleton_declarations_removed':0,
                        'skeleton_analyzed':True,
                        'skeleton_analysis_seconds':time.perf_counter()-started}
    anchor=min(ctx.cs(owner) for items in groups.values() for _,_,owner in items)
    if '_rmix' in groups:
        # Its one external callee must resolve to the same immutable outer
        # mixer, not a VM-local shadow carrying a different key/state.
        references={n.id:b for b in bindings if b.original=='_pmix' for n in b.nodes}
        callees=[]
        for _,declaration,_ in groups['_rmix']:
            stack=[declaration]
            while stack:
                node=stack.pop();stack.extend(node.named_children)
                if node.type=='identifier' and ctx.plain_text(node)=='_pmix':
                    callees.append(references.get(node.id))
        target=callees[0] if callees else None
        declaration=_declaration(target) if target is not None else None
        if (declaration is None or ctx.cs(declaration)>=anchor
                or any(b is not target for b in callees)
                or any(n.parent.type!='function_call' or n.parent.child_by_field_name('name').id!=n.id
                       for n in target.nodes[1:] if live(n))):
            del groups['_rmix']
    allocator=NameAllocator.for_source(source)
    intro=[];removed=0
    for name,items in sorted(groups.items()):
        shared=allocator.allocate('shared_'+name)
        binding,declaration,_=items[0]
        a,b=ctx.cs(declaration),ctx.ce(declaration)+1
        node=binding.nodes[0]
        intro.extend((source[a:ctx.cs(node)],shared,source[ctx.ce(node)+1:b],'\n'))
        for binding,declaration,_ in items:
            edits.append((ctx.cs(declaration),ctx.ce(declaration)+1,''))
            edits.extend((ctx.cs(n),ctx.ce(n)+1,shared) for n in binding.nodes[1:] if live(n))
        removed+=len(items)-1
    if intro:
        edits.append((anchor,anchor,join_code(intro)))
    result=_render(source,edits)
    return result, {'skeleton_shared_helpers':sorted(groups),
                    'skeleton_declarations_removed':removed,
                    'skeleton_analyzed':True,
                    'skeleton_bytes_saved':len(_render(source,[(a,b,'\n') for a,b in removed_ranges]).encode())-len(result.encode()),
                    'skeleton_analysis_seconds':time.perf_counter()-started}
