"""Numeric origin spans and a private transport through structural rewrites.

Provenance is carried on strings/edits, never inferred from variable names or
the shape of a number expression. Private comments serialize registered span
identities only while FunctionObf's existing textual emitters rearrange code;
they are removed before another pass or the Lua compiler sees the result.
"""
from __future__ import annotations

from bisect import bisect_right
from contextvars import ContextVar
import re


class CodeText(str):
    def __new__(cls, value, protected=(), reconstructions=(), origins=()):
        obj = super().__new__(cls, value)
        obj.protected = tuple(sorted(protected))
        obj._starts = tuple(a for a, _ in obj.protected)
        obj.reconstructions = tuple(sorted(reconstructions))
        obj._reconstruction_starts = tuple(a for a, _ in obj.reconstructions)
        obj.origins = tuple(sorted(origins))
        obj._origin_starts = tuple(a for a, _, _ in obj.origins)
        return obj

    def __getitem__(self, key):
        value = super().__getitem__(key)
        if not isinstance(key, slice):
            return value
        start, end, step = key.indices(len(self))
        if step != 1:
            return value
        first=max(0,bisect_right(self._starts,start)-1)
        last=bisect_right(self._starts,end)
        reconstruction_first = max(0, bisect_right(self._reconstruction_starts,start)-1)
        reconstruction_last = bisect_right(self._reconstruction_starts,end)
        origin_first = max(0,bisect_right(self._origin_starts,start)-1)
        origin_last = bisect_right(self._origin_starts,end)
        return CodeText(value, [(max(a, start)-start, min(b, end)-start)
                                for a,b in self.protected[first:last] if a < end and start < b],
                        [(max(a,start)-start,min(b,end)-start) for a,b in self.reconstructions[reconstruction_first:reconstruction_last]
                         if a < end and start < b],
                        [(max(a,start)-start,min(b,end)-start,origin)
                         for a,b,origin in self.origins[origin_first:origin_last] if a < end and start < b])


def number_origin(source, start, end, default='source_number'):
    if not isinstance(source, CodeText): return default
    i = bisect_right(source._origin_starts,start)-1
    if i >= 0 and end <= source.origins[i][1]: return source.origins[i][2]
    return default


def protected_number(source, start, end):
    if not isinstance(source, CodeText):
        return False
    i = bisect_right(source._starts, start)-1
    return i >= 0 and end <= source.protected[i][1]


def join_code(parts):
    text=[]; spans=[]; reconstruction_spans=[]; origins=[]; offset=0
    for part in parts:
        text.append(str(part))
        if isinstance(part, CodeText):
            spans.extend((a+offset,b+offset) for a,b in part.protected)
            reconstruction_spans.extend((a+offset,b+offset) for a,b in part.reconstructions)
            origins.extend((a+offset,b+offset,origin) for a,b,origin in part.origins)
        offset += len(part)
    result=''.join(text)
    merged=[]
    for a,b in reconstruction_spans:
        if merged and merged[-1][1] == a:
            merged[-1] = (merged[-1][0], b)
        else:
            merged.append((a,b))
    return CodeText(result,spans,merged,origins) if spans or merged or origins else result


CURRENT = ContextVar('function_numeric_transport',default=None)


class NumericTransport:
    def __init__(self, source, engine, *, max_chars=192, max_operations=3):
        self.prefix='KarityNumericOrigin'
        while self.prefix in source:
            self.prefix += '_'
        self.engine=engine
        self.max_chars=max_chars
        self.max_operations=max_operations
        self.records={}
        self.ends={}
        self.marker_pattern=re.compile(r'--\[\['+re.escape(self.prefix)+r':\d+:(?:begin|end)\]\]')
        self.serial=0
        self.generated=0
        self.source_count=0

    def clean(self, source):
        return self.marker_pattern.sub('', source)

    def generated_expression(self, value, *, hot=True):
        self.generated += 1
        from .literal_mosaic import ACTIVE
        mosaic = ACTIVE.get()
        fallback = lambda: self.engine.generated_int(value,hot=hot,max_chars=self.max_chars,
                                                   max_operations=self.max_operations)
        expression = (mosaic.number(value,context='function_constant',hot=hot,
            max_chars=self.max_chars,max_operations=self.max_operations,fallback=fallback)
            if mosaic is not None else fallback())
        return self.wrap(expression,True,'function_constant')

    def wrap(self, text, generated, origin='source_number'):
        self.serial += 1
        ident=f'{self.prefix}:{self.serial}'
        left=f'--[[{ident}:begin]]'
        right=f'--[[{ident}:end]]'
        self.records[left]=(right,generated,number_origin(text,0,len(text),origin))
        self.ends[right]=left
        # A preceding subtraction must not combine with the comment's '--'.
        # Parentheses keep both markers inside the expression's AST range.
        return '('+left+' '+str(text)+' '+right+')'

    def regions(self, source, *, ctx=None, nodes=None):
        # Only identities registered by this transport are recognized. Scanning
        # comments from the syntax tree avoids interpreting strings as markers.
        from .ts_utils import parse
        if ctx is None:
            ctx=parse(source)
        open_spans={}; regions=[]; markers=[]; self.region_origins={}
        traversal = ctx.walk() if nodes is None else nodes
        for node in sorted((n for n in traversal if n.type=='comment'),key=ctx.cs):
            token=ctx.text(node)
            if token in self.records:
                open_spans[token]=ctx.ce(node)+1
                markers.append((ctx.cs(node),ctx.ce(node)+1))
            elif token in self.ends:
                left=self.ends[token]
                if left not in open_spans:
                    raise RuntimeError('FunctionObf lost numeric origin start')
                a,b = open_spans.pop(left),ctx.cs(node)
                regions.append((a,b,self.records[left][1]))
                self.region_origins[a,b] = self.records[left][2]
                markers.append((ctx.cs(node),ctx.ce(node)+1))
            elif token.startswith('--[['+self.prefix+':'):
                raise RuntimeError('unregistered numeric provenance marker')
        if open_spans:
            raise RuntimeError('FunctionObf lost numeric origin end')
        return ctx,regions,markers

    def source_edits(self, ctx, function_node):
        # Use the existing AST and only this function subtree. Re-parsing an
        # entire VM source for every small helper makes this quadratic.
        nodes=[]
        stack=[function_node]
        while stack:
            node=stack.pop()
            nodes.append(node)
            stack.extend(node.children)
        _,regions,_=self.regions(ctx.script,ctx=ctx,nodes=nodes)
        edits=[]
        start,end=ctx.cs(function_node),ctx.ce(function_node)+1
        registered=CodeText(ctx.script,[(a,b) for a,b,_ in regions])
        protected=[]
        if isinstance(ctx.script,CodeText):
            first=max(0,bisect_right(ctx.script._starts,start)-1)
            last=bisect_right(ctx.script._starts,end)
            expression_spans={(ctx.cs(n),ctx.ce(n)+1) for n in nodes
                if n.type in ('number','parenthesized_expression','binary_expression','unary_expression')}
            for a,b in ctx.script.protected[first:last]:
                if start <= a and b <= end and not protected_number(registered,a,b):
                    fragment=ctx.script[a:b]
                    expression_start=a+len(fragment)-len(fragment.lstrip())
                    expression_end=a+len(fragment.rstrip())
                    if (expression_start,expression_end) not in expression_spans:
                        # A renderer/edit can clip metadata through punctuation.
                        # Such spans are not expressions; preserve their numeric
                        # leaves individually below rather than wrapping syntax.
                        continue
                    # Transport an already handled expression once, rather
                    # than serializing every numeric leaf inside it. This
                    # preserves its generation budget and structural origin.
                    protected.append((a,b))
                    edits.append((a,b,self.wrap(fragment,True,
                        number_origin(ctx.script,a,b))))
        covered=CodeText(ctx.script,[(a,b) for a,b,_ in regions]+protected)
        for node in nodes:
            if node.type!='number':continue
            a,b=ctx.cs(node),ctx.ce(node)+1
            if start <= a and b <= end and not protected_number(covered,a,b):
                edits.append((a,b,self.wrap(ctx.text(node),protected_number(ctx.script,a,b),
                    number_origin(ctx.script,a,b))))
        return edits

    def lower(self, body):
        ctx,regions,_=self.regions(body)
        covered=CodeText(body,[(a,b) for a,b,_ in regions])
        edits=[]
        for node in ctx.walk():
            if node.type!='number':continue
            a,b=ctx.cs(node),ctx.ce(node)+1
            if protected_number(covered,a,b):continue
            value=int(ctx.text(node),0) if ctx.text(node).lower().startswith('0x') else int(ctx.text(node))
            ancestor=node.parent
            hot=False
            while ancestor is not None:
                if ancestor.type in ('while_statement','repeat_statement','for_statement',
                                     'function_definition','function_declaration'):
                    hot=True; break
                ancestor=ancestor.parent
            edits.append((a,b,self.generated_expression(value,hot=hot)))
        parts=[]; pos=0
        for a,b,text in sorted(edits):
            parts.extend((body[pos:a],text)); pos=b
        parts.append(body[pos:])
        return ''.join(parts)

    def finish(self, source):
        _,regions,markers=self.regions(source)
        points=sorted(markers)
        ends=[b for _,b in points]
        removed=[0]
        for a,b in points:
            removed.append(removed[-1]+b-a)
        def shifted(pos):
            return pos-removed[bisect_right(ends,pos)]
        spans=[(shifted(a),shifted(b)) for a,b,generated in regions if generated]
        parts=[]; pos=0
        for a,b in points:
            parts.append(source[pos:a]); pos=b
        parts.append(source[pos:])
        self.source_count += sum(not generated for _,_,generated in regions)
        origins=[(shifted(a),shifted(b),self.region_origins[a,b]) for a,b,_ in regions]
        return CodeText(''.join(parts),spans,origins=origins)
