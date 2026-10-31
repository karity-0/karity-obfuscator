"""Bounded helper cross-checks with expected fingerprints outside hashed code.

Installed after ordinary output transforms, before API/source-line finalization.
Only pure generator-owned helpers are relocated; every bound execution reference
uses the checked bank. No user chunk or captured guest value is evaluated here.
"""
from dataclasses import dataclass
import re
import random
import tree_sitter as ts

from ..names import NameAllocator
from ..parser import Lua53Parser, Reader as ChunkReader
from ..passes.ts_utils import _LANG, parse
from ..passes.rename_ts import resolve_bindings, _apply_replacements_once


_CHECKPOINT_NODES = ts.Query(_LANG,
    '[(function_definition) (function_declaration) (while_statement)] @checkpoint')


def fingerprint(data):
    value = 0x811c9dc5
    for byte in data:
        value = ((value ^ byte) * 0x01000193) & 0xffffffff
    return value


@dataclass(frozen=True)
class HelperIntegrity:
    bank: str
    slots: tuple[int, ...]
    helpers: int
    periods: tuple[int, ...]
    checkpoints: int

    def manifest(self, source, dump):
        """Recreate child function dumps from the final stripped parent dump.

        Child prototypes retain their exact raw bytes, including floating-point
        constants and upvalue descriptors. Source AST order is checked against
        the compiled prototype tree rather than guessing from helper names.
        """
        ranges = {}
        class Parser(Lua53Parser):
            def _read_proto(parser):
                start = parser._r._pos
                proto = super()._read_proto()
                ranges[id(proto)] = dump[start:parser._r._pos]
                return proto
        if dump[12:17] not in (bytes((4,4,4,8,8)), bytes((4,8,4,8,8))):
            raise ValueError('helper integrity requires standard Lua 5.3 integer/double chunks')
        parser = Parser(dump)
        # The bundled Windows interpreter uses 32-bit size_t; compiler/library
        # consumers can use 64-bit size_t. Preserve either native dump layout.
        class DumpReader(ChunkReader):
            def read_size_t(reader):
                return int.from_bytes(reader.read_bytes(dump[13]), 'little')
        parser._r = DumpReader(dump)
        root = parser.parse()
        if parser._r.remaining():
            raise ValueError('helper integrity dump has an unsupported trailing section')
        ctx = parse(source)
        factory = next(node for node in ctx.root.named_children
                       if node.type == 'return_statement').named_children[0]
        if factory.type == 'expression_list':
            factory = factory.named_children[0]
        if factory.type != 'function_definition':
            raise ValueError('helper integrity factory boundary changed')
        targets = {}
        def children(node):
            found = []
            for child in node.named_children:
                if child.type in ('function_definition', 'function_declaration'):
                    found.append(child)
                else:
                    found.extend(children(child))
            return found
        def walk(node, proto):
            nodes = children(node)
            if len(nodes) != len(proto.protos):
                raise ValueError('helper integrity source/prototype correspondence changed')
            for child, compiled in zip(nodes, proto.protos):
                parent = child.parent
                if parent.type == 'assignment_statement':
                    variables = parent.named_children[0]
                    spelling = ctx.plain_text(variables)
                    for slot in self.slots:
                        if spelling == f'{self.bank}[{slot}]':
                            targets[slot] = compiled
                elif parent.type == 'expression_list' and parent.parent.type == 'assignment_statement':
                    variables = parent.parent.named_children[0]
                    spelling = ctx.plain_text(variables)
                    for slot in self.slots:
                        if spelling == f'{self.bank}[{slot}]':
                            targets[slot] = compiled
                walk(child, compiled)
        walk(factory, root)
        if set(targets) != set(self.slots):
            raise ValueError('helper integrity target assignment was changed')
        return ''.join(f'{fingerprint(dump[:33] + bytes((len(targets[slot].upvalues),)) + ranges[id(targets[slot])]):08x}'
                       for slot in self.slots)


def _candidates(ctx):
    bindings, *_ = resolve_bindings(ctx, collect_literals=False)
    candidates = []
    allowed = {'return_statement', 'expression_list', 'binary_expression',
               'unary_expression', 'parenthesized_expression', 'identifier', 'number'}
    for binding in bindings:
        first = binding.nodes[0]
        node = first.parent
        if (node.type != 'function_declaration' or node.children[0].type != 'local'
                or node.child_by_field_name('name').id != first.id or len(binding.nodes) < 2):
            continue
        if any(ref.parent.type != 'function_call'
               or ref.parent.child_by_field_name('name').id != ref.id
               for ref in binding.nodes[1:]):
            continue
        params = node.child_by_field_name('parameters')
        names = {ctx.plain_text(n) for n in params.named_children if n.type == 'identifier'}
        if not 1 <= len(names) <= 2 or len(names) != len(params.named_children):
            continue
        body = node.child_by_field_name('body')
        if len(body.named_children) != 1 or body.named_children[0].type != 'return_statement':
            continue
        pending = list(body.named_children)
        valid = True
        count = 0
        while pending:
            item = pending.pop(); count += 1
            if (item.type not in allowed or count > 32
                    or (item.type == 'identifier' and ctx.plain_text(item) not in names)):
                valid = False; break
            pending.extend(item.named_children)
        if valid:
            candidates.append((binding, node))
    candidates.sort(key=lambda item: ctx.cs(item[1]))
    return candidates[:3]


def preserve_function_targets(source):
    """Keep the existing pure relocation contract through FunctionObf only."""
    ctx=parse(source)
    candidates=_candidates(ctx)
    if len(candidates) < 2:
        raise ValueError('distributed integrity requires two eligible pure runtime helpers')
    edits=[]
    for _,node in candidates:
        start=ctx.cs(node.child_by_field_name('body'))
        edits.append((start,start-1,'--[[VM_INTEGRITY_HELPER]] '))
    return _apply_replacements_once(source,edits)


def install(source, *, library_dump=False, output_passes=()):
    ctx = parse(source)
    candidates=_candidates(ctx)
    if len(candidates) < 2:
        raise ValueError('distributed integrity requires two eligible pure runtime helpers')
    allocator = NameAllocator.for_source(source + '\ni f ok data h type string pcall error tonumber getmetatable')
    bank = allocator.allocate('checks')
    manifest = allocator.allocate('manifest')
    expected = allocator.allocate('expected')
    originals = allocator.allocate('originals')
    count = len(candidates)
    # Numeric bank keys do not carry security roles in the emitted output.
    keys = random.sample(range(31,4096), count*2+1)
    slots = tuple(keys[:-1])
    tick = keys[-1]
    periods = (257, 509, 1021)[:count]
    edits = []
    declarations = []
    for index, (binding, node) in enumerate(candidates):
        slot = slots[index]
        literal = re.sub(r'^local\s+function\s+[A-Za-z_]\w*', 'function', ctx.plain_text(node), count=1)
        declarations.append(f'{bank}[{slot}]={literal};')
        edits.append((ctx.cs(node), ctx.ce(node), ''))
        edits.extend((ctx.cs(ref), ctx.ce(ref), f'{bank}[{slot}]') for ref in binding.nodes[1:])
    root = next(n for n in ctx.walk() if n.type == 'function_definition')
    params = root.child_by_field_name('parameters')
    parameter = next((ctx.plain_text(n) for n in params.named_children if n.type == 'identifier'), None)
    if parameter is None:
        raise ValueError('distributed integrity manifest parameter is missing')
    dump = 'string.dump'
    if library_dump:
        from ..toolchain import LIBRARY_DUMP_FUNCTION
        dump = LIBRARY_DUMP_FUNCTION
    prefix = f'''local {manifest}={parameter};
if type({manifest})~="string" or #{manifest}~={8*len(slots)} then error(nil,0) end;
local {expected}={{}};for i=1,{len(slots)} do {expected}[i]=tonumber(string.sub({manifest},(i-1)*8+1,i*8),16);if not {expected}[i] then error(nil,0) end end;
local {bank}={{[{tick}]=0}};local {originals}={{}};
'''
    prefix += ''.join(declarations)
    for index in range(count):
        # Each checker covers a real operation and the next checker. Expected
        # values are external upvalue contents, never embedded in these bodies.
        peer = count + (index + 1) % count
        prefix += f'{bank}[{slots[count+index]}]=function() '
        prefix += (f'if getmetatable({bank})~=nil or getmetatable({expected})~=nil '
                   f'or getmetatable({originals})~=nil then error(nil,0) end;')
        for checked in (index, peer):
            prefix += (f'do local f={bank}[{slots[checked]}];'
                       f'if f~={originals}[{checked+1}] or type(f)~="function" then error(nil,0) end;'
                       f'local ok,data=pcall({dump},f,true);if not ok then error(nil,0) end;'
                       'local h=2166136261;for i=1,#data do h=((h~string.byte(data,i))*16777619)&4294967295 end;'
                       f'if h~={expected}[{checked+1}] then error(nil,0) end end;')
        prefix += 'end;'
    prefix += ''.join(f'{originals}[{i+1}]={bank}[{slot}];' for i,slot in enumerate(slots))
    prefix += ''.join(f'{bank}[{slot}]();' for slot in slots[count:])
    from .runtime_finalization import protect_fragment_strings
    prefix = protect_fragment_strings(prefix, output_passes, lua_version='5.3')
    schedule = f'{bank}[{tick}]=({bank}[{tick}]+1)%1048576;'
    schedule += ''.join(f'if {bank}[{tick}]%{period}==0 then {bank}[{slots[count+index]}]() end;'
                        for index, period in enumerate(periods))
    # Sparse checkpoints cover long-running interpreters and resumed executors.
    # Only generator-owned runtime code enters this service; guest code is data.
    captures = ts.QueryCursor(_CHECKPOINT_NODES).captures(ctx.root)
    checkpoints_nodes = (captures.get('checkpoint', []) if isinstance(captures, dict)
                         else [n for n, name in captures if name == 'checkpoint'])
    functions = [n for n in checkpoints_nodes if n.type in ('function_definition', 'function_declaration') and n.id != root.id]
    largest = max((ctx.ce(n)-ctx.cs(n) for n in functions), default=0)
    excluded = [(ctx.cs(n), ctx.ce(n)) for _, n in candidates]
    checkpoints = 0
    for node in checkpoints_nodes:
        if any(a <= ctx.cs(node) <= b for a, b in excluded):
            continue
        checkpoint = node.type == 'while_statement' and ctx.ce(node)-ctx.cs(node) >= 1024
        checkpoint |= node.type in ('function_definition', 'function_declaration') and node.id != root.id and ctx.ce(node)-ctx.cs(node) >= largest//2
        if checkpoint:
            body = node.child_by_field_name('body')
            if body is not None:
                edits.append((ctx.cs(body), ctx.cs(body)-1, schedule))
                checkpoints += 1
    body = root.child_by_field_name('body')
    edits.append((ctx.cs(body), ctx.cs(body)-1, prefix))
    # Insertions at the first declaration's offset precede its removal.
    edits.sort(key=lambda edit: (edit[0], edit[1]))
    return _apply_replacements_once(source, edits), HelperIntegrity(bank, slots, count, periods, checkpoints)
