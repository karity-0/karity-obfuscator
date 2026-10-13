"""Conservative constructor reshaping and bounded table reconstruction."""
from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections import Counter
import math
import random
import time

from ..names import NameAllocator
from .base import BasePass, Replacement
from .numeric_provenance import CodeText, join_code
from .number_expressions import NumberExpressionEngine
from .string_obfuscation import parse_lua_string


def validate_options(options):
    if not isinstance(options, dict) or set(options) - {'mode', 'max_fields', 'string_keys'}:
        raise ValueError('table_obf_options accepts mode, max_fields, and string_keys')
    if options.get('mode', 'mixed') not in ('mixed', 'shuffle', 'reconstruct'):
        raise ValueError('table_obf_options.mode must be mixed, shuffle, or reconstruct')
    limit = options.get('max_fields', 16)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 64:
        raise ValueError('table_obf_options.max_fields must be between 1 and 64')
    if not isinstance(options.get('string_keys', False), bool):
        raise ValueError('table_obf_options.string_keys must be boolean')


def _fields(node):
    return [c for c in node.named_children if c.type == 'field']


def _parse_field(field):
    children = field.children
    eq = next((i for i, c in enumerate(children) if c.type == '='), None)
    if eq is None:
        return None, children[0], 'array'
    return children[1] if children[0].type == '[' else children[0], children[eq+1], (
        'bracket' if children[0].type == '[' else 'record')


def _literal_key(tree, key, kind, index):
    if kind == 'array':
        return ('number', index)
    if kind == 'record':
        return ('string', tree.text(key).encode('utf-8'))
    if key.type == 'string':
        return ('string', parse_lua_string(tree.text(key)))
    if key.type in {'true', 'false'}:
        return ('boolean', key.type == 'true')
    if key.type == 'number':
        text = tree.text(key).lower()
        try:
            value = (float.fromhex(text) if text.startswith('0x') else float(text))
            if math.isfinite(value) and abs(value) < 2**53:
                return ('number', value)
        except ValueError:
            pass
    return None


class TableObfuscationPass(BasePass):
    parser = 'treesitter'

    def __init__(self, **options):
        validate_options(options)
        self.options = options

    def run(self, script, tree):
        started = time.perf_counter()
        from .literal_mosaic import ACTIVE
        mosaic = ACTIVE.get()
        if self.options.get('string_keys') and mosaic is not None and mosaic.policy.lua_version == '5.1':
            raise ValueError('table_obf_options.string_keys requires Lua 5.3 StringObf support')
        tables = [n for n in tree.walk() if n.type == 'table_constructor' and _fields(n)]
        if not tables:
            self.last_profile = [{'phase': 'table_generation', 'elapsed': time.perf_counter()-started,
                                  'tables_seen': 0}]
            return []
        from .rename_ts import resolve_bindings
        # Resolve actual lexical reads once. Free globals may invoke _ENV's
        # __index; identifier spelling alone is not a purity proof.
        bindings, _, _, _, _ = resolve_bindings(tree, collect_literals=False)
        locals_ = {n.id: id(binding) for binding in bindings for n in binding.nodes if binding.original != '_ENV'}
        tables.sort(key=tree.cs, reverse=True)
        allocator = NameAllocator.for_source(script, seed=random.getrandbits(64))
        numbers = NumberExpressionEngine()
        safe = {}
        captures = {}
        fields = {}
        # Postorder facts cover unselected nested constructors too. No repeated
        # recursion over the same nested tables and no Python recursion limit.
        stack = [(node, False) for node in tables]
        while stack:
            node, visited = stack.pop()
            if node.id in safe:
                continue
            if not visited:
                stack.append((node, True))
                if node.type == 'table_constructor':
                    fields[node.id] = [_parse_field(f) for f in _fields(node)]
                    stack.extend((value, False) for _, value, _ in fields[node.id])
                continue
            if node.type == 'table_constructor':
                parsed = fields[node.id]
                seen, valid, index = set(), True, 0
                for key, value, kind in parsed:
                    index += kind == 'array'
                    identity = _literal_key(tree, key, kind, index)
                    if identity is None or identity in seen or not safe.get(value.id, False):
                        valid = False
                    seen.add(identity)
                safe[node.id] = valid
                captures[node.id] = set().union(*(captures.get(value.id, set()) for _, value, _ in parsed))
            else:
                safe[node.id] = (node.type in {'number', 'string', 'true', 'false', 'nil'}
                                 or node.type == 'identifier' and node.id in locals_)
                captures[node.id] = {locals_[node.id]} if node.type == 'identifier' and node.id in locals_ else set()
        replacements, starts = [], []  # descending, disjoint intervals
        counts = Counter()

        def fragment(node):
            start, end = tree.cs(node), tree.ce(node)+1
            first, last = bisect_right(starts, -end), bisect_right(starts, -start)
            parts, pos = [], start
            for replacement in reversed(replacements[first:last]):
                parts.extend((script[pos:replacement.start], replacement.new_text))
                pos = replacement.end+1
            return join_code((*parts, script[pos:end]))

        for node in tables:
            parsed = fields[node.id]
            if not safe[node.id]:
                counts['preserved_unsafe_or_colliding'] += 1
                continue
            identities, index = [], 0
            for key, _, kind in parsed:
                index += kind == 'array'
                identities.append(_literal_key(tree, key, kind, index))
            has_array = any(kind == 'array' for _, _, kind in parsed)
            # Sparse/uncertain lists must keep constructor allocation/order.
            # A proven dense final table has a unique length regardless of
            # insertion order and can be reconstructed with assignments.
            shuffle_safe = not has_array and all(k[0] != 'number' for k in identities)
            dense = all(kind != 'array' or value.type in {'number', 'string', 'true', 'false'}
                        for _, value, kind in parsed)
            staged_safe = dense and all(kind == 'array' or k[0] != 'number'
                                       for (_, _, kind), k in zip(parsed, identities))
            mode = self.options.get('mode', 'mixed')
            staged = staged_safe and mode != 'shuffle' and (
                mode == 'reconstruct' or bool(random.getrandbits(1)))
            if staged and len(parsed) > self.options.get('max_fields', 16):
                staged = False
                counts['reconstruction_field_budget'] += 1
            # Lua 5.1 allows 60 upvalues per function. Reserve one slot for
            # StringObf's environment when string key reconstruction is enabled.
            if staged and len(captures[node.id]) > 60 - bool(self.options.get('string_keys')):
                staged = False
                counts['reconstruction_upvalue_budget'] += 1
            entries = []
            array_index = 0
            for key, value, kind in parsed:
                key_text = ('"'+tree.text(key)+'"') if kind == 'record' else fragment(key) if key is not None else None
                if staged and kind == 'array':
                    array_index += 1
                    fallback = lambda: '('+numbers._fmt_plain_int(array_index)+')'
                    if mosaic is not None:
                        with mosaic.at(tree.cs(value), tree.ce(value)+1):
                            key_text = mosaic.number(array_index, context='table_index', hot=True,
                                                     max_chars=80, max_operations=1, fallback=fallback)
                    else:
                        key_text = fallback()
                    key_text = CodeText(key_text, [(0,len(key_text))],
                                        origins=getattr(key_text,'origins',()) or [(0,len(key_text),'table_index')])
                entries.append((key_text, fragment(value), kind))
            if staged:
                table, key_name, value_name = (allocator.allocate(h) for h in ('table', 'table_key', 'table_value'))
                parts = ['(function() local ', table, '={};local ', key_name, ',', value_name, ';']
                records = entries.copy()
                random.shuffle(records)
                for key_text, value_text, _ in records:
                    if self.options.get('string_keys') and key_text.startswith(('"', "'", '[')):
                        from .string_obfuscation import _encode
                        key_text = _encode(parse_lua_string(key_text), allocator)
                    parts.extend((key_name, '=', key_text, ';', value_name, '=', value_text, ';',
                                  table, '[', key_name, ']=', value_name, ';'))
                parts.extend(('return ', table, ' end)()'))
                expression = join_code(parts)
                expression = CodeText(expression, getattr(expression, 'protected', ()),
                                      [(0, len(expression))], getattr(expression, 'origins', ()))
                counts['reconstruction_programs'] += 1
                counts['reconstruction_fields'] += len(parsed)
            else:
                if shuffle_safe:
                    random.shuffle(entries)
                    counts['shuffled_constructors'] += 1
                else:
                    counts['ordered_constructors'] += 1
                body = [value if kind == 'array' else join_code(('[', key, ']=', value))
                        for key, value, kind in entries]
                expression = join_code(('{', join_code(part for i, value in enumerate(body)
                                                       for part in ((',' if i else ''), value)), '}'))
            # A parent incorporates every child edit, including constructors
            # nested inside keys/other expressions. Replace those intervals in
            # one ordered sweep, rather than an all-pairs containment filter.
            start, end = tree.cs(node), tree.ce(node)
            first = bisect_left(starts, -end)
            del replacements[first:]
            del starts[first:]
            replacements.append(Replacement(start, end, expression))
            starts.append(-start)
        self.last_profile = [{'phase': 'table_generation', 'elapsed': time.perf_counter()-started,
                              'tables_seen': len(tables), **dict(counts)}]
        return list(reversed(replacements))
