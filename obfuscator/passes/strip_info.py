"""Strip lexical names, comments and provably private table field names.

The escape analysis follows local declaration aliases, rejecting rebinding:
every other reference must be a direct, statically keyed field access.
"""
import re

from ..names import NameAllocator, RENAME_OPTIONS
from .base import PrePass
from .rename_ts import resolve_bindings, rename_script_ts, _apply_replacements_once
from .ts_utils import parse


def _string_bytes(text):
    """Decode supported Lua literals as bytes, never Python Unicode escapes."""
    match = re.fullmatch(r'\[(=*)\[(.*)\]\1\]', text, re.DOTALL)
    if match:
        content = re.sub(r'\r\n|\n\r|\r', '\n', match[2])
        return (content[1:] if content.startswith('\n') else content).encode('utf-8')
    if not text or text[0] not in {'"', "'"}:
        return None
    content = text[1:-1]
    result = bytearray()
    escapes = {'a': 7, 'b': 8, 'f': 12, 'n': 10, 'r': 13, 't': 9,
               'v': 11, '\\': 92, '"': 34, "'": 39}
    i = 0
    while i < len(content):
        ch = content[i]
        i += 1
        if ch != '\\':
            result.extend(ch.encode('utf-8'))
            continue
        if i == len(content):
            return None
        ch = content[i]
        i += 1
        if ch in escapes:
            result.append(escapes[ch])
        elif ch in '0123456789':
            digits = ch
            while i < len(content) and len(digits) < 3 and content[i] in '0123456789':
                digits += content[i]
                i += 1
            value = int(digits)
            if value > 255:
                return None
            result.append(value)
        elif ch == 'x':
            digits = content[i:i + 2]
            if not re.fullmatch('[0-9a-fA-F]{2}', digits):
                return None
            result.append(int(digits, 16))
            i += 2
        elif ch == 'z':
            while i < len(content) and content[i] in ' \t\n\r\v\f':
                i += 1
        elif ch in '\r\n':
            if i < len(content) and content[i] in '\r\n' and content[i] != ch:
                i += 1
            result.append(10)
        else:
            # Unknown/version-specific escapes (including Unicode escapes)
            # remain untouched instead of approximating runtime behavior.
            return None
    return bytes(result)


def _unwrap(node):
    while node.type == 'parenthesized_expression':
        node = next(n for n in node.named_children if n.type != 'comment')
    return node


def _literal_keys(ctx):
    values = {}
    for node in reversed(list(ctx.walk())):
        value = None
        if node.type == 'string':
            value = _string_bytes(ctx.text(node))
        elif node.type == 'parenthesized_expression':
            value = values.get(_unwrap(node).id)
        elif node.type == 'binary_expression':
            operator = node.child_by_field_name('operator')
            if operator is not None and ctx.text(operator) == '..':
                left = values.get(node.child_by_field_name('left').id)
                right = values.get(node.child_by_field_name('right').id)
                if left is not None and right is not None:
                    value = left + right
        if value is not None:
            values[node.id] = value
    return values


def _key(ctx, node, literals):
    if node.type == 'identifier':
        parent = node.parent
        if (parent.type == 'dot_index_expression' or
                (parent.type == 'field' and parent.children[0].id == node.id)):
            return ctx.text(node).encode('utf-8')
        return None
    return literals.get(node.id)


def _initializers(bindings):
    initializers = {}
    for binding in bindings:
        declaration = binding.nodes[0]
        names = declaration.parent
        if names is None or names.type != 'variable_list':
            continue
        assignment = names.parent
        if (assignment.type != 'assignment_statement' or
                assignment.parent.type != 'variable_declaration' or
                binding.original == '_ENV'):
            continue
        values = next((n for n in assignment.named_children
                       if n.type == 'expression_list'), None)
        variables = [n for n in names.named_children if n.type == 'identifier']
        index = next(i for i, n in enumerate(variables) if n.id == declaration.id)
        expressions = [] if values is None else [n for n in values.named_children
                                                 if n.type != 'comment']
        if index < len(expressions):
            initializers[id(binding)] = _unwrap(expressions[index])
    return initializers


def field_replacements(ctx):
    bindings, _, _, _, _ = resolve_bindings(ctx)
    initializers = _initializers(bindings)
    literals = _literal_keys(ctx)
    owners = {n.id: id(b) for b in bindings for n in b.nodes}
    aliases = {}
    for binding in bindings:
        value = initializers.get(id(binding))
        if value is not None and value.type == 'identifier' and value.id in owners:
            aliases.setdefault(owners[value.id], []).append((binding, value.id))
    replacements = []
    for binding in bindings:
        constructor = initializers.get(id(binding))
        if constructor is None or constructor.type != 'table_constructor':
            continue
        # A declaration-only alias is exact if no member of the group is ever
        # rebound. Escaping any alias invalidates the entire object's mapping.
        group = [binding]
        alias_uses = set()
        for member in group:
            for alias, use in aliases.get(id(member), []):
                group.append(alias)
                alias_uses.add(use)
        keys = []
        safe = True
        for field in constructor.named_children:
            if field.type != 'field':
                continue
            key = field.child_by_field_name('name')
            if key is None or key.type == 'number':
                continue
            value = _key(ctx, key, literals)
            if value is None:
                safe = False
                break
            keys.append((key, value))
        if not safe:
            continue
        references = (n for member in group for n in member.nodes[1:])
        for reference in references:
            if reference.id in alias_uses:
                continue
            while reference.parent.type == 'parenthesized_expression':
                reference = reference.parent
            access = reference.parent
            if (access.type not in {'dot_index_expression', 'bracket_index_expression'} or
                    access.child_by_field_name('table').id != reference.id):
                safe = False
                break
            key = access.child_by_field_name('field')
            if key.type == 'number':
                continue
            value = _key(ctx, key, literals)
            if value is None:
                safe = False
                break
            keys.append((key, value))
        if not safe:
            continue
        # Reserve all original keys, including absent-field reads, to prevent
        # collisions. One mapping per object preserves duplicate constructor keys.
        allocator = NameAllocator({value.decode('ascii') for _, value in keys if value.isascii()},
                                  seed=RENAME_OPTIONS.get().get('seed'))
        mapping = {}
        for node, value in keys:
            if value not in mapping:
                mapping[value] = allocator.allocate()
            name = mapping[value]
            replacements.append((ctx.cs(node), ctx.ce(node),
                                 name if node.type == 'identifier' else '"' + name + '"'))
    return replacements


def label_replacements(ctx):
    # A bijection over label spellings preserves Lua's existing block/function
    # visibility rules, including shadowed labels, without moving any token.
    labels = [n for n in ctx.walk()
              if n.type == 'identifier' and n.parent.type in
              {'label_statement', 'goto_statement'}]
    allocator = NameAllocator({ctx.text(n) for n in labels},
                              seed=RENAME_OPTIONS.get().get('seed'))
    mapping = {}
    replacements = []
    for node in sorted(labels, key=lambda n: n.start_byte):
        original = ctx.text(node)
        if original not in mapping:
            mapping[original] = allocator.allocate()
        replacements.append((ctx.cs(node), ctx.ce(node), mapping[original]))
    return replacements


class StripInfoPass(PrePass):
    def run(self, script):
        ctx = parse(script)
        replacements = field_replacements(ctx)
        replacements.extend(label_replacements(ctx))
        # Whitespace prevents a removed inline comment from joining tokens.
        # Literal-expression replacements can contain comments; do not emit
        # overlapping edits for comments already removed with their expression.
        spans = sorted((start, end) for start, end, _ in replacements)
        comments = sorted((n for n in ctx.walk() if n.type == 'comment'),
                          key=lambda n: n.start_byte)
        index = 0
        for node in comments:
            start, end = ctx.cs(node), ctx.ce(node)
            while index < len(spans) and spans[index][1] < start:
                index += 1
            if index < len(spans) and spans[index][0] <= start and end <= spans[index][1]:
                continue
            replacements.append((start, end, '\n' if '\n' in ctx.text(node) else ' '))
        stripped = _apply_replacements_once(script, replacements)
        return rename_script_ts(stripped, readable=False)
