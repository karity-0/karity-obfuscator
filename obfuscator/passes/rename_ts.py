"""Resolve lexical bindings before assigning frequency-ranked short Lua names.

The iterative traversal handles declaration visibility, block scopes, closures,
loop variables and implicit method self without Python recursion limits.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from ..names import NameAllocator, RENAME_OPTIONS
from .base import Replacement
from .ts_utils import parse as _ts_parse


@dataclass
class Binding:
    original: str
    nodes: list = field(default_factory=list)


class Scope:
    def __init__(self, parent=None):
        self.parent = parent
        self.names = {}

    def resolve(self, name):
        scope = self
        while scope is not None:
            if name in scope.names:
                return scope.names[name]
            scope = scope.parent
        return None


def _first(node, typ):
    return next((c for c in node.named_children if c.type == typ), None)


def _is_reference(node):
    parent = node.parent
    if parent is None:
        return True
    if parent.type in {'attribute', 'label_statement', 'goto_statement'}:
        return False
    if parent.type in {'dot_index_expression', 'method_index_expression'}:
        return node.id == parent.named_children[0].id
    if parent.type == 'field':
        return not (parent.children[0].id == node.id and
                    len(parent.children) > 1 and parent.children[1].type == '=')
    return True


def resolve_bindings(ctx):
    """Return symbolic bindings, free names, literals and traversal statistics."""
    if ctx.root.has_error:
        raise ValueError('Cannot rename Lua source with syntax errors')
    bindings, literals = [], []
    reserved = {'_ENV', 'self'}
    scopes = 1
    identifiers = 0
    stack = [('walk', ctx.root, Scope())]

    def declare(node, scope):
        name = ctx.text(node)
        binding = Binding(name, [node])
        bindings.append(binding)
        scope.names[name] = binding

    while stack:
        action, node, scope = stack.pop()
        if action == 'declare':
            declare(node, scope)
            identifiers += 1
            continue
        typ = node.type
        if typ == 'identifier':
            identifiers += 1
            if _is_reference(node):
                name = ctx.text(node)
                binding = scope.resolve(name)
                if binding is None:
                    reserved.add(name)
                else:
                    binding.nodes.append(node)
            continue
        if typ in {'string', 'number', 'true', 'false'}:
            literals.append(node)
            continue
        if typ in {'comment', 'attribute', 'label_statement', 'goto_statement'}:
            continue
        actions = []
        if typ == 'variable_declaration':
            assignment = _first(node, 'assignment_statement')
            container = assignment if assignment is not None else node
            values = _first(container, 'expression_list')
            names = _first(container, 'variable_list')
            if values is not None:
                actions.append(('walk', values, scope))
            if names is not None:
                actions.extend(('declare', c, scope) for c in names.named_children if c.type == 'identifier')
        elif typ in {'function_declaration', 'function_definition'}:
            name = node.child_by_field_name('name')
            inner = Scope(scope)
            scopes += 1
            if name is not None:
                if node.children[0].type == 'local':
                    actions.append(('declare', name, scope))
                else:
                    actions.append(('walk', name, scope))
                if name.type == 'method_index_expression':
                    # Implicit self has no declaration token and must keep its spelling.
                    inner.names['self'] = None
            params = node.child_by_field_name('parameters')
            if params is not None:
                actions.extend(('declare', c, inner) for c in params.named_children if c.type == 'identifier')
            body = node.child_by_field_name('body')
            if body is not None:
                actions.append(('body', body, inner))
        elif typ == 'for_statement':
            inner = Scope(scope)
            scopes += 1
            clause = node.child_by_field_name('clause')
            if clause.type == 'for_numeric_clause':
                name = clause.child_by_field_name('name')
                actions.extend(('walk', c, scope) for c in clause.named_children if c.id != name.id)
                actions.append(('declare', name, inner))
            else:
                names = _first(clause, 'variable_list')
                actions.extend(('walk', c, scope) for c in clause.named_children if c.id != names.id)
                actions.extend(('declare', c, inner) for c in names.named_children if c.type == 'identifier')
            body = node.child_by_field_name('body')
            if body is not None:
                actions.append(('body', body, inner))
        elif typ == 'repeat_statement':
            inner = Scope(scope)
            scopes += 1
            body = node.child_by_field_name('body')
            if body is not None:
                actions.append(('body', body, inner))
            condition = node.child_by_field_name('condition')
            if condition is not None:
                actions.append(('walk', condition, inner))
        else:
            if typ == 'block' and action != 'body':
                scope = Scope(scope)
                scopes += 1
            actions.extend(('walk', c, scope) for c in node.named_children)
        stack.extend(reversed(actions))
    return bindings, reserved, literals, scopes, identifiers


def _apply_replacements_once(script: str, replacements: list[tuple[int, int, str]]) -> str:
    """
    원본 source 좌표 기준 replacement를 한 번만 조립한다.

    기존 구현처럼 각 scope segment마다 15MB+ 문자열을 재복사하지 않는다.
    """
    if not replacements:
        return script

    replacements.sort(key=lambda item: item[0])

    parts: list[str] = []
    pos = 0

    for start, end, new_text in replacements:
        # identifier node들은 서로 겹치지 않아야 한다.
        # 혹시 grammar/버그로 겹치면 조용히 source를 깨뜨리지 말고 실패시킨다.
        if start < pos:
            raise RuntimeError(
                f"overlapping rename replacement at {start}:{end}, previous end={pos - 1}"
            )

        parts.append(script[pos:start])
        parts.append(new_text)
        pos = end + 1

    parts.append(script[pos:])
    return "".join(parts)


def rename_script_ts(script: str, *, seed=None, readable=None) -> str:
    return rename_with_ctx(_ts_parse(script), seed=seed, readable=readable)


def rename_replacements_with_ctx(ctx, **options) -> list[Replacement]:
    return rename_plan_with_ctx(ctx, **options)[0]


def rename_plan_with_ctx(ctx, **options):
    replacements, literals, _ = rename_plan_with_ctx_profiled(ctx, **options)
    return replacements, literals


def rename_plan_with_ctx_profiled(ctx, *, seed=None, readable=None, reserved=()):
    options = RENAME_OPTIONS.get()
    seed = options.get('seed') if seed is None else seed
    readable = options.get('readable', False) if readable is None else readable
    start = time.perf_counter()
    bindings, free, literals, scopes, identifiers = resolve_bindings(ctx)
    collected = time.perf_counter()
    allocator = NameAllocator(free | set(reserved), seed=seed, readable=readable)
    # Unique names across the chunk also prevent accidental upvalue capture.
    ordered = sorted(bindings, key=lambda b: -len(b.nodes))
    names = [(b, b.original if b.original == '_ENV' else allocator.allocate(b.original))
             for b in ordered]
    allocated = time.perf_counter()
    replacements = [Replacement(ctx.cs(n), ctx.ce(n), name)
                    for binding, name in names for n in binding.nodes]
    replacements.sort(key=lambda r: r.start)
    return replacements, literals, {
        'collect_elapsed': collected - start,
        'scope_resolution_elapsed': allocated - collected,
        'replacement_elapsed': time.perf_counter() - allocated,
        'total_elapsed': time.perf_counter() - start,
        'scope_count': scopes, 'identifier_count': identifiers,
        'literal_count': len(literals),
    }


def rename_with_ctx(ctx, **options) -> str:
    replacements = rename_replacements_with_ctx(ctx, **options)
    return _apply_replacements_once(ctx.script, [(r.start, r.end, r.new_text) for r in replacements])
