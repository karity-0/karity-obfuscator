"""Resolve lexical bindings before assigning frequency-ranked short Lua names.

The iterative traversal handles declaration visibility, block scopes, closures,
loop variables and implicit method self without Python recursion limits.
"""
from __future__ import annotations

import time
from bisect import bisect_left
from dataclasses import dataclass, field
import tree_sitter as ts
from ..names import NameAllocator, RENAME_OPTIONS
from .base import Replacement
from .ts_utils import _LANG, parse as _ts_parse


_IDENTIFIERS = ts.Query(_LANG, '(identifier) @identifier')
_RENAME_NODES = ts.Query(_LANG, '(identifier) @identifier (number) @literal (string) @literal [(true) (false)] @literal')
_OUTPUT_NODES = ts.Query(_LANG, '(identifier) @identifier (number) @literal (string) @literal [(true) (false)] @literal (comment) @comment (label_statement (identifier) @label) (goto_statement (identifier) @label)')


def collect_output_nodes(ctx):
    """One C traversal for a generated output's literals, names and stripping."""
    captures = ts.QueryCursor(_OUTPUT_NODES).captures(ctx.root)
    if not isinstance(captures, dict):
        grouped = {}
        for node, name in captures:
            grouped.setdefault(name, []).append(node)
        captures = grouped
    captures.setdefault('literal', []).sort(key=lambda n: n.start_byte)
    return captures


@dataclass
class Binding:
    original: str
    nodes: list = field(default_factory=list)
    function_scope: Scope | None = None


class Scope:
    def __init__(self, parent=None, *, function=False, name_scopes=False):
        self.parent = parent
        self.names = {}
        self.name_scopes = name_scopes if parent is None else parent.name_scopes
        if self.name_scopes:
            self.function = self if parent is None or function else parent.function
            if self.function is self:
                self.depth = 0 if parent is None else parent.function.depth + 1
                self.captures = set()

    def resolve(self, name):
        scope = self
        while scope is not None:
            if name in scope.names:
                return scope.names[name]
            scope = scope.parent
        return None

    def is_implicit(self, name):
        scope = self
        while scope is not None:
            if name in scope.names:
                return scope.names[name] is None
            scope = scope.parent
        return False


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


def resolve_bindings(ctx, *, free_environments=None, collect_literals=True, sparse=True,
                     identifier_filter=None, captures=None, collect_name_scopes=False):
    """Return symbolic bindings, free names, literals and traversal statistics.

    A closed-runtime dependency caller may restrict identifier spellings; all
    occurrences of those names, including shadowing declarations, are retained.
    Ordinary naming/field analysis uses the unchanged complete traversal.
    """
    if ctx.root.has_error:
        raise ValueError('Cannot rename Lua source with syntax errors')
    bindings, literals = [], []
    reserved = {'_ENV', 'self'}
    scopes = 1
    identifiers = 0
    stack = [('walk', ctx.root, Scope(name_scopes=collect_name_scopes))]
    text = ctx.plain_text
    # Final naming/field analysis needs identifiers, not the hundreds of
    # thousands of arithmetic nodes introduced by literal emitters. The C
    # query finds *all* identifiers, including field names and declarations;
    # prune only subtrees proven to contain none. Capture requested literals
    # in that same C traversal and preserve original source order. The full
    # walk remains available for coverage auditing and conservative callers.
    identifier_offsets = None
    if sparse:
        if captures is None:
            captures = ts.QueryCursor(_RENAME_NODES if collect_literals else _IDENTIFIERS).captures(ctx.root)
        if isinstance(captures, dict):
            nodes = captures.get('identifier', [])
            literals = captures.get('literal', []) if collect_literals else []
        else:
            nodes = [n for n, name in captures if name == 'identifier']
            literals = [n for n, name in captures if name == 'literal'] if collect_literals else []
        literals.sort(key=lambda n: n.start_byte)
        if identifier_filter is not None:
            nodes = [n for n in nodes if identifier_filter(n)]
        identifier_offsets = sorted(n.start_byte for n in nodes)
        del captures, nodes

    def declare(node, scope):
        name = text(node)
        binding = Binding(name, [node], scope.function if collect_name_scopes else None)
        bindings.append(binding)
        scope.names[name] = binding

    while stack:
        action, node, scope = stack.pop()
        if identifier_offsets is not None:
            index = bisect_left(identifier_offsets, node.start_byte)
            if index == len(identifier_offsets) or identifier_offsets[index] >= node.end_byte:
                continue
        if action == 'declare':
            declare(node, scope)
            identifiers += 1
            continue
        typ = node.type
        if typ == 'identifier':
            identifiers += 1
            if _is_reference(node):
                name = text(node)
                binding = scope.resolve(name)
                if binding is None:
                    reserved.add(name)
                    if free_environments is not None:
                        free_environments[node.id] = None if scope.is_implicit(name) else scope.resolve('_ENV')
                else:
                    binding.nodes.append(node)
                    if collect_name_scopes:
                        function = scope.function
                        while function is not binding.function_scope:
                            # Reserve captures through intermediate functions:
                            # an unused local there must not shadow a grandchild's upvalue.
                            function.captures.add(id(binding))
                            function = function.parent.function
            continue
        if typ in {'string', 'number', 'true', 'false'}:
            if collect_literals and not sparse:
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
            inner = Scope(scope, function=True)
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
    from .numeric_provenance import join_code
    return join_code(parts)


def rename_script_ts(script: str, *, seed=None, readable=None, reuse_function_names=False) -> str:
    return rename_with_ctx(_ts_parse(script), seed=seed, readable=readable,
                          reuse_function_names=reuse_function_names)


def qualify_runtime_globals(script: str, *, lexical_names=()) -> str:
    """Prevent an embedded runtime from capturing surrounding source locals.

    This runs before integrity finalization. Explicit _ENV accesses compile in
    the runtime's own environment even if user locals shadow math/type/string.
    """
    ctx = _ts_parse(script)
    bindings, _, _, _, _ = resolve_bindings(ctx)
    bound = {node.id for binding in bindings for node in binding.nodes}
    lexical_names = set(lexical_names)
    # _LS is bound by the late line-state emitter after this pass. self is an
    # implicit method parameter whose declaration has no identifier token.
    replacements = [
        (ctx.cs(node), ctx.ce(node), "_ENV." + ctx.text(node))
        for node in ctx.walk()
        if node.type == "identifier" and node.id not in bound and _is_reference(node)
        and ctx.text(node) not in lexical_names
        and ctx.text(node) not in {"_ENV", "self", "_LS", "_ENV_GUEST", "_ENV_NATIVE", "_ENV_CHECK", "_ENV_REFRESH"}
    ]
    return _apply_replacements_once(script, replacements)


def rename_replacements_with_ctx(ctx, **options) -> list[Replacement]:
    return rename_plan_with_ctx(ctx, **options)[0]


def rename_plan_with_ctx(ctx, **options):
    replacements, literals, _ = rename_plan_with_ctx_profiled(ctx, **options)
    return replacements, literals


def rename_plan_with_ctx_profiled(ctx, *, seed=None, readable=None, reserved=(), keep=None,
                                 resolution=None, collect_literals=True, reuse_function_names=False):
    options = RENAME_OPTIONS.get()
    seed = options.get('seed') if seed is None else seed
    readable = options.get('readable', False) if readable is None else readable
    start = time.perf_counter()
    bindings, free, literals, scopes, identifiers = (resolution if resolution is not None
        else resolve_bindings(ctx, collect_literals=collect_literals, collect_name_scopes=reuse_function_names))
    collected = time.perf_counter()
    kept = {id(b) for b in bindings if keep is not None and keep(b)}
    unavailable = free | set(reserved) | {b.original for b in bindings if id(b) in kept}
    ordered = sorted(bindings, key=lambda b: -len(b.nodes))
    reuse = reuse_function_names and not readable and all(b.function_scope is not None for b in bindings)
    groups = {}
    if reuse:
        for binding in ordered:
            groups.setdefault(binding.function_scope, []).append(binding)
        assigned, names = {}, []
        for function, group in sorted(groups.items(), key=lambda item: item[0].depth):
            allocator = NameAllocator(unavailable | {assigned[capture] for capture in function.captures}, seed=seed)
            for binding in group:
                name = binding.original if binding.original == '_ENV' or id(binding) in kept else allocator.allocate(binding.original)
                assigned[id(binding)] = name
                names.append((binding, name))
    else:
        # General source naming and readable hints retain their existing policy.
        allocator = NameAllocator(unavailable, seed=seed, readable=readable)
        names = [(b, b.original if b.original == '_ENV' or id(b) in kept else allocator.allocate(b.original))
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
        'function_name_scopes': len(groups) if reuse else 1,
        'reused_function_names': bool(reuse),
    }


def rename_with_ctx(ctx, **options) -> str:
    replacements = rename_replacements_with_ctx(ctx, **options)
    return _apply_replacements_once(ctx.script, [(r.start, r.end, r.new_text) for r in replacements])
