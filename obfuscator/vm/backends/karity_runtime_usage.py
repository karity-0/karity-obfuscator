"""Dependencies of the closed, generated Karity runtime (before DAG emission).

This is deliberately not a general Lua dead-code eliminator. Only audited,
side-effect-free local function declarations are removable. Handler bodies,
fake handlers, dispatch tables, escaped callbacks, execution-kit clones and
initializers are roots. Lexical bindings include indirect references and
closures; a spelling occurring inside another dead helper is not a root.
"""
from __future__ import annotations

from bisect import bisect_right
import time
from ...passes.ts_utils import parse
from ...passes.rename_ts import resolve_bindings
from ...passes.numeric_provenance import join_code


_HELPERS = frozenset('''decode _ss_step _ss_value _int1 _int2 _cross
_branch _cf _touch _graph_for _couple_direct _seal_result _arith1 _arith2
_elinear1 _elinear2 _pending_snapshot _pending_fragment _defer1r _defer2r
_arith1r _arith2r _arith1s _arith2s _syn_arith1r _syn_arith2r _call_args _return_values _native_call
_jump _loop_commit _forloop make_closure close_upvalues get_box get_upvalue
set_upvalue _tnew _tkey _tget _tset _tlen _texpose'''.split())

_SEMANTIC_TOKENS = (
    '__VM_DATA_VALUE__', '__VM_DATA_GET__', '__VM_DATA_SET__',
    '__VM_CMP_EQ__', '__VM_CMP_LT__', '__VM_CMP_LE__', '__VM_CMP_TRUTH__',
    '__VM_OP_MOD__', '__VM_OP_POW__', '__VM_OP_DIV__', '__VM_OP_IDIV__',
    '__VM_OP_NOT__', '__VM_OP_LEN__', '__VM_OP_CONCAT__',
    '__VM_OP_NEWTABLE__', '__VM_OP_SETLIST__', '__VM_OP_CLOSURE__', '__VM_OP_VARARG__',
)
_SLOT_TOKENS = {f'__VM_SLOT_{k}__' for k in (
    'ADD', 'SUB', 'MUL', 'BAND', 'BOR', 'BXOR', 'SHL', 'SHR', 'UNM', 'BNOT',
)}
_SLOT_ARGUMENTS = {
    '_arith2': 3, '_arith1': 2, '_arith2r': 4, '_arith1r': 3,
    '_defer2r': 4, '_defer1r': 3, '_arith2s': 3, '_arith1s': 2,
    # Derived raw-value helpers append operands after the original slot ABI.
    '_syn_arith2r': 4, '_syn_arith1r': 3,
}
_LOOP_TOKENS = {f'__VM_LOOP_{kind}__' for kind in ('FORLOOP', 'FORPREP', 'TFORLOOP')}

def _relevant(name):
    return (name in _HELPERS or name in ('_sem', 'slot') or name.startswith('_sem_')
            or name in _SLOT_TOKENS or name in _SEMANTIC_TOKENS
            or name.startswith('__VM_LOOP_'))

def _resolve(ctx, extra_names=()):
    nodes = []
    def select(node):
        name = ctx.plain_text(node)
        if _relevant(name) or name in extra_names:
            nodes.append(node)
            return True
        return False
    bindings, _, _, _, _ = resolve_bindings(
        ctx, collect_literals=False, identifier_filter=select,
    )
    return bindings, nodes


def specialize_runtime(source: str, *, shared_helpers=()) -> tuple[str, dict]:
    started = time.perf_counter()
    ctx = parse(source)
    # An unfamiliar target syntax must retain the original runtime, not guess.
    if ctx.root.has_error:
        return source, {'helper_pruning_deferred': 'unrecognized runtime syntax'}
    bindings, nodes = _resolve(ctx, set(shared_helpers) | ({'_pmix'} if shared_helpers else set()))
    declarations = {}
    for index, binding in enumerate(bindings):
        name = binding.nodes[0]
        parent = name.parent
        if (binding.original in _HELPERS and parent.type == 'function_declaration'
                and parent.children[0].type == 'local'
                and parent.child_by_field_name('name').id == name.id):
            declarations[index] = parent
    owners = {node.id: index for index, node in declarations.items()}
    roots = set()
    dependencies = {index: set() for index in declarations}
    for index in declarations:
        for reference in bindings[index].nodes[1:]:
            owner = reference.parent
            while owner is not None and owner.id not in owners:
                owner = owner.parent
            if owner is None:
                roots.add(index)
            else:
                dependencies[owners[owner.id]].add(index)
    live = set(roots)
    pending = list(roots)
    while pending:
        for dependency in dependencies[pending.pop()] - live:
            live.add(dependency)
            pending.append(dependency)
    removed = {index: node for index, node in declarations.items() if index not in live}
    ranges = sorted((ctx.cs(n), ctx.ce(n) + 1) for n in removed.values())
    parts, end = [], 0
    for start, stop in ranges:
        # Nested declarations inside a removed helper are already covered.
        if start < end:
            continue
        parts.extend((source[end:start], '\n'))
        end = stop
    parts.append(source[end:])
    result = join_code(parts)
    requirements = _requirements(ctx, bindings, ranges, nodes)
    helper_bytes_removed = len(source.encode()) - len(result.encode())
    skeleton_stats = {}
    if shared_helpers:
        from .runtime_skeleton import share_runtime_helpers
        result, skeleton_stats = share_runtime_helpers(
            source, shared_helpers, ctx=ctx, bindings=bindings, removals=ranges,
        )
    return result, {
        '_graph_requirements': requirements,
        'helper_analysis_seconds': round(time.perf_counter() - started, 6),
        'helper_analysis_input_bytes': len(source.encode()),
        'audited_helpers_before': len(declarations),
        'audited_helpers_after': len(declarations) - len(removed),
        'removed_helpers': [bindings[i].original for i in sorted(removed)],
        'helper_bytes_removed': helper_bytes_removed,
        **skeleton_stats,
    }


def graph_requirements(source: str) -> tuple[set[str], set[str]]:
    """Finite graph keys of the generated runtime, including cold/fake routes.

    Arithmetic slot tokens are explicit capabilities passed by emitted handlers.
    Semantic keys are the first argument at every bound _sem/clone call. If a
    helper escapes or a key is computed, retain the entire semantic bank. Do
    not infer keys from source opcode reachability or operand types.
    """
    ctx = parse(source)
    if ctx.root.has_error:
        return _SLOT_TOKENS | _LOOP_TOKENS, set(_SEMANTIC_TOKENS)
    bindings, nodes = _resolve(ctx)
    return _requirements(ctx, bindings, [], nodes)


def _requirements(ctx, bindings, removed, nodes):
    starts = [a for a, _ in removed]
    def retained(node):
        offset = ctx.cs(node)
        index = bisect_right(starts, offset) - 1
        return index < 0 or offset >= removed[index][1]
    # Capability tokens are generated identifiers, never user-selected names.
    # Include even unknown/guard references conservatively. Unlike a second
    # resolver/tree walk/query, use identifiers captured by the same analysis.
    tokens = {ctx.plain_text(node) for node in nodes
              if retained(node) and ctx.plain_text(node).startswith('__VM_')}
    semantic = set()
    bound_nodes = {node.id for binding in bindings for node in binding.nodes}
    for node in nodes:
        if node.id in bound_nodes or not retained(node):
            continue
        name = ctx.plain_text(node)
        if name in _SLOT_ARGUMENTS:
            tokens.update(_SLOT_TOKENS)
        if name == '_sem' or name.startswith('_sem_'):
            semantic.update(_SEMANTIC_TOKENS)
    parameter_slots = set()
    for binding in bindings:
        if binding.original != 'slot' or binding.nodes[0].parent.type != 'parameters':
            continue
        owner = binding.nodes[0].parent.parent
        name = owner.child_by_field_name('name')
        if name is not None and ctx.plain_text(name) in _SLOT_ARGUMENTS:
            parameter_slots.update(node.id for node in binding.nodes[1:])
    for binding in bindings:
        if binding.original in _SLOT_ARGUMENTS:
            for reference in binding.nodes[1:]:
                if not retained(reference):
                    continue
                call = reference.parent
                argument = _SLOT_ARGUMENTS[binding.original]
                if call.type != 'function_call' or call.child_by_field_name('name').id != reference.id:
                    tokens.update(_SLOT_TOKENS)
                    continue
                arguments = call.child_by_field_name('arguments').named_children
                key = ctx.plain_text(arguments[argument]) if len(arguments) > argument else ''
                if key in _SLOT_TOKENS:
                    continue
                # The audited forwarding helpers pass their own slot parameter
                # unchanged. Escapes or any other computed key retain all kinds.
                owner = call.parent
                while owner is not None and owner.type not in ('function_declaration', 'function_definition'):
                    owner = owner.parent
                name = owner.child_by_field_name('name') if owner is not None else None
                if not (key == 'slot' and arguments[argument].id in parameter_slots and name is not None
                        and ctx.plain_text(name) in _SLOT_ARGUMENTS):
                    tokens.update(_SLOT_TOKENS)
        if binding.original != '_sem' and not binding.original.startswith('_sem_'):
            continue
        for reference in binding.nodes[1:]:
            if not retained(reference):
                continue
            call = reference.parent
            if (call.type != 'function_call'
                    or call.child_by_field_name('name').id != reference.id):
                semantic.update(_SEMANTIC_TOKENS)
                continue
            arguments = call.child_by_field_name('arguments').named_children
            if not arguments or ctx.plain_text(arguments[0]) not in _SEMANTIC_TOKENS:
                semantic.update(_SEMANTIC_TOKENS)
                continue
            semantic.add(ctx.plain_text(arguments[0]))
    return tokens, semantic
