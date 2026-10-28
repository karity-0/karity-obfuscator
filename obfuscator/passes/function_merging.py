"""Merge eligible sibling source bodies into one shared CFF execution worker.

Callable wrappers stay distinct. A worker may persist only when all members have
the same external captures, so an escaped wrapper cannot retain another member's
guest objects. Original declaration visibility and source ownership are checked
before any generated helper exists.
"""
from dataclasses import dataclass
from contextlib import nullcontext
import random
import re

from .function_costs import POLICY, measure
from .numeric_provenance import CURRENT, join_code
from .rename_ts import resolve_bindings
from .ts_utils import parse


FUNCTIONS = frozenset(('function_declaration', 'function_definition'))


@dataclass(frozen=True)
class MergeGroup:
    nodes: tuple
    options: dict
    names: tuple[str, ...]


def _owners(node):
    parent = node.parent
    while parent is not None:
        if parent.type in FUNCTIONS:
            yield parent
        parent = parent.parent


def _internal(declaration, owner):
    name = owner.child_by_field_name('name')
    return (owner.start_byte <= declaration.start_byte < owner.end_byte
            and (name is None or name.id != declaration.id))


def plan_groups(pass_, ctx):
    """Plan from original bindings; never discover groups in generated workers."""
    if pass_.skip_vm_dispatcher:
        return {}, []
    free: dict = {}
    bindings, _, _, _, _ = resolve_bindings(ctx, free_environments=free, collect_literals=False)
    by_node = {n.id: b for b in bindings for n in b.nodes}
    captures: dict[int, set] = {}
    for binding in bindings:
        declaration = binding.nodes[0]
        for ref in binding.nodes[1:]:
            for owner in _owners(ref):
                if _internal(declaration, owner):
                    break
                captures.setdefault(owner.id, set()).add(declaration.id)
    identifiers = {n.id: n for n in ctx.walk() if n.type == 'identifier'}
    for ident, environment in free.items():
        ref = identifiers[ident]
        declaration = environment.nodes[0] if environment is not None else None
        for owner in _owners(ref):
            if declaration is not None and _internal(declaration, owner):
                break
            captures.setdefault(owner.id, set()).add(declaration.id if declaration is not None else 'environment')
    report = []
    candidates = {}
    version = POLICY.get().lua_version
    resolver = pass_.selection_resolver
    selection = getattr(getattr(resolver, '__self__', None), 'plan', None)
    for node in ctx.walk():
        if node.type != 'function_declaration' or node.children[0].type != 'local':
            continue
        name_node = node.child_by_field_name('name')
        if name_node is None or name_node.type != 'identifier':
            continue
        name = ctx.plain_text(name_node)
        depth = sum(1 for _ in _owners(node))
        if resolver is None and depth and (not pass_.nested or
                not pass_.all_source_functions and depth > pass_.nested_max_depth):
            continue
        options = resolver(ctx, node) if resolver is not None else {}
        if options is None or not options.get('merge', pass_.merge) or not options.get('cff', pass_.features['cff']):
            continue
        params = node.child_by_field_name('parameters')
        body = node.child_by_field_name('body')
        reason = None
        if params is None or any(n.type != 'identifier' for n in params.named_children):
            reason = 'vararg-owner'
        elif body is None or not any(n.type != 'comment' for n in body.named_children):
            reason = 'empty-body'
        elif name == '_ENV' or any(ctx.plain_text(n) == '_ENV' for n in params.named_children):
            reason = 'lexical-environment'
        else:
            stack = list(body.named_children)
            while stack:
                child = stack.pop()
                if child.type in ('goto_statement', 'label_statement'):
                    reason = 'goto-or-label'; break
                binding = by_node.get(child.id)
                if binding is not None and binding.original == '_ENV' and binding.nodes[0].id == child.id:
                    reason = 'lexical-environment'; break
                if version == '5.1' and child.type == 'identifier' and ctx.plain_text(child) in ('getfenv','setfenv','debug'):
                    reason = 'lua51-environment-or-reflection'; break
                stack.extend(child.named_children)
        binding = by_node.get(name_node.id)
        if reason is None and version == '5.1' and (binding is None or any(
                ref.parent.type != 'function_call' or ref.parent.child_by_field_name('name').id != ref.id
                for ref in binding.nodes[1:])):
            reason = 'lua51-escaped-function'
        policy_spans = []
        if reason is None and selection is not None:
            start, stop = ctx.cs(node), ctx.ce(node)+1
            for span in selection.spans:
                if span.start < stop and start < span.end:
                    if not (span.start <= start and stop <= span.end):
                        reason = 'nested-selection-boundary'; break
                    policy_spans.append((span.feature, repr(span.options), span.kind))
        if reason:
            report.append({'phase':'function_merge','outcome':'excluded','functions':(name,), 'reason':reason})
            continue
        # Include the real lexical environment even when the spelling is implicit.
        key = (frozenset(captures.get(node.id, ())), repr(sorted(options.items())), tuple(sorted(policy_spans)))
        candidates[node.id] = (node, name, options, key)

    result = {}
    groups = 0
    for block in ctx.walk():
        if block.type not in ('chunk','block'):
            continue
        run: list[tuple] = []
        def flush():
            nonlocal groups
            if len(run) >= 2:
                nodes = tuple(item[0] for item in run)
                names = tuple(item[1] for item in run)
                group_bindings = {by_node[n.child_by_field_name('name').id].nodes[0].id for n in nodes}
                # Moving a body after later declarations must not turn an old
                # global/outer reference into a newly visible sibling binding.
                hazard = False
                for node in nodes:
                    stack = list(node.child_by_field_name('body').named_children)
                    while stack:
                        child = stack.pop()
                        if child.type == 'identifier' and ctx.plain_text(child) in names:
                            binding = by_node.get(child.id)
                            if child.id in free or (binding is not None
                                    and binding.nodes[0].id not in group_bindings
                                    and not node.start_byte <= binding.nodes[0].start_byte < node.end_byte):
                                hazard = True; break
                        stack.extend(child.named_children)
                    if hazard:break
                limit = run[0][2].get('merge_max_groups', pass_.merge_max_groups)
                reason = ('declaration-visibility' if hazard or len(set(names)) != len(names)
                          else 'group-budget' if groups >= limit else None)
                if reason:
                    report.append({'phase':'function_merge','outcome':'excluded','functions':names,'reason':reason})
                else:
                    result[nodes[0].id] = MergeGroup(nodes, run[0][2], names)
                    groups += 1
            run.clear()
        for statement in block.named_children:
            if statement.type in ('comment','empty_statement'):continue
            candidate = candidates.get(statement.id)
            if candidate is None:
                flush();continue
            maximum = candidate[2].get('merge_max_functions', pass_.merge_max_functions)
            if run and (run[0][3] != candidate[3] or len(run) >= maximum):
                if run[0][3][0] != candidate[3][0]:
                    report.append({'phase':'function_merge','outcome':'separated',
                                   'functions':(run[-1][1], candidate[1]),'reason':'different-captures'})
                flush()
            run.append(candidate)
        flush()
    return result, report


def emit_group(pass_, ctx, group, fragments):
    """Apply the selected member policy to all generated entry and state tags."""
    from .literal_mosaic import ACTIVE
    mosaic = ACTIVE.get()
    transport = CURRENT.get()
    prior_limits = (transport.max_chars, transport.max_operations) if transport is not None else None
    if transport is not None:
        transport.max_chars = group.options.get('generated_number_max_chars', pass_.generated_number_max_chars)
        transport.max_operations = group.options.get('generated_number_max_operations', pass_.generated_number_max_operations)
    try:
        with mosaic.at(ctx.cs(group.nodes[0]), ctx.ce(group.nodes[0])+1) if mosaic is not None else nullcontext():
            return _emit_group(pass_, ctx, group, fragments)
    finally:
        if transport is not None:
            transport.max_chars, transport.max_operations = prior_limits


def _emit_group(pass_, ctx, group, fragments):
    """Emit real source bodies in a single block bank, not a closure multiplexer."""
    from .function_obfuscation import (_build_lexical_plan, _rewrite_node_with_plan,
        _plan_simple_function_inlines, _apply_simple_function_inlines,
        _transform_body, _FUNCTION_FEATURES)
    allocator = pass_._merge_allocator
    worker_name = allocator.allocate('merged')
    selector = allocator.allocate('entry')
    bodies = []
    original_params = []
    inlined = 0
    for fragment in fragments:
        parsed = parse(fragment)
        root = next(n for n in parsed.root.named_children if n.type == 'function_declaration')
        body = root.child_by_field_name('body')
        parameters = root.child_by_field_name('parameters')
        assert body is not None and parameters is not None
        original_params.append([parsed.plain_text(n) for n in parameters.named_children])
        lexical = _build_lexical_plan(parsed, root)
        inline, skipped = (_plan_simple_function_inlines(parsed, body, lexical)
                           if group.options.get('inline', pass_.features['inline']) else ({}, set()))
        inlined += len(skipped)
        statements = [_apply_simple_function_inlines(_rewrite_node_with_plan(parsed,n,lexical), inline)
                      for n in body.named_children if n.type != 'comment' and n.id not in skipped]
        bodies.append((lexical.root_param_names, join_code([join_code((s,'\n')) for s in statements])))
    arguments = [allocator.allocate('argument') for _ in range(max(map(len, original_params)))]
    tags = random.sample(range(1, 1<<23), len(group.nodes))
    transport = CURRENT.get()
    tag_text = [(transport.generated_expression(tag) if transport is not None else str(tag)) for tag in tags]
    branches = []
    for index, (params, body) in enumerate(bodies):
        binding = 'local '+','.join(params)+'='+','.join(arguments[:len(params)])+'\n' if params else ''
        branches.append(f"{'if' if index == 0 else 'elseif'} {selector}=={tag_text[index]} then\n"+binding+body+'\n')
    plain = 'local function '+worker_name+'('+','.join((selector,*arguments))+')\n'+join_code(branches)+'end\nend'
    parsed = parse(plain)
    if parsed.root.has_error:
        raise RuntimeError('function merge worker has invalid source syntax')
    root = parsed.root.named_children[0]
    options = group.options
    features = {**pass_.features, **{k:v for k,v in options.items() if k in pass_.features}, 'wrapper':False}
    features['merge_no_frame_pooling'] = True
    features['merge_counter_start'] = max((int(v) for v in re.findall(r'\b_z(\d+)\b',plain)),default=-1)+1
    compound = {**pass_.compound_options, **{k[5:]:v for k,v in options.items() if k.startswith('loop_')}}
    feature_token = _FUNCTION_FEATURES.set(features)
    from dataclasses import replace
    policy = replace(POLICY.get(), max_jump=options.get('max_jump_instructions', pass_.max_jump_instructions),
                     max_instructions=options.get('max_function_instructions', pass_.max_function_instructions),
                     compact_pass=True, avoid_helper_captures=True)
    token = POLICY.set(policy)
    try:
        try:
            transformed, stats = _transform_body(parsed,root,root.child_by_field_name('body'),
                rich_junk=True,boundary_mode='cff',compound_options=compound)
        except RuntimeError as error:
            if not str(error).startswith(('FunctionObf minimum CFF cost', 'FunctionObf cannot safely partition CFF',
                    'FunctionObf function budget exhausted', 'function merge would pool captured invocation locals')):
                raise
            return None, {'reason':'compiler-budget-or-capture-layout','error':str(error)}
    finally:
        POLICY.reset(token);_FUNCTION_FEATURES.reset(feature_token)
    if transformed is None:
        return None, {'reason':'unsupported-worker-body'}
    # The worker is assigned only after all original callable declarations exist.
    # Each original wrapper is a fresh function object and a tail entry.
    parts = ['local '+worker_name+'\n']
    for index, name in enumerate(group.names):
        params = original_params[index]
        call_args = ','.join((tag_text[index], *params))
        parts.append('local function '+name+'('+','.join(params)+') return '+worker_name+'('+call_args+') end\n')
        if index+1 < len(group.nodes):
            parts.append(ctx.script[ctx.ce(group.nodes[index])+1:ctx.cs(group.nodes[index+1])])
            parts.append('\n')
    parts.append(worker_name+'=function('+','.join((selector,*arguments))+')\n'+transformed+'\nend\n')
    result = join_code(parts)
    cost = measure(result)
    if 'error' in cost:
        return None, {'reason':'compiler-limit','error':cost['error']}
    if cost['total_instructions'] > policy.max_instructions or any(r['max_jump'] > policy.max_jump for r in cost['functions']):
        return None, {'reason':'compiler-budget','compiler_instructions':cost['total_instructions']}
    stats['inlined_functions'] += inlined
    return result, {'phase':'function_merge','outcome':'merged','functions':group.names,
                    'source_functions':len(group.nodes),'entry_tags':tuple(tags),
                    'compiler_instructions':cost['total_instructions'],
                    'compiler_max_jump':max(r['max_jump'] for r in cost['functions']), 'stats':stats}
