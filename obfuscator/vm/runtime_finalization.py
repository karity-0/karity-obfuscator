"""Finish generated code before source locations and function dumps are bound.

Output passes can introduce new native calls, and environment/line helpers are
assembled later still. Resolve those dependencies here, after generation, rather
than teaching every producer the layout of an earlier private capture bank.
"""
import random
import re


def protect_fragment_strings(source, pass_names, *, lua_version):
    """Transform late helper strings once per distinct value, sharing the pool."""
    selected = [name for name in pass_names if name in {'string_obf', 'string_flow_obf', 'string_encode'}]
    if not selected:
        return source
    from ..names import NameAllocator
    from ..passes.ts_utils import parse
    from ..passes.string_obfuscation import parse_lua_string
    from ..passes.rename_ts import _apply_replacements_once
    ctx = parse(source)
    pool = NameAllocator.for_source(source).allocate('strings')
    literals = {}
    edits = []
    for node in sorted((n for n in ctx.walk() if n.type == 'string'), key=lambda n: n.start_byte):
        spelling = ctx.plain_text(node)
        value = parse_lua_string(spelling, lua_version)
        if value not in literals:
            literals[value] = (len(literals) + 1, spelling)
        edits.append((ctx.cs(node), ctx.ce(node), f'{pool}[{literals[value][0]}]'))
    if not edits:
        return source
    declaration = 'local ' + pool + '={' + ','.join(text for _, text in literals.values()) + '}\n'
    from ..passes.function_costs import POLICY, CostPolicy
    token = POLICY.set(CostPolicy(lua_version=lua_version))
    try:
        for name in selected:
            if name in {'string_obf', 'string_flow_obf'}:
                from .output_emitter import emit_vm_literals
                declaration, _ = emit_vm_literals(declaration, [name])
            else:
                from ..passes.string_encode import StringEncodePass
                from ..pipeline import Pipeline
                declaration = Pipeline(show_header=False)._apply(
                    declaration, StringEncodePass(lua_version=lua_version).run(declaration, parse(declaration)))
    finally:
        POLICY.reset(token)
    return declaration + '\n' + _apply_replacements_once(source, edits)


def capture_generated_apis(source, *, lua_version, string_style=False):
    """Freeze free native references after all code generators have finished.

    Bootstrap names remain ordinary literal keys: running StringObf on its own
    dependency lookup would recursively require another dependency lookup. The
    optional String Encode policy needs no runtime dependencies and can safely
    style these keys. Other string reconstruction passes cannot bootstrap themselves.
    Captured values are the original functions/tables, never Lua wrappers.
    Lexically shadowed libraries retain their original lookup semantics.
    """
    from ..names import NameAllocator
    from ..passes.ts_utils import parse
    from ..passes.rename_ts import resolve_bindings, _apply_replacements_once
    from ..passes.string_obfuscation import parse_lua_string
    from .runtime_security import _CORE_GLOBALS, _CORE_MEMBERS
    anchor = re.match(r'return\s+function\s*\([^)]*\)', source)
    if anchor is None:
        raise ValueError('runtime finalization requires a VM factory')
    ctx = parse(source)
    libraries = set(_CORE_MEMBERS)
    globals_ = set(_CORE_GLOBALS) | libraries | {'assert', 'unpack', 'getfenv', 'setfenv'}
    free = {}
    resolve_bindings(ctx, free_environments=free, collect_literals=False,
                     identifier_filter=lambda n: ctx.plain_text(n) in globals_ | {'_ENV'})

    def quoted(text):
        from ..passes.string_mosaic import lua_string
        return lua_string(text, lua_version=lua_version, enabled=string_style)

    def path(node):
        if node.type == 'identifier':
            name = ctx.plain_text(node)
            if node.id in free and name in globals_:
                return (name,)
            if name == '_ENV':
                return ()
        elif node.type in {'dot_index_expression', 'bracket_index_expression'}:
            owner, key = node.named_children
            prefix = path(owner)
            if prefix is not None:
                if node.type == 'dot_index_expression':
                    name = ctx.plain_text(key)
                elif key.type == 'string':
                    try:
                        name = parse_lua_string(ctx.plain_text(key), lua_version).decode('utf8')
                    except UnicodeDecodeError:
                        return None
                else:
                    return None
                candidate = (*prefix, name)
                if ((len(candidate) == 1 and name in globals_) or
                        (len(candidate) == 2 and candidate[0] in libraries)):
                    return candidate
        return None

    accesses = []
    edits = []
    stack = [ctx.root]
    while stack:
        node = stack.pop()
        if (node.parent is not None and node.parent.type == 'function_declaration'
                and node.parent.child_by_field_name('name') == node):
            # Lua's function-name grammar cannot contain bracket indexes.
            # Declarations publish fields; they are not native dependencies.
            continue
        native = path(node)
        # Do not turn stores into writes to a private capture slot.
        store = node.parent is not None and node.parent.type == 'variable_list'
        if native and not store:
            accesses.append((node, native))
            continue
        if node.type == 'dot_index_expression':
            owner, key = node.named_children
            # A target may deliberately bind a lexical library alias. Keep its
            # dynamic lookup using an ordinary constant field key.
            if owner.type == 'identifier' and ctx.plain_text(owner) in libraries:
                edits.append((ctx.ce(owner) + 1, ctx.ce(key),
                              '[' + quoted(ctx.plain_text(key)) + ']'))
                stack.append(owner)
                continue
        stack.extend(node.named_children)
    if not accesses:
        return _apply_replacements_once(source, edits)
    allocator = NameAllocator.for_source(source)
    bank, environment, raw, read, table, key, value = [allocator.allocate() for _ in range(7)]
    paths = sorted({native for _, native in accesses})
    slots = dict(zip(paths, random.sample(range(31, 65536), len(paths))))
    def lookup(native):
        expression = environment
        for name in native:
            expression = f'{read}({expression},{quoted(name)})'
        return expression
    entries = [f'[{slots[native]}]={lookup(native)}' for native in paths]
    random.shuffle(entries)
    original = '_ENV' if lua_version == '5.3' else '(getfenv and getfenv(1) or _ENV)'
    capture = (f' local {bank}=(function({environment}) '
               f'local {raw}={environment}[{quoted("rawget")}] '
               f'local function {read}({table},{key}) local {value}={raw}({table},{key});'
               f'if {value}==nil then return {table}[{key}] end;return {value} end '
               f'return {{{",".join(entries)}}} end)({original}); ')
    edits.extend((ctx.cs(node), ctx.ce(node), f'{bank}[{slots[native]}]')
                 for node, native in accesses)
    edits.append((anchor.end(), anchor.end() - 1, capture))
    return _apply_replacements_once(source, edits)


def output_finalizer(pass_names, *, lua_version):
    """One terminal dependency/formatting boundary shared by every VM backend."""
    def finish(source):
        source = capture_generated_apis(source, lua_version=lua_version, string_style='string_encode' in pass_names)
        if 'minify' in pass_names:
            from ..passes.minify import MinifyPass
            source = MinifyPass().run(source)
        if 'semicolon' in pass_names:
            from ..passes.semicolon import SemiColonPass
            source = SemiColonPass(lua_version).run(source)
        return source
    return finish
