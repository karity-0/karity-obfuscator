"""Advisory module dependencies; never rewrite Lua loading behavior."""
from pathlib import PurePosixPath

from .passes.ts_utils import parse
from .passes.rename_ts import resolve_bindings
from .passes.string_obfuscation import parse_lua_string


def analyze_modules(sources: dict[str, str], discovered: set[str], templates: tuple[str, ...],
                    version: str = '5.3', *, local_path=None, versions=None) -> tuple[dict, list[list[str]]]:
    modules: dict[str,dict] = {}
    for path, source in sources.items():
        module_version = versions.get(path,version) if versions is not None else version
        ctx = parse(source)
        if ctx.root.has_error:
            modules[path] = {'requires': [], 'calls': [], 'warnings': ['Dependency analysis: Lua syntax is not statically parseable']}
            continue
        free: dict = {}
        resolve_bindings(ctx, free_environments=free, collect_literals=False)
        rebound = any(node.type=='identifier' and ctx.plain_text(node)=='require' and node.id in free
            and node.parent is not None and (node.parent.type=='variable_list' and node.parent.parent is not None
                and node.parent.parent.type=='assignment_statement' or node.parent.type=='function_declaration')
            for node in ctx.walk())
        references = []
        calls = []
        warnings = []
        for node in ctx.walk():
            if node.type != 'function_call':
                continue
            callee = node.child_by_field_name('name')
            if callee is None:
                callee = next((c for c in node.named_children if c.type != 'arguments'), None)
            if callee is None:
                continue
            spelling = ctx.plain_text(callee)
            calls.append({'callee': spelling, 'line': node.start_point[0] + 1})
            if callee.type != 'identifier' or spelling != 'require' or callee.id not in free:
                continue
            args = next((c for c in node.named_children if c.type == 'arguments'), None)
            values = args.named_children if args is not None else []
            item = {'line': node.start_point[0] + 1, 'expression': ctx.plain_text(node),
                    'status': 'dynamic', 'module': None, 'candidates': []}
            if rebound:
                item['reason'] = 'global require is reassigned in this module'
            elif free[callee.id] is not None:
                item['reason'] = 'require is resolved through a local _ENV'
            elif len(values) == 1 and values[0].type == 'string':
                try:
                    name = parse_lua_string(ctx.plain_text(values[0]), module_version).decode('utf8')
                    item['module'] = name
                    stem = name.replace('.', '/')
                    if not stem or stem.startswith('/') or '\\' in stem or ':' in stem or '\0' in stem:
                        raise ValueError('non-local module spelling')
                    candidates = []
                    for template in templates:
                        candidate = template.replace('?', stem)
                        parts = PurePosixPath(candidate).parts
                        if '..' in parts or PurePosixPath(candidate).is_absolute():
                            raise ValueError('module path escapes the project')
                        candidate = PurePosixPath(candidate).as_posix()
                        resolved = candidate if candidate in discovered else local_path(candidate) if local_path is not None else None
                        if resolved is not None and resolved not in candidates:
                            candidates.append(resolved)
                    item['candidates'] = candidates
                    if len(candidates) > 1:
                        item['status'] = 'ambiguous'
                    elif candidates:
                        item['status'] = 'internal' if candidates[0] in sources else 'unresolved'
                        if item['status'] == 'internal':item['path'] = candidates[0]
                        else:item['reason'] = 'local file is not a selected Lua source'
                    else:
                        item['status'] = 'external'
                except (ValueError, UnicodeError) as error:
                    item['status'] = 'unresolved';item['reason'] = str(error)
            references.append(item)
            if item['status'] in ('unresolved','ambiguous'):
                warnings.append(f"require at line {item['line']}: {item['status']} ({item.get('reason', ', '.join(item['candidates']))})")
        # Paths/searchers remain owned by the program. This warning does not
        # pretend that static resolution models arbitrary runtime loaders.
        for node in ctx.walk():
            if node.type == 'assignment_statement':
                text = ctx.plain_text(node).split('=', 1)[0]
                if any(name in text for name in ('package.path', 'package.searchers', 'package.loaders')):
                    warnings.append('Runtime module search configuration is modified; dependency results are advisory')
        modules[path] = {'requires': references, 'calls': calls, 'warnings': list(dict.fromkeys(warnings))}
    graph: dict[str,set[str]] = {path: {r['path'] for r in info['requires'] if r['status'] == 'internal'}
             for path, info in modules.items()}
    reverse: dict[str,set[str]] = {path: set() for path in graph}
    for path, targets in graph.items():
        for target in targets:reverse[target].add(path)
    seen = set();order = []
    for start in graph:
        stack = [(start, False)]
        while stack:
            node, finished = stack.pop()
            if finished:order.append(node);continue
            if node in seen:continue
            seen.add(node);stack.append((node, True))
            stack.extend((target, False) for target in sorted(graph[node], reverse=True) if target not in seen)
    seen.clear();cycles = []
    for start in reversed(order):
        if start in seen:continue
        component = [];component_stack = [start];seen.add(start)
        while component_stack:
            node = component_stack.pop();component.append(node)
            for target in reverse[node]:
                if target not in seen:seen.add(target);component_stack.append(target)
        if len(component) > 1 or start in graph[start]:cycles.append(sorted(component))
    return modules, sorted(cycles)
