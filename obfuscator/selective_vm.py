"""Native/VM boundaries with live lexical capture cells.

Host factories reside outside the root VM. A bridge uses getter/setter closures
over original bindings, preserving reassignment, shared closures and recursion.
Generated VM text is emitted once at its final line position, then left intact.
"""
from __future__ import annotations

from dataclasses import replace

from .passes.base import Replacement
from .passes.rename_ts import _is_reference
from .selection import FUNCTION_TYPES, Span, SelectionError, _ancestors, _apply


def _method(node):
    name = node.child_by_field_name("name")
    return name is not None and name.type == "method_index_expression"


def _parameters(ctx, node):
    text = ctx.text(node.child_by_field_name("parameters"))
    return "(self" + ("," if text[1:-1].strip() else "") + text[1:] if _method(node) else text


def _factory(ctx, node, bindings, allocator, *, metatable="_ENV.setmetatable"):
    body = node.child_by_field_name("body")
    body_start = ctx.cs(body) if body is not None else ctx.ce(node) - 2
    body_end = ctx.ce(body) + 1 if body is not None else body_start
    parameter_node = node.child_by_field_name("parameters")
    owned_start, owned_end = ctx.cs(parameter_node), ctx.ce(node) + 1
    cap = allocator.allocate("captures")
    captured = []
    edits = []
    bound_ids = set()
    for binding in bindings:
        bound_ids.update(n.id for n in binding.nodes)
        refs = [n for n in binding.nodes if body_start <= ctx.cs(n) and ctx.ce(n) < body_end]
        declaration = binding.nodes[0]
        if not refs or owned_start <= ctx.cs(declaration) < owned_end:
            continue
        key = len(captured) + 1
        captured.append((key, binding.original))
        edits.extend(Replacement(ctx.cs(n) - body_start, ctx.ce(n) - body_start, f"{cap}[{key}]") for n in refs)
    # The lexical resolver represents a method's implicit self without a token.
    # When an inner closure is selected, self is a live outer capture.
    outer_self = not _method(node) and any(_method(a) for a in _ancestors(node) if a.type in FUNCTION_TYPES)
    free_nodes = [n for n in ctx.walk() if n.type == "identifier" and body_start <= ctx.cs(n) < body_end
                  and n.id not in bound_ids and _is_reference(n)]
    self_refs = [n for n in free_nodes if ctx.text(n) == "self" and not any(
        a.type in FUNCTION_TYPES and _method(a) and body_start <= ctx.cs(a) < body_end
        for a in _ancestors(n))] if outer_self else []
    if self_refs:
        key = len(captured) + 1
        captured.append((key, "self"))
        edits.extend(Replacement(ctx.cs(n) - body_start, ctx.ce(n) - body_start, f"{cap}[{key}]") for n in self_refs)
    edits.extend(Replacement(ctx.cs(n) - body_start, ctx.ce(n) - body_start, f"{cap}.e")
                 for n in free_nodes if ctx.text(n) == "_ENV")

    # A captured object in `function object:method()` needs assignment syntax;
    # replacing its name with captures[1] inside a declaration is invalid Lua.
    header_edits = []
    for child in ctx.walk():
        if child.type != "function_declaration" or not (body_start <= ctx.cs(child) < body_end):
            continue
        name = child.child_by_field_name("name")
        params = child.child_by_field_name("parameters")
        if name is None or child.children[0].type == "local":
            continue
        a, b = ctx.cs(name) - body_start, ctx.ce(name) + 1 - body_start
        replacements = [Replacement(r.start - a, r.end - a, r.new_text) for r in edits if a <= r.start and r.end < b]
        if not replacements:
            continue
        rewritten_name = _apply(ctx.text(name), replacements)
        if _method(child):
            rewritten_name = rewritten_name.rsplit(":", 1)
            rewritten_name = ".".join(rewritten_name)
        header_edits.append(Replacement(ctx.cs(child) - body_start, ctx.ce(params) - body_start,
                                        rewritten_name + "=function" + _parameters(ctx, child)))
    edits = [r for r in edits if not any(h.start <= r.start and r.end <= h.end for h in header_edits)] + header_edits
    body_text = _apply(ctx.script[body_start:body_end], edits)
    factory = f"function({cap})\nlocal _ENV={cap}.g\nreturn function{_parameters(ctx, node)}\n{body_text}\nend\nend"

    value_arg, key_arg, ignore_arg = [allocator.allocate(h) for h in ("value", "key", "ignored")]
    getters = [f"[{key}]=function() return {name} end" for key, name in captured]
    setters = [f"[{key}]=function({value_arg}) {name}={value_arg} end" for key, name in captured]
    getters.append("e=function() return _ENV end")
    setters.append(f"e=function({value_arg}) _ENV={value_arg} end")
    get, put, env = [allocator.allocate(h) for h in ("get", "put", "env")]
    bridge = (f"(function() local {get}={{{','.join(getters)}}}; local {put}={{{','.join(setters)}}}; "
              f"local {env}={metatable}({{}},{{__index=function({ignore_arg},{key_arg}) return _ENV[{key_arg}] end,"
              f"__newindex=function({ignore_arg},{key_arg},{value_arg}) _ENV[{key_arg}]={value_arg} end}}); "
              f"return {metatable}({{g={env}}},{{__index=function({ignore_arg},{key_arg}) return {get}[{key_arg}]() end,"
              f"__newindex=function({ignore_arg},{key_arg},{value_arg}) {put}[{key_arg}]({value_arg}) end}}) end)()")
    return factory, bridge


def _replacement(ctx, node, expression):
    if node.type == "function_definition":
        return Replacement(ctx.cs(node), ctx.ce(node), expression)
    name = ctx.text(node.child_by_field_name("name"))
    if node.children[0].type == "local":
        # local function f makes f visible to its own closure before assignment.
        text = f"local {name}; {name}={expression}"
    else:
        if _method(node):
            name = ".".join(name.rsplit(":", 1))
        text = f"{name}={expression}"
    return Replacement(ctx.cs(node), ctx.ce(node), text)


def _vm_build(runtime, template, options, source, prefix):
    from .vm.vm_pass import VMPass
    target = replace(template.target_profile, backend=options.get("backend", template.backend))
    vm = VMPass(vm_options=options, vm_output_passes=template.vm_output_passes,
                toolchain=template.toolchain, target=target, output_prefix="\n" * prefix.count("\n"),
                debug_dumps=template._backend.debug_dumps)
    vm._backend.isolate_runtime_globals = True
    output = vm.run(source)
    template.last_profile.extend(vm.last_profile)
    for field in ("last_source_ir", "last_optimized_ir", "last_protected_ir", "last_semantic_ir",
                  "last_protection_plan", "last_lowered_ir"):
        setattr(template, field, getattr(vm, field))
    return output


def _vm_factories_entry(runtime, template, options, factories, prefix, allocator):
    # Existing VM runners execute the root chunk for its effects and do not
    # expose its return packet. Publish each factory into a private HOST table.
    # A table constructed inside bytecode may have virtualized keys and cannot
    # be indexed directly by host source when table_virtualization is enabled.
    cell, environment, key = [allocator.allocate(h) for h in ("factory_cell", "environment", "factory_key")]
    intro = (f"(function() local {cell}={{}}; local {environment}=_ENV; "
             f"local _ENV={environment}.setmetatable({{[{key!r}]={cell}}},{{__index={environment},__newindex={environment}}}); "
             "(function()\n")
    source = "\n".join(f"{key}[{index}]={factory}" for index, factory in factories)
    output = _vm_build(runtime, template, options, source, prefix + intro)
    return intro + output + f"\nend)(); return {cell} end)()"


def _whole_chunk_excluded(source, exclusions):
    from .passes.ts_utils import parse
    ctx = parse(source)
    if ctx.root.has_error:
        return False
    # Check complete top-level statements, not overlapping ranges: excluding
    # only a function's body must not exclude its declaration or native caller.
    return all(any(span.start <= ctx.cs(node) and ctx.ce(node) < span.end
                   for span in exclusions)
               for node in ctx.root.named_children
               if node.type not in {"comment", "hash_bang_line", "empty_statement"})


def run_selective_vm(runtime, template, source):
    plan = runtime.plan
    template.last_profile = []
    base_options = {**template.vm_options, **runtime.vm_options(plan.file_vm_options)}
    # Flat configs and a plain @VM retain the existing whole-script fast path.
    whole = plan.file_vm or plan.modes.get("vm", "all") == "all"
    vm_spans = [s for s in plan.spans if s.feature == "vm"]
    exclusions = [s for s in plan.spans if s.feature in {"no_vm", "no_obf"}]
    if whole:
        fully_excluded = bool(exclusions) and _whole_chunk_excluded(source, exclusions)
    else:
        fully_excluded = all(any(s.start <= span.start and span.end <= s.end for s in exclusions)
                             for span in vm_spans)
    if fully_excluded:
        # No VM/native bridge is needed when every requested region is excluded.
        # Resolve this before checking boundary target support (e.g. Lua 5.1).
        for span in vm_spans:
            plan.record("vm", span, "excluded", "native exclusion")
        for span in exclusions:
            plan.record("vm", span, "excluded", span.feature.upper())
        if plan.file_vm:
            plan.record("vm", Span(0, len(source), "vm", line=plan.file_vm_line),
                        "excluded", "whole chunk has only native statements")
        return source
    if whole and not exclusions and not vm_spans:
        if plan.file_vm:
            plan.record("vm", Span(0, len(source), "vm", line=plan.file_vm_line), "applied", "whole chunk")
        if base_options == template.vm_options:
            return template.run(source)
        prefix = template.output_prefix
        return _vm_build(runtime, template, base_options, source, prefix)

    if template.target_profile.lua_version != "5.3":
        raise SelectionError("selective VM/native boundaries currently require Lua 5.3")
    signature = runtime.pipeline._output_signature
    from .passes.packer import PackerPass
    prefix = signature.prefix if signature is not None and not any(isinstance(p, PackerPass) for p in runtime.pipeline._post_passes) else ""
    from .statement_vm import run_statement_vm
    return run_statement_vm(runtime, template, source, base_options, whole, prefix)
