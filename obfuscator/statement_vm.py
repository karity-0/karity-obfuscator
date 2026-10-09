"""Host factory bank for nested native/VM statement domains."""
from dataclasses import replace

from .names import NameAllocator
from .passes.base import Replacement
from .passes.ts_utils import parse
from .passes.rename_ts import resolve_bindings
from .selection import FUNCTION_TYPES, Span, _apply
from .statement_regions import lower_region, transport_prelude


def run_statement_vm(runtime, template, source, base_options, whole, prefix):
    from .selective_vm import _factory, _replacement, _vm_factories_entry, _vm_build
    from .vm.backend import normalize_vm_backend
    plan = runtime.plan
    def effective_options(options):
        result = {**template._backend.vm_options, **options}
        result["backend"] = normalize_vm_backend(result.get("backend", template.backend))
        return result
    base_options = effective_options(base_options)
    originals = [replace(s) for s in plan.spans if s.feature in {"vm", "no_vm", "no_obf"}]
    virtual = [s for s in plan.spans if s.feature == "vm"]
    native = [s for s in plan.spans if s.feature in {"no_vm", "no_obf"}]
    contains = lambda a, b: a.start <= b.start and b.end <= a.end
    def report_domains():
        for span in originals:
            if span.feature == "vm":
                excluded = [s for s in originals if s.feature in {"no_vm", "no_obf"}
                            and s.start < span.end and span.start < s.end]
                status = "excluded" if any(contains(s, span) for s in excluded) else "partial" if excluded else "applied"
                plan.record("vm", span, status, "native exclusion" if excluded else "statement VM boundary")
            else:
                plan.record("vm", span, "excluded", span.feature.upper())
        if plan.file_vm:
            plan.record("vm", Span(0, len(source), "vm", line=plan.file_vm_line), "applied", "whole chunk with native statement boundaries")
    domains = []
    for span in virtual:
        if any(contains(s, span) for s in native):
            continue
        owners = sorted((s for s in virtual if contains(s, span)), key=lambda s: s.end - s.start, reverse=True)
        options = dict(base_options)
        for owner in owners:
            options = effective_options(runtime.vm_options(owner.options, options))
        parent_options = dict(base_options) if whole else None
        for owner in owners:
            if owner is span:
                break
            parent_options = effective_options(runtime.vm_options(owner.options, parent_options or base_options))
        if parent_options != options:
            domains.append((span, options))
    native_roots = []
    for span in sorted(native, key=lambda s: s.end - s.start, reverse=True):
        if not any(contains(s, span) for s in native_roots):
            native_roots.append(span)
    for span in native_roots:
        if not whole and not any(contains(s, span) for s in virtual):
            continue
        domains.append((span, None))
    if not domains and not whole:
        report_domains()
        return source
    allocator = NameAllocator.for_source(source)
    allocator.used.add("e")
    bank, bank_key, env_key = [allocator.allocate(h) for h in ("host_factories", "bank_key", "env_key")]
    # Declare the bank in the parse context too, so extracted factories capture
    # calls to previously extracted inner domains as ordinary lexical upvalues.
    declaration = f"local {bank};\n"
    source = plan.apply(source, [Replacement(0, -1, declaration)])
    transport_source, transport = transport_prelude(allocator, "5.3")
    transport_added = False
    entries = []
    for index, (span, options) in enumerate(sorted(domains, key=lambda d: d[0].end - d[0].start), 1):
        ctx = parse(source)
        bindings, _, _, _, _ = resolve_bindings(ctx)
        if span.kind == "function":
            node = next(n for n in ctx.walk() if n.type in FUNCTION_TYPES
                        and ctx.cs(n) == span.start and ctx.ce(n) + 1 == span.end)
            factory, bridge = _factory(ctx, node, bindings, allocator, metatable=f"{bank}.m")
            replacement = _replacement(ctx, node, f"{bank}[{index}]({bridge})")
            outside = []
        else:
            region = lower_region(source, ctx, span, allocator, transport=transport)
            if region.needs_transport and not transport_added:
                source = plan.apply(source, [Replacement(len(declaration), len(declaration) - 1, transport_source)])
                for edit in region.outside:
                    edit.start += len(transport_source)
                    edit.end += len(transport_source)
                transport_added = True
            # The helper sees exactly the host slots/vararg packet that will be
            # declared at the callsite. Only its implementation leaves the host.
            temporary = _apply(source, [*region.outside, Replacement(span.start, span.end - 1,
                                                                      region.setup + region.helper)])
            temporary_ctx = parse(temporary)
            helper = next(n for n in temporary_ctx.walk() if n.type == "function_declaration"
                          and temporary_ctx.text(n.child_by_field_name("name")) == region.name)
            temporary_bindings, _, _, _, _ = resolve_bindings(temporary_ctx)
            factory, bridge = _factory(temporary_ctx, helper, temporary_bindings, allocator, metatable=f"{bank}.m")
            replacement = region.replacement(span, f"{bank}[{index}]({bridge})")
            outside = region.outside
        entries.append((index, factory, options))
        source = plan.apply(source, [*outside, replacement])
    # Equal effective options share bytecode and interpreter initialization. The
    # exported factories retain separate live capture bridges at every callsite.
    prelude = f"local {bank}={{m=_ENV.setmetatable}}\n"
    groups = []
    for index, factory, options in entries:
        if options is None:
            prelude += f"{bank}[{index}]={factory}\n"
            continue
        group = next((items for existing, items in groups if existing == options), None)
        if group is None:
            group = []
            groups.append((options, group))
        group.append((index, factory))
    for options, items in groups:
        bundle = allocator.allocate("vm_factories")
        prelude += f"do local {bundle}="
        prelude += _vm_factories_entry(runtime, template, options, items, prefix + prelude, allocator)
        prelude += "\n" + "; ".join(f"{bank}[{index}]={bundle}[{index}]" for index, _ in items) + "\nend\n"
    source = source[len(declaration):]
    if whole:
        root_source = f"local {bank}={bank_key}; local _ENV={env_key};\n" + source
        wrapper = (f"return (function({bank},e) local _ENV=e.setmetatable({{[{bank_key!r}]={bank},[{env_key!r}]=e}},"
                   "{__index=e,__newindex=e})\nreturn (function()\n")
        output = _vm_build(runtime, template, base_options, root_source, prefix + prelude + wrapper)
        result = prelude + wrapper + output + f"\nend)()\nend)({bank},_ENV)"
    else:
        result = prelude + source
    report_domains()
    return result
