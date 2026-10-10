"""Integrate source selections with existing passes without changing defaults."""
from __future__ import annotations

# Load processing dependencies only when the corresponding feature is used.
__lazy_modules__ = {
    "obfuscator.passes.ts_utils",
}

import difflib

from .selection import SelectionPlan, Span, SelectionError, SELECTABLE, FUNCTION_TYPES, _ancestors
from .passes.base import Replacement
from .passes.ts_utils import parse


class _SelectedTree:
    def __init__(self, tree, plan, feature):
        self.tree, self.plan, self.feature = tree, plan, feature

    def __getattr__(self, name):
        return getattr(self.tree, name)

    def walk(self):
        return (n for n in self.tree.walk() if self.plan.selected(self.feature, self.tree.cs(n), self.tree.ce(n) + 1))


class SelectionRuntime:
    def __init__(self, pipeline, source):
        from .registry import PASS_REGISTRY
        self.pipeline = pipeline
        self.config = pipeline.selection_config
        self.plan = SelectionPlan(source, self.config.get("selection_modes", {}))
        self.enabled = self.plan.active
        class_names = {info.class_name: name for name, info in PASS_REGISTRY.items()}
        self.names = {type(p): class_names.get(type(p).__name__)
                      for p in (*pipeline._pre_passes, *pipeline._passes, *pipeline._post_passes)}
        self.vm_finished = False
        self._function_defaults = {}
        for span in self.plan.spans:
            try:
                if any(value is None for value in span.options.values()):
                    raise ValueError("directive options cannot be null")
                if span.feature == "function_obf":
                    self.function_options(span.options)
                elif span.feature == "vm":
                    self.vm_options(span.options)
            except (ValueError, TypeError) as error:
                raise SelectionError(f"line {span.line}: {error}") from error
        if self.plan.file_vm:
            try:
                if any(value is None for value in self.plan.file_vm_options.values()):
                    raise ValueError("directive options cannot be null")
                self.vm_options(self.plan.file_vm_options)
            except (ValueError, TypeError) as error:
                raise SelectionError(f"line {self.plan.file_vm_line}: {error}") from error

    def function_options(self, options):
        from .registry import _validate_function_obf_options
        _validate_function_obf_options(options)
        return {**self._function_defaults, **self.config.get("function_obf_options", {}), **options}

    def vm_options(self, options, base=None):
        from .registry import _validate_vm_options, resolve_config_profile
        result = dict(self.config.get("vm_options", {}) if base is None else base)
        options = dict(options)
        preset = options.pop("profile", None)
        if preset is not None:
            profiles = {**self.config.get("_selection_profiles", {}), **self.config.get("selection_profiles", {})}
            if preset not in profiles:
                raise SelectionError(f"unknown VM selection profile {preset!r}; configure selection_profiles")
            resolved = resolve_config_profile(profiles[preset])
            result.update(resolved.get("vm_options", {}))
        result.update(options)
        _validate_vm_options(result)
        return result

    def base_passes(self, passes):
        from .registry import PASS_REGISTRY
        from .vm.targets.pass_requirements import validate_pass_target
        from .vm.targets.profile import TargetProfile
        present = {self.names.get(type(p)) for p in passes}
        extra = []
        for feature in ("string_obf", "boolean_obf", "number_obf", "table_obf", "function_obf"):
            if self.plan.explicit(feature) and feature not in present:
                targets = [s for s in self.plan.spans if s.feature == feature]
                if self.plan.modes.get(feature, "marked") == "marked" and all(
                        self.plan.excluded(s.start, s.end) for s in targets):
                    for span in targets:
                        self.plan.record(feature, span, "excluded", "NO_OBF")
                    self.plan.spans = [s for s in self.plan.spans if s not in targets]
                    continue
                try:
                    validate_pass_target(feature, getattr(self.pipeline, "target_profile", TargetProfile()))
                except ValueError as error:
                    raise SelectionError(f"line {targets[0].line}: {error}") from error
                extra.append(PASS_REGISTRY[feature]["cls"](**(self.config.get("function_obf_options", {})
                                                            if feature == "function_obf" else {})))
                self.names[type(extra[-1])] = feature
                self.plan.modes.setdefault(feature, "marked")
        # New macro passes precede final renaming; existing pass order is retained.
        from .passes.rename_obfuscation import RenameObfuscationPass
        index = next((i for i, p in enumerate(passes) if isinstance(p, RenameObfuscationPass)), len(passes))
        result = passes[:index] + extra + passes[index:]
        if self.plan.explicit("table_obf"):
            tables = [p for p in result if self.names.get(type(p)) == "table_obf"]
            result = [p for p in result if p not in tables]
            index = max((i + 1 for i, p in enumerate(result) if self.names.get(type(p)) in
                         {"string_obf", "boolean_obf", "number_obf"}), default=0)
            result[index:index] = tables
        if any(s.kind == "macro" for s in self.plan.spans):
            functions = [p for p in result if self.names.get(type(p)) == "function_obf"]
            result = [p for p in result if p not in functions]
            index = max((i + 1 for i, p in enumerate(result) if self.names.get(type(p)) in
                         {"string_obf", "boolean_obf", "number_obf", "table_obf"}), default=0)
            result[index:index] = functions
        return result

    def post_passes(self, passes):
        from .vm.vm_pass import VMPass
        from .passes.minify import MinifyPass
        from .passes.packer import PackerPass
        from .vm.targets.profile import TargetProfile
        if self.plan.explicit("vm") and not any(isinstance(p, VMPass) for p in passes):
            output_passes = list(self.config.get("vm_output_passes", []))
            if any(isinstance(p, MinifyPass) for p in passes):
                output_passes.append("minify")
                passes = [p for p in passes if not isinstance(p, MinifyPass)]
            vm = VMPass(vm_options=self.config.get("vm_options", {}), vm_output_passes=output_passes,
                        toolchain=getattr(self.pipeline, "toolchain", None),
                        target=getattr(self.pipeline, "target_profile", TargetProfile()),
                        output_prefix=self.pipeline._output_signature.prefix if self.pipeline._output_signature
                        and not any(isinstance(p, PackerPass) for p in passes) else "")
            self.plan.modes.setdefault("vm", "marked")
            passes = [vm, *passes]
        return passes

    def run_pre(self, pre, source):
        name = self.names.get(type(pre), type(pre).__name__)
        if any(s.feature == "no_obf" for s in self.plan.spans) and name in {"strip_info", "anti_debug"}:
            # These pre-passes include nonlocal symbol/field changes or a whole
            # script wrapper. Preserve exclusions instead of partially applying
            # their edits and breaking lexical bindings or field accesses.
            self.plan.record(name, Span(0, len(source), name), "skipped", "whole-source pre-pass conflicts with NO_OBF")
            return source
        after = pre.run(source)
        if name == "remove_comment" and any(s.feature == "no_obf" for s in self.plan.spans):
            edits = [Replacement(a, b - 1, after[c:d]) for op, a, b, c, d in
                     difflib.SequenceMatcher(None, source, after, autojunk=False).get_opcodes()
                     if op != "equal" and not self.plan.excluded(a, b)]
            return self.plan.apply(source, edits)
        return self.plan.follow_text(source, after)

    def _function_selection(self, tree, node):
        start, end = tree.cs(node), tree.ce(node) + 1
        if self.plan.excluded(start, end):
            return None
        owners = sorted((s for s in self.plan.spans if s.feature == "function_obf"
                         and s.start <= start and end <= s.end), key=lambda s: s.end - s.start)
        if owners and owners[0].kind == "skip":
            return None
        if self.plan.modes.get("function_obf", "all") == "marked" and not owners:
            return None
        options = self.function_options({})
        for owner in reversed(owners):
            options.update(owner.options)
        if owners and (start != owners[0].start or end != owners[0].end):
            if not options.get("nested", True):
                return None
            depth = sum(1 for a in _ancestors(node) if a.type in FUNCTION_TYPES
                        and owners[0].start <= tree.cs(a) and tree.ce(a) < owners[0].end)
            if depth > options.get("nested_max_depth", 4):
                return None
        elif not owners:
            depth = sum(a.type in FUNCTION_TYPES for a in _ancestors(node))
            if depth and (not options.get("nested", True) or depth > options.get("nested_max_depth", 4)):
                return None
        # Replacing an enclosing function destroys the positions of an explicit
        # nested target. Process the nested target and leave its parent intact.
        nested = [s for s in self.plan.spans if s.feature in {"vm", "no_vm", "function_obf", "no_obf"}
                  and start <= s.start and s.end <= end and (s.start, s.end) != (start, end)]
        if nested:
            return None
        return options

    def prepare_base(self, pass_, source):
        if self.names.get(type(pass_)) != "function_obf":
            return source
        # Direct Pipeline users configure the pass instance without a config
        # dictionary. Those defaults also govern region lowering and nesting.
        self._function_defaults = {
            **pass_.features,
            **{key: getattr(pass_, key) for key in ("boundary_mode", "nested", "nested_max_depth")},
            **{"loop_" + key: value for key, value in pass_.compound_options.items()},
        }
        from .statement_regions import lower_region, transport_prelude
        from .names import NameAllocator
        from .passes.ts_utils import parse
        allocator = NameAllocator.for_source(source)
        from .vm.targets.profile import TargetProfile
        version = getattr(self.pipeline, "target_profile", TargetProfile()).lua_version
        transport_source, transport = transport_prelude(allocator, version)
        transport_added = False
        regions = sorted((s for s in self.plan.spans if s.feature == "function_obf" and s.kind == "region"),
                         key=lambda s: s.end - s.start)
        for span in regions:
            nested = any(s is not span and s.feature in {"vm", "no_vm", "function_obf"}
                         and span.start <= s.start and s.end <= span.end for s in self.plan.spans)
            if self.plan.excluded(span.start, span.end) or nested:
                self.plan.record("function_obf", span, "excluded" if self.plan.excluded(span.start, span.end) else "skipped",
                                 "NO_OBF" if self.plan.excluded(span.start, span.end) else "nested protection boundary")
                span.kind = "skip"
                continue
            owners = sorted((s for s in self.plan.spans if s.feature == "function_obf"
                             and s.start <= span.start and span.end <= s.end), key=lambda s: s.end - s.start, reverse=True)
            options = self.function_options({})
            for owner in owners:
                options.update(owner.options)
            if not any(options.get(k, True) for k in ("cff", "junk", "wrapper")):
                self.plan.record("function_obf", span, "skipped", "disabled function features")
                span.kind = "skip"
                continue
            ctx = parse(source)
            region = lower_region(source, ctx, span, allocator, version, transport=transport)
            if any(self.plan.excluded(edit.start, edit.end + 1) for edit in region.outside):
                self.plan.record("function_obf", span, "skipped", "exported binding referenced by NO_OBF")
                span.kind = "skip"
                continue
            if region.needs_transport and not transport_added:
                source = self.plan.apply(source, [Replacement(0, -1, transport_source)])
                for edit in region.outside:
                    edit.start += len(transport_source)
                    edit.end += len(transport_source)
                transport_added = True
            replacement = Replacement(span.start, span.end - 1,
                                      region.setup + region.helper + region.left + region.name + "()" + region.right)
            source = self.plan.apply(source, [*region.outside, replacement])
            ctx = parse(source)
            node = next(n for n in ctx.walk() if n.type == "function_declaration"
                        and ctx.text(n.child_by_field_name("name")) == region.name)
            span.start, span.end, span.kind = ctx.cs(node), ctx.ce(node) + 1, "function"
        return source

    def run_base(self, pass_, source, tree):
        name = self.names.get(type(pass_))
        if name == "rename_obf":
            from .passes.rename_ts import rename_plan_with_ctx_profiled
            return rename_plan_with_ctx_profiled(tree, **pass_.options,
                keep=lambda binding: any(self.plan.excluded(tree.cs(n), tree.ce(n) + 1) for n in binding.nodes))[0]
        if name == "function_obf":
            pass_.selection_resolver = self._function_selection
            try:
                replacements = pass_.run(source, tree)
            finally:
                pass_.selection_resolver = None
        elif name in SELECTABLE:
            replacements = pass_.run(source, _SelectedTree(tree, self.plan, name))
        else:
            replacements = [r for r in pass_.run(source, tree) if not self.plan.excluded(r.start, r.end + 1)
                            and not any(s.kind == "macro" and s.feature != name and s.start <= r.end and r.start < s.end
                                        for s in self.plan.spans)]
        for span in self.plan.spans:
            if span.feature != name or span.kind == "skip":
                continue
            if self.plan.excluded(span.start, span.end):
                status, reason = "excluded", "NO_OBF"
            elif name == "function_obf":
                nodes = [n for n in tree.walk() if n.type in FUNCTION_TYPES and tree.cs(n) == span.start and tree.ce(n) + 1 == span.end]
                changed = any(pass_.last_selection_results.get(n.id, False) for n in nodes)
                status, reason = ("applied", "") if changed else ("skipped", "eligibility, nesting or boundary constraint")
            elif any(r.start < span.end and span.start <= r.end and source[r.start:r.end + 1] != r.new_text for r in replacements):
                status, reason = "applied", ""
            else:
                status, reason = "skipped", "eligibility, nesting or boundary constraint"
            self.plan.record(name, span, status, reason)
        # Consumed macro locations no longer need to follow later structural
        # rewrites. Their report entries retain the original source line.
        self.plan.spans = [s for s in self.plan.spans if not (s.kind == "macro" and s.feature == name)]
        return replacements

    def run_post(self, post, source):
        from .vm.vm_pass import VMPass
        from .passes.minify import MinifyPass
        if isinstance(post, VMPass):
            from .selective_vm import run_selective_vm
            result = run_selective_vm(self, post, source)
            self.vm_finished = bool(post.last_profile)
            return result
        if self.vm_finished:
            if isinstance(post, MinifyPass):
                raise SelectionError("minify after a selective VM would invalidate integrity; put it in vm_output_passes")
            return post.run(source)
        if isinstance(post, MinifyPass) and any(s.feature == "no_obf" for s in self.plan.spans):
            after = post.run(source)
            edits = [Replacement(a, b - 1, after[c:d]) for op, a, b, c, d in
                     difflib.SequenceMatcher(None, source, after, autojunk=False).get_opcodes()
                     if op != "equal" and not self.plan.excluded(a, b)]
            return self.plan.apply(source, edits)
        return self.plan.follow_text(source, post.run(source))
