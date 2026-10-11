"""Compile-time source selections. Coordinates are Unicode character offsets.

Markers are read before any pass removes comments. A plan follows replacements
through the pipeline; it is never rediscovered in generated Lua helpers.
"""
from __future__ import annotations

# Load processing dependencies only when the corresponding feature is used.
__lazy_modules__ = {
    "obfuscator.passes.ts_utils",
}

import ast
from dataclasses import dataclass, field
import difflib
import re

from .passes.base import Replacement
from .passes.ts_utils import parse

MACROS = {"STRING_OBF": "string_obf", "NUMBER_OBF": "number_obf",
          "BOOLEAN_OBF": "boolean_obf", "TABLE_OBF": "table_obf"}
FUNCTION_TYPES = {"function_declaration", "function_definition"}
SELECTABLE = frozenset((*MACROS.values(), "function_obf", "meme_strings", "vm"))
_REGION_FEATURES = {'VM':'vm','FUNCTION_OBF':'function_obf','NO_VM':'no_vm',
                    'NO_OBF':'no_obf','NUMBER_OBF':'number_obf','MEME_STRINGS':'meme_strings'}
_TOKEN = re.compile(
    r"(?P<longcomment>--\[(?P<ceq>=*)\[.*?\](?P=ceq)\])"
    r"|(?P<comment>--[^\r\n]*)"
    r"|(?P<longstring>\[(?P<seq>=*)\[.*?\](?P=seq)\])"
    r'''|(?P<string>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')'''
    r"|(?P<space>\s+)|(?P<name>[A-Za-z_][A-Za-z_0-9]*)|(?P<other>.)",
    re.DOTALL,
)
_DIRECTIVE = re.compile(r"@([A-Z][A-Z_]*)(.*)$")


class SelectionError(ValueError):
    pass


@dataclass
class Span:
    start: int
    end: int
    feature: str
    options: dict = field(default_factory=dict)
    line: int = 1
    kind: str = "region"


def _error(source, position, message):
    line = source.count("\n", 0, position) + 1
    column = position - source.rfind("\n", 0, position)
    raise SelectionError(f"line {line}, column {column}: {message}")


def _without_comments(text):
    return "".join(" " * len(t.group()) if t.lastgroup in {"comment", "longcomment"} else t.group()
                   for t in _TOKEN.finditer(text))


def _options(source, position, tail, feature):
    if not tail.strip():
        return {}
    try:
        call = ast.parse("options" + tail.strip(), mode="eval").body
        if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name) or call.func.id != "options":
            raise ValueError()
        result = {}
        flags = []
        for item in call.args:
            if not isinstance(item, ast.Name):
                raise ValueError()
            flags.append(item.id)
        for item in call.keywords:
            if item.arg is None or item.arg in result:
                raise ValueError()
            if isinstance(item.value, ast.Name) and item.value.id in {"true", "false"}:
                value = item.value.id == "true"
            else:
                value = ast.literal_eval(item.value)
            result[item.arg] = value
        if len(set(flags)) != len(flags) or set(flags) & set(result):
            raise ValueError()
        if feature == "function_obf" and flags:
            known = {"cff", "junk", "inline", "wrapper", "split", "loop_split", "loop_unroll"}
            if set(flags) - known:
                raise ValueError("unknown function feature: " + ", ".join(sorted(set(flags) - known)))
            result = {**{key: key in flags for key in known - {"split"}}, **result}
            if "split" in flags:
                if result.get("cff") is False and "cff" in {item.arg for item in call.keywords}:
                    raise ValueError("split requires cff")
                result["cff"] = True
                result["boundary_mode"] = "split"
        else:
            result.update({key: True for key in flags})
        return result
    except (SyntaxError, ValueError, TypeError) as error:
        _error(source, position, f"invalid {feature} options: {error or 'use flags and key=value literals'}")


def validate_modes(modes):
    if not isinstance(modes, dict):
        raise ValueError("selection_modes must be an object")
    for name, mode in modes.items():
        if name not in SELECTABLE or not isinstance(mode, str) or mode not in {"all", "marked"}:
            raise ValueError(f"invalid selection_modes entry {name}={mode!r}; use a selectable pass and all/marked")


class SelectionPlan:
    def __init__(self, source, modes=None):
        self.spans: list[Span] = []
        self.report: list[dict] = []
        self.modes = dict(modes or {})
        validate_modes(self.modes)
        self.file_vm = False
        self.file_vm_line = 1
        self.file_vm_options = {}
        self.active = False
        if not self.modes and not re.search(r"\b(?:STRING_OBF|NUMBER_OBF|BOOLEAN_OBF|TABLE_OBF)\b|(?:^|\n)\s*(?:--\s*)?@", source):
            self.source = source
            return
        self.source = self._read(source)

    def _read(self, source):
        edits = []
        directives = []
        tokens = list(_TOKEN.finditer(source))
        ignored_end = -1
        for token in tokens:
            if token.start() < ignored_end:
                continue
            kind = token.lastgroup
            position = token.start()
            text = token.group()
            if kind == "comment":
                candidate = text[2:].strip()
                if not candidate.startswith("@"):
                    continue
            elif kind == "other" and text == "@":
                end = source.find("\n", position)
                end = len(source) if end < 0 else end
                candidate = source[position:end].strip()
                ignored_end = end
            else:
                continue
            # A directive occupies its own physical line. Long comments and
            # strings never reach here, including text resembling directives.
            line_start = source.rfind("\n", 0, position) + 1
            if source[line_start:position].strip():
                _error(source, position, "directives must be on their own lines")
            match = _DIRECTIVE.fullmatch(candidate)
            if match is None:
                _error(source, position, "malformed obfuscation directive")
            end = source.find("\n", position)
            end = len(source) if end < 0 else end
            directives.append((position, end, match[1], _without_comments(match[2])))
            edits.append(Replacement(position, end - 1, " " * (end - position)))

        lowered = _apply(source, edits)
        ctx = parse(lowered)
        if ctx.root.has_error:
            _error(source, 0, "invalid Lua source after removing directives")
        functions = sorted((n for n in ctx.walk() if n.type in FUNCTION_TYPES), key=ctx.cs)
        stack = []
        for start, end, name, tail in directives:
            if name == "VM":
                if lowered[:start].strip() and any(t.lastgroup not in {"space", "comment", "longcomment"}
                                                 for t in _TOKEN.finditer(lowered[:start])):
                    _error(source, start, "@VM must precede Lua code")
                if self.file_vm:
                    _error(source, start, "duplicate @VM")
                self.file_vm = True
                self.file_vm_line = source.count("\n", 0, start) + 1
                self.file_vm_options = _options(source, start, tail, "vm")
            elif name in {"FUNCTION_OBF", "NO_VM"}:
                feature = "function_obf" if name == "FUNCTION_OBF" else "no_vm"
                opts = _options(source, start, tail, feature)
                candidates = [n for n in functions if ctx.cs(n) >= end]
                if not candidates:
                    _error(source, start, f"@{name} requires a following function")
                node = candidates[0]
                gap = lowered[end:ctx.cs(node)]
                # Permit local x = function(...) as well as declarations.
                gap = _without_comments(gap).strip()
                if gap and not re.fullmatch(r"local\s+[A-Za-z_]\w*\s*=\s*", gap):
                    _error(source, start, f"@{name} must immediately precede a function")
                if feature == "no_vm" and opts:
                    _error(source, start, "@NO_VM accepts no options")
                self.spans.append(Span(ctx.cs(node), ctx.ce(node) + 1, feature, opts,
                                       source.count("\n", 0, start) + 1, "function"))
            elif name.endswith("_START") and name[:-6] in _REGION_FEATURES:
                base = name[:-6]
                feature = _REGION_FEATURES[base]
                opts = _options(source, start, tail, feature)
                if (feature.startswith("no_") or feature in {'number_obf','meme_strings'}) and opts:
                    _error(source, start, f"@{name} accepts no options")
                stack.append((start, end, base, feature, opts))
            elif name.endswith("_END") and name[:-4] in _REGION_FEATURES:
                if tail.strip() or not stack or stack[-1][2] != name[:-4]:
                    _error(source, start, f"unmatched @{name}")
                opening, body_start, _, feature, opts = stack.pop()
                line = source.count("\n", 0, opening) + 1
                if feature == "function_obf":
                    owners = [n for n in functions if ctx.cs(n) < body_start and start <= ctx.ce(n)]
                    node = min(owners, key=lambda n: ctx.ce(n) - ctx.cs(n)) if owners else None
                    if node is None:
                        _error(source, opening, "FUNCTION_OBF_START must enclose a complete function body; use @FUNCTION_OBF before a declaration")
                    body = node.child_by_field_name("body")
                    if body is not None and not (body_start <= ctx.cs(body) and ctx.ce(body) < start):
                        self._validate_region(source, lowered, ctx, body_start, start, feature)
                        self.spans.append(Span(body_start, start, feature, opts, line))
                    else:
                        self.spans.append(Span(ctx.cs(node), ctx.ce(node) + 1, feature, opts, line, "function"))
                else:
                    self._validate_region(source, lowered, ctx, body_start, start, feature)
                    self.spans.append(Span(body_start, start, feature, opts, line))
            else:
                _error(source, start, f"unknown directive @{name}")
        if stack:
            _error(source, stack[-1][0], f"missing @{stack[-1][2]}_END")
        function_targets = set()
        for span in self.spans:
            if span.feature == "function_obf":
                target = (span.start, span.end)
                if target in function_targets:
                    raise SelectionError(f"line {span.line}: duplicate function protection selection")
                function_targets.add(target)

        # Macro calls are ordinary Lua AST nodes until this lowering step.
        # Name declarations/references are reserved, never runtime identity calls.
        macro_nodes = []
        from .passes.rename_ts import _is_reference
        for node in ctx.walk():
            if node.type != "identifier" or ctx.text(node) not in MACROS:
                continue
            parent = node.parent
            if not _is_reference(node):
                continue
            if parent.type != "function_call" or parent.child_by_field_name("name") != node:
                _error(source, ctx.cs(node), f"{ctx.text(node)} is a reserved compile-time macro")
            arguments = parent.child_by_field_name("arguments")
            args = [n for n in arguments.named_children if n.type != "comment"]
            if len(args) != 1 or arguments.children[0].type != "(":
                _error(source, ctx.cs(node), "macros require exactly one parenthesized argument")
            arg = args[0]
            feature = MACROS[ctx.text(node)]
            expected = {"string_obf": {"string"}, "number_obf": {"number", "unary_expression"},
                        "boolean_obf": {"true", "false"}, "table_obf": {"table_constructor"}}[feature]
            if arg.type not in expected or (arg.type == "unary_expression" and
                    not (ctx.text(arg).lstrip().startswith("-") and len(arg.named_children) == 1 and arg.named_children[0].type == "number")):
                _error(source, ctx.cs(arg), f"{ctx.text(node)} requires a literal of the corresponding type")
            self.spans.append(Span(ctx.cs(arg), ctx.ce(arg) + 1, feature, {},
                                   source.count("\n", 0, ctx.cs(node)) + 1, "macro"))
            macro_nodes.append((node, parent, arguments))
        macro_edits = []
        for name, call, arguments in macro_nodes:
            # Keep parentheses, including the one-value behavior of literals.
            macro_edits.append(Replacement(ctx.cs(name), ctx.cs(arguments) - 1, ""))
        self.active = bool(directives or macro_nodes or self.modes)
        lowered = self.apply(lowered, macro_edits)
        return lowered

    @staticmethod
    def _validate_region(source, lowered, ctx, start, end, feature):
        # Validate against statement siblings, never indentation or regex alone.
        statements = [n for n in ctx.walk() if n.parent is not None and n.parent.type in {"chunk", "block"}
                      and n.type not in {"comment"} and start <= ctx.cs(n) and ctx.ce(n) < end]
        roots = [n for n in statements if not any(start <= ctx.cs(a) and ctx.ce(a) < end
                                                  for a in _ancestors(n) if a in statements)]
        masked = list(lowered[start:end])
        for n in roots:
            masked[ctx.cs(n) - start:ctx.ce(n) + 1 - start] = " " * (ctx.ce(n) + 1 - ctx.cs(n))
        rest = _without_comments("".join(masked)).strip()
        if rest or (roots and len({n.parent.id for n in roots}) != 1):
            _error(source, start, "region boundaries must surround complete statements in the same Lua block")
        if feature in {"vm", "no_vm", "function_obf"} and not roots:
            _error(source, start, "protection regions require at least one complete statement")
        return roots

    def excluded(self, start, end, vm=False):
        kinds = {"no_obf", "no_vm"} if vm else {"no_obf"}
        return any(s.feature in kinds and s.start < end and start < s.end for s in self.spans)

    def selected(self, feature, start, end):
        if self.excluded(start, end, feature == "vm"):
            return False
        return self.modes.get(feature, "all") == "all" or any(
            s.feature == feature and s.start <= start and end <= s.end for s in self.spans)

    def explicit(self, feature):
        return any(s.feature == feature for s in self.spans) or (feature == "vm" and self.file_vm)

    def record(self, feature, span, status, reason=""):
        self.report.append({"feature": feature, "line": span.line, "status": status, "reason": reason})

    def apply(self, source, replacements):
        replacements = sorted(replacements, key=lambda r: (r.start, r.end))
        result = _apply(source, replacements)
        # Each edit uses old coordinates. Update from right to left so every
        # remaining edit retains its original position, including insertions.
        for r in reversed(replacements):
            old_end = r.end + 1
            delta = len(r.new_text) - (old_end - r.start)
            for span in self.spans:
                if old_end <= span.start:
                    span.start += delta
                    span.end += delta
                elif r.start < span.end:
                    if r.start <= span.start:
                        span.start = r.start
                    span.end = span.end + delta if old_end <= span.end else r.start + len(r.new_text)
        return result

    def follow_text(self, before, after):
        if before == after:
            return after
        # Pre-passes do not expose Replacement objects. This path is only used
        # for annotated source, never for the large generated VM/packer output.
        edits = [Replacement(a, b - 1, after[c:d]) for op, a, b, c, d in
                 difflib.SequenceMatcher(None, before, after, autojunk=False).get_opcodes() if op != "equal"]
        return self.apply(before, edits)


def _ancestors(node):
    node = node.parent
    while node is not None:
        yield node
        node = node.parent


def _walk(node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.named_children))


def _apply(source, replacements):
    from .passes.numeric_provenance import join_code
    parts, position = [], 0
    for r in sorted(replacements, key=lambda r: (r.start, r.end)):
        if not (0 <= r.start <= len(source) and r.start - 1 <= r.end < len(source)):
            raise SelectionError("selection replacement is outside the source")
        if r.start < position:
            raise SelectionError("overlapping selection replacements")
        parts.extend((source[position:r.start], r.new_text))
        position = r.end + 1
    return join_code((*parts, source[position:]))
