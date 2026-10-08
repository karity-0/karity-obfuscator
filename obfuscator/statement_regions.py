"""Lower statement domains without copying lexical state across boundaries.

Escaping locals get fresh host slots; declaration RHS references retain their
original binding. Escaping returns/breaks use a counted result packet, while
control flow and declarations in nested functions/blocks remain local.
"""
from dataclasses import dataclass

from .passes.base import Replacement
from .passes.rename_ts import resolve_bindings
from .selection import FUNCTION_TYPES, SelectionError, SelectionPlan, _ancestors, _apply


def _owner(node, types=FUNCTION_TYPES):
    return next((a for a in _ancestors(node) if a.type in types), None)


@dataclass
class Region:
    helper: str
    name: str
    setup: str
    left: str
    right: str
    outside: list
    needs_transport: bool

    def replacement(self, span, expression=None):
        return Replacement(span.start, span.end - 1,
                           self.setup + self.left + (expression or self.name) + "()" + self.right)


def transport_prelude(allocator, lua_version):
    select, pack, unpack = [allocator.allocate(h) for h in ("select", "pack", "unpack")]
    environment = "_ENV." if lua_version != "5.1" else ""
    text = (f"local {select}={environment}select; local {unpack}={environment}table.unpack or {environment}unpack;\n"
            f"local function {pack}(...) return {{n={select}('#',...),...}} end\n")
    return text, (pack, unpack)


def lower_region(source, ctx, span, allocator, lua_version="5.3", *, transport):
    roots = SelectionPlan._validate_region(source, source, ctx, span.start, span.end, span.feature)
    enclosing = _owner(roots[0])
    inside = lambda n: span.start <= ctx.cs(n) and ctx.ce(n) < span.end
    nodes = list(ctx.walk())

    # Lua labels have block scope. Neither direction of a cross-domain jump can
    # be represented by a helper call without changing local lifetimes.
    labels = [n for n in nodes if n.type == "label_statement"]
    for node in nodes:
        if node.type != "goto_statement":
            continue
        name = ctx.text(node.named_children[0])
        scopes = [a for a in _ancestors(node) if a.type in {"chunk", "block"}]
        candidates = [label for label in labels if _owner(label) == _owner(node)
                      and label.parent in scopes and ctx.text(label.named_children[0]) == name]
        target = min(candidates, key=lambda label: scopes.index(label.parent)) if candidates else None
        if target is not None and inside(node) != inside(target):
            raise SelectionError(f"line {span.line}: goto cannot cross a protection region boundary")

    envs = {}
    bindings, _, _, _, _ = resolve_bindings(ctx, free_environments=envs)
    hoisted = {}
    for binding in bindings:
        declaration = binding.nodes[0]
        statement = next((a for a in _ancestors(declaration) if a in roots), None)
        if statement is not None and (statement.type == "variable_declaration" or
                (statement.type == "function_declaration" and statement.children[0].type == "local"
                 and declaration == statement.child_by_field_name("name"))):
            # Nested declarations under a root local's RHS belong to its closure.
            if declaration == statement.child_by_field_name("name") or not any(
                    a.type in FUNCTION_TYPES for a in _ancestors(declaration) if a != statement
                    and inside(a)):
                hoisted[id(binding)] = allocator.allocate(binding.original)

    edits, outside = [], []
    for binding in bindings:
        fresh = hoisted.get(id(binding))
        if fresh is not None:
            for node in binding.nodes:
                edit = Replacement(ctx.cs(node), ctx.ce(node), fresh)
                (edits if inside(node) else outside).append(edit)
    # Hoisted _ENV must still govern implicit globals at its original lexical
    # positions (including closures), without affecting its own initializer.
    if lua_version != "5.1":
        for node in nodes:
            binding = envs.get(node.id)
            if binding is not None and id(binding) in hoisted and ctx.text(node) != "_ENV":
                edit = Replacement(ctx.cs(node), ctx.ce(node), hoisted[id(binding)] + "." + ctx.text(node))
                (edits if inside(node) else outside).append(edit)
    for statement in roots:
        if statement.type not in {"variable_declaration", "function_declaration"} or statement.children[0].type != "local":
            continue
        keyword = statement.children[0]
        edits.append(Replacement(ctx.cs(keyword), ctx.ce(keyword), ""))
        if statement.type == "variable_declaration" and not any(n.type == "assignment_statement" for n in statement.named_children):
            count = sum(1 for b in bindings if id(b) in hoisted and inside(b.nodes[0])
                        and statement in _ancestors(b.nodes[0]))
            edits.append(Replacement(ctx.ce(statement) + 1, ctx.ce(statement), "=" + ",".join(["nil"] * count)))

    escaping_return, escaping_break, varargs = [], [], []
    for node in nodes:
        if not inside(node) or _owner(node) != enclosing:
            continue
        if node.type == "return_statement":
            escaping_return.append(node)
            values = next((n for n in node.named_children if n.type == "expression_list"), None)
            keyword = node.children[0]
            edits.append(Replacement(ctx.cs(keyword), ctx.ce(keyword), "return 1," if values else "return 1"))
        elif node.type == "break_statement":
            loop = _owner(node, {"for_statement", "while_statement", "repeat_statement"})
            if loop is not None and not inside(loop):
                escaping_break.append(node)
                edits.append(Replacement(ctx.cs(node), ctx.ce(node), "return 2"))
        elif node.type == "vararg_expression":
            varargs.append(node)

    name, packet, packed = [allocator.allocate(h) for h in ("region", "result", "varargs")]
    pack, unpack = transport
    setup = "local " + ",".join(hoisted.values()) + "\n" if hoisted else ""
    if varargs:
        setup += f"local {packed}={pack}(...)\n"
        edits.extend(Replacement(ctx.cs(node), ctx.ce(node), f"{unpack}({packed},1,{packed}.n)") for node in varargs)
    text = _apply(source[span.start:span.end], [Replacement(r.start - span.start, r.end - span.start, r.new_text) for r in edits])
    helper = f"local function {name}()\n{text}\nend\n"
    left = ""
    right = "\n"
    if escaping_return or escaping_break:
        left += f"local {packet}={pack}("
        right = ")\n"
        if escaping_return:
            right += f"if {packet}[1]==1 then return {unpack}({packet},2,{packet}.n) end\n"
        if escaping_break:
            right += f"if {packet}[1]==2 then break end\n"
    return Region(helper, name, setup, left, right, outside, bool(varargs or escaping_return or escaping_break))
