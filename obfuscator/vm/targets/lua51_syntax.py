"""Translate generated runtime integer semantics into fixed Lua 5.1 helpers."""
from ...passes.ts_utils import parse

_BINARY = {"+": "add", "-": "sub", "*": "mul", "/": "div", "//": "idiv", "%": "mod", "^": "pow",
           "&": "band", "|": "bor", "~": "bxor", "<<": "shl", ">>": "shr",
           "==": "eq", "~=": "ne", "<": "lt", "<=": "le", ">": "gt", ">=": "ge", "..": "concat"}


def translate(script: str, helper: str = "_target51") -> str:
    ctx = parse(script)
    graph_labels = []
    def render(node):
        if node.type == "block" and any(child.type == "label_statement" for child in node.children):
            # Generated graphs have an entry jump followed by scoped labelled
            # blocks. Lua 5.1 expresses these edges as mutually recursive tail
            # calls, keeping both local scopes and bounded stack usage.
            children = [child for child in node.children if child.type not in ("empty_statement", "comment")]
            first = next(i for i, child in enumerate(children) if child.type == "label_statement")
            if first == 0 or children[first - 1].type != "goto_statement":
                raise ValueError("target requires an explicit entry edge for a labelled graph")
            pairs = children[first:]
            if len(pairs) % 2 or any(pairs[i].type != "label_statement" or pairs[i+1].type != "do_statement" for i in range(0,len(pairs),2)):
                raise ValueError("unsupported target graph scope")
            names = [ctx.text(pairs[i].named_children[0]) for i in range(0,len(pairs),2)]
            prefix = ";".join(render(child) for child in children[:first-1])
            graph_labels.append(set(names))
            functions = []
            for i,name in zip(range(0,len(pairs),2),names):
                body = pairs[i+1].child_by_field_name("body")
                if body is None:
                    body = next(child for child in pairs[i+1].children if child.type == "block")
                functions.append(name + "=function() " + render(body) + " end")
            entry = render(children[first-1])
            graph_labels.pop()
            return (prefix + ";" if prefix else "") + "do local " + ",".join(names) + ";" + ";".join(functions) + ";" + entry + " end "
        if node.type == "goto_statement":
            name = ctx.text(node.named_children[0])
            if not graph_labels or name not in graph_labels[-1]:
                raise ValueError("unsupported target graph edge: " + name)
            return "return " + name + "()"

        if node.type == "empty_statement":
            return " "
        if node.type == "number":
            token = ctx.text(node)
            try:
                integer = int(token, 16 if token.lower().startswith("0x") else 10)
            except ValueError:
                return repr(float.fromhex(token)) if token.lower().startswith("0x") else token
            if not token.lower().startswith("0x") and integer > 0x7FFFFFFFFFFFFFFF:
                return token + ".0"
            return f'{helper}.integer("{integer}")' 
        if node.type == "binary_expression" and len(node.children) >= 3:
            op = ctx.text(node.children[1])
            if op in _BINARY:
                return f"{helper}.{_BINARY[op]}({render(node.children[0])},{render(node.children[2])})"
        if node.type == "unary_expression":
            op = ctx.text(node.children[0])
            if op == "#":
                return f"{helper}.len({render(node.children[-1])})"
            if op in ("-", "~"):
                return f"{helper}.{'neg' if op == '-' else 'bnot'}({render(node.children[-1])})"
        if node.type == "bracket_index_expression":
            return f"{render(node.children[0])}[{helper}.key({render(node.children[2])})]"
        if node.type == "field" and node.children[0].type == "[":
            return f"[{helper}.key({render(node.children[1])})]={render(node.children[-1])}"
        if node.type == "for_numeric_clause":
            values = [render(child) for child in node.children[2:] if child.type != ',']
            return render(node.children[0]) + "=" + ",".join(f"{helper}.number({value})" for value in values)
        start, end = ctx.cs(node), ctx.ce(node)
        parts, position = [], start
        for child in node.children:
            child_start, child_end = ctx.cs(child), ctx.ce(child)
            parts.append(script[position:child_start])
            if child.type == "block" and node.type == "for_statement" and node.children[1].type == "for_numeric_clause":
                variable = ctx.text(node.children[1].children[0])
                parts.append(f"{variable}={helper}.integer_number({variable}); ")
            parts.append(render(child));position=child_end+1
        parts.append(script[position:end+1])
        return "".join(parts)
    return render(ctx.tree.root_node)
