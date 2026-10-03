"""Translate generated runtime integer semantics into fixed Lua 5.1 helpers."""
from ...passes.ts_utils import parse

_BINARY = {"+": "add", "-": "sub", "*": "mul", "//": "idiv", "%": "mod",
           "&": "band", "|": "bor", "~": "bxor", "<<": "shl", ">>": "shr",
           "==": "eq", "~=": "ne", "<": "lt", "<=": "le", ">": "gt", ">=": "ge"}

_PRIVATE_BINARY = {"+": "_padd", "-": "_psub", "*": "_pmul",
                   "&": "_pband", "|": "_pbor", "~": "_pxor",
                   "<<": "_pshl", ">>": "_pshr", "==": "_peq"}


def _translate_private(script: str, binary: dict[str, str]) -> str:
    """Lower an annotated exact-state graph to Lua 5.1 private-word calls."""
    ctx = parse(script)

    def render(node):
        if node.type == "number":
            token = ctx.text(node)
            try:
                integer = int(token,16 if token.lower().startswith("0x") else 10)
            except ValueError:
                return token
            return token if 0 <= integer <= 0xFFFFFFFF else f'_pint("{integer}")'
        if node.type == "binary_expression" and len(node.children) >= 3:
            op = ctx.text(node.children[1])
            if op in binary:
                return f"{binary[op]}({render(node.children[0])},{render(node.children[2])})"
        if node.type == "unary_expression":
            op = ctx.text(node.children[0])
            if op in ("-","~"):
                return f"{'_pneg' if op == '-' else '_pnot'}({render(node.children[-1])})"
        start,end=ctx.cs(node),ctx.ce(node)
        parts=[];position=start
        for child in node.children:
            child_start,child_end=ctx.cs(child),ctx.ce(child)
            parts.append(script[position:child_start]);parts.append(render(child))
            position=child_end+1
        parts.append(script[position:end+1])
        return "".join(parts)

    return render(ctx.tree.root_node)


def translate_private_graph(script: str) -> str:
    return _translate_private(script, _PRIVATE_BINARY)


def translate_private_modulo(script: str) -> str:
    return _translate_private(script, {**_PRIVATE_BINARY, "%": "_pmod"})


def translate_private_low(expression: str, modulus: int) -> str:
    """Project low-bit arithmetic to native limbs; retain exact fallback leaves."""
    if not 1 <= modulus <= 0x100000000 or modulus & (modulus - 1):
        raise ValueError('private low modulus must be a power of two up to 2^32')
    ctx = parse('return ' + expression)
    statement = next(node for node in ctx.tree.root_node.named_children
                     if node.type == 'return_statement')
    # Parse the expression separately from its return/list wrappers.
    node = statement.named_children[-1]
    while node.type == 'expression_list':
        node = node.named_children[0]

    def render(node):
        if node.type == 'parenthesized_expression':
            return render(node.named_children[0])
        if node.type == 'number':
            token = ctx.text(node)
            try:
                return str(int(token, 16 if token.lower().startswith('0x') else 10) % modulus)
            except ValueError:
                pass
        if node.type == 'binary_expression' and len(node.children) >= 3:
            operator = ctx.text(node.children[1])
            if operator in ('&', '|', '~'):
                helper = {'&': '_pand_limb', '|': '_por_limb', '~': '_ixor'}[operator]
                return f'{helper}({render(node.children[0])},{render(node.children[2])})'
            if operator in ('+', '-'):
                # Each operand is below 2^32, so the intermediate is exact in
                # binary64 even when the original 64-bit operation wraps.
                return f'(({render(node.children[0])}{operator}{render(node.children[2])})%{modulus})'
            if operator == '*':
                return f'_pmul_low({render(node.children[0])},{render(node.children[2])},{modulus})'
            if operator in ('<<', '>>'):
                # Right shifts need the original high limb; never project the
                # operand or shift count before the target helper sees them.
                value = translate_private_graph('return ' + ctx.text(node.children[0]))[len('return '):]
                count_node = node.children[2]
                while count_node.type == 'parenthesized_expression':
                    count_node = count_node.named_children[0]
                token = ctx.text(count_node)
                try:
                    count = int(token, 16 if token.lstrip('-').lower().startswith('0x') else 10)
                except ValueError:
                    count = None
                argument = str(count) if count is not None and abs(count) <= 0xFFFFFFFF else translate_private_graph('return ' + token)[len('return '):]
                return f'_plow_shift({value},{argument},{modulus},{str(operator == ">>").lower()})'
        if node.type == 'unary_expression':
            operator = ctx.text(node.children[0])
            if operator in ('-', '~'):
                prefix = '-' if operator == '-' else f'{modulus - 1}-'
                return f'(({prefix}{render(node.children[-1])})%{modulus})'
        exact = translate_private_graph('return ' + ctx.text(node))
        return f'_plow({exact[len("return "):]},{modulus})'

    return render(node)


def translate(script: str, helper: str = "_target51") -> str:
    ctx = parse(script)
    graph_labels = []
    def table_key(node):
        value = render(node)
        # Literal keys that stay native Lua 5.1 values do not need the
        # transitional exact-integer key canonicalizer.  Dynamic expressions
        # still cross it because they may carry a private 64-bit word.
        if node.type == "string":
            return value
        if node.type == "number" and not value.startswith(f"{helper}.integer("):
            return value
        return f"{helper}.key({value})"

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
            # Lua 5.1 represents these values exactly as binary64 numbers. Keep
            # ordinary indices, counts and 32-bit target state native; only
            # wider runtime words need the transitional two-limb representation.
            if 0 <= integer <= 0xFFFFFFFF:
                return token
            if not token.lower().startswith("0x") and integer > 0x7FFFFFFFFFFFFFFF:
                return token + ".0"
            return f'{helper}.integer("{integer}")' 
        if node.type == "binary_expression" and len(node.children) >= 3:
            op = ctx.text(node.children[1])
            if op in _BINARY:
                return f"{helper}.{_BINARY[op]}({render(node.children[0])},{render(node.children[2])})"
        if node.type == "unary_expression":
            op = ctx.text(node.children[0])
            if op in ("-", "~"):
                return f"{helper}.{'neg' if op == '-' else 'bnot'}({render(node.children[-1])})"
        if node.type == "bracket_index_expression":
            return f"{render(node.children[0])}[{table_key(node.children[2])}]"
        if node.type == "field" and node.children[0].type == "[":
            return f"[{table_key(node.children[1])}]={render(node.children[-1])}"
        if node.type == "for_numeric_clause":
            values = [render(child) for child in node.children[2:] if child.type != ',']
            return render(node.children[0]) + "=" + ",".join(f"{helper}.number({value})" for value in values)
        start, end = ctx.cs(node), ctx.ce(node)
        parts, position = [], start
        for child in node.children:
            child_start, child_end = ctx.cs(child), ctx.ce(child)
            parts.append(script[position:child_start])
            parts.append(render(child));position=child_end+1
        parts.append(script[position:end+1])
        return "".join(parts)
    return render(ctx.tree.root_node)
