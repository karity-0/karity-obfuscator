"""Conservative, flow-insensitive value kinds for lexical naming only."""
from collections import deque
import re
from tree_sitter import Node

from .rename_ts import Binding
from .ts_utils import TSContext


_FUNCTION, _STRING, _INTEGER, _OTHER = 1, 2, 4, 8
_KINDS = {_FUNCTION: 'function', _STRING: 'string', _INTEGER: 'integer'}


def classify_bindings(ctx: TSContext, bindings: list[Binding]) -> dict[int, str]:
    """Use every write, including captured writes; unknown/mixed kinds are default.

    Alias cycles reach a finite union fixed point. This is not a runtime type
    check or interprocedural inference: parameters, calls and arithmetic without
    an integer range proof deliberately stay unknown.
    """
    owners = {node.id: i for i, binding in enumerate(bindings) for node in binding.nodes}
    writes: list[list[Node | str | None]] = [[] for _ in bindings]
    assignments: dict[int, dict[int, Node | None]] = {}

    def children(node: Node) -> list[Node]:
        return [c for c in node.named_children if c.type != 'comment']

    for i, binding in enumerate(bindings):
        for index, node in enumerate(binding.nodes):
            parent = node.parent
            value: Node | str | None = 'read'
            if parent is not None and parent.type == 'variable_list':
                statement = parent.parent
                if statement is not None and statement.type == 'assignment_statement':
                    if statement.id not in assignments:
                        expr_list = next((c for c in statement.named_children if c.type == 'expression_list'), None)
                        rhs = children(expr_list) if expr_list is not None else []
                        lhs = [n for n in children(parent) if n.type != 'attribute']
                        assignments[statement.id] = {n.id: rhs[j] if j < len(rhs) else None
                                                    for j, n in enumerate(lhs)}
                    value = assignments[statement.id].get(node.id)
                else:
                    value = None  # Uninitialized local or generic loop variable.
            elif parent is not None and parent.type == 'function_declaration':
                name = parent.child_by_field_name('name')
                if name is not None and name.id == node.id:
                    value = 'function'
            if value != 'read':
                writes[i].append(value)
            elif index == 0:
                writes[i].append(None)  # Parameters and unsupported declarations.

    def expression(node: Node | None, masks: list[int], dependencies: set[int], depth: int = 0) -> int:
        if node is None or depth > 64:
            return _OTHER
        typ = node.type
        if typ == 'identifier':
            owner = owners.get(node.id)
            if owner is None:
                return _OTHER
            dependencies.add(owner)
            return masks[owner]
        if typ == 'function_definition':
            return _FUNCTION
        if typ == 'string':
            return _STRING
        if typ == 'number':
            text = ctx.plain_text(node)
            # Exact finite integers shared by Lua 5.1's double and 5.3's integer.
            if len(text) <= 18 and re.fullmatch(r'(?:[0-9]+|0[xX][0-9a-fA-F]+)', text):
                value = int(text, 16 if text.lower().startswith('0x') else 10)
                if value <= (1 << 53):
                    return _INTEGER
            return _OTHER
        if typ == 'parenthesized_expression':
            nodes = children(node)
            return expression(nodes[0], masks, dependencies, depth+1) if len(nodes) == 1 else _OTHER
        if typ == 'unary_expression':
            op = node.child_by_field_name('operator')
            if op is not None and ctx.plain_text(op) in {'-', '#'}:
                mask = expression(node.child_by_field_name('operand'), masks, dependencies, depth+1)
                expected = _INTEGER if ctx.plain_text(op) == '-' else _STRING
                return (0 if mask == 0 else _INTEGER if mask == expected else _OTHER)
        if typ == 'binary_expression':
            op = node.child_by_field_name('operator')
            if op is not None and ctx.plain_text(op) == '..':
                left = expression(node.child_by_field_name('left'), masks, dependencies, depth+1)
                right = expression(node.child_by_field_name('right'), masks, dependencies, depth+1)
                if not left or not right:
                    return 0
                return _STRING if not (left | right) & ~(_STRING | _INTEGER) else _OTHER
        return _OTHER

    masks = [0] * len(bindings)
    dependents: list[set[int]] = [set() for _ in bindings]
    for i, values in enumerate(writes):
        dependencies: set[int] = set()
        for value in values:
            if not isinstance(value, str):
                expression(value, masks, dependencies)
        for dependency in dependencies:
            dependents[dependency].add(i)
    queue = deque(range(len(bindings)))
    pending = set(queue)
    while queue:
        i = queue.popleft()
        pending.remove(i)
        mask = masks[i]
        for value in writes[i]:
            mask |= _FUNCTION if isinstance(value, str) else expression(value, masks, set())
        if mask != masks[i]:
            masks[i] = mask
            for dependent in dependents[i] - pending:
                pending.add(dependent)
                queue.append(dependent)
    return {id(binding): _KINDS.get(masks[i], 'default') for i, binding in enumerate(bindings)}
