"""Decorate complete statements without touching expressions or line numbers."""
from .base import PostPass, Replacement


class SemiColonPass(PostPass):
    pattern = (1, 3, 2, 1)

    def __init__(self, lua_version='5.3'):
        self.lua_version = lua_version

    def replacements(self, source):
        from .ts_utils import parse

        ctx = parse(source)
        if ctx.root.has_error:
            raise ValueError('SemiColon requires valid Lua source')
        sites = []
        for block in ctx.walk():
            if block.type not in {'chunk', 'block'}:
                continue
            children = [node for node in block.named_children if node.type != 'comment']
            for index, node in enumerate(children):
                # Lua 5.1 permits only an optional terminator after a statement.
                # Return/break are terminal statements; leave their syntax alone.
                if node.type in {'hash_bang_line', 'empty_statement', 'return_statement', 'break_statement', 'label_statement'}:
                    continue
                if index + 1 < len(children) and children[index + 1].type == 'empty_statement':
                    continue
                sites.append(ctx.ce(node) + 1)
        return [Replacement(position, position - 1, ';' * (
            1 if self.lua_version == '5.1' else self.pattern[index % len(self.pattern)]))
            for index, position in enumerate(sorted(set(sites)))]

    def run(self, script: str) -> str:
        from ..pipeline import Pipeline
        return Pipeline(show_header=False)._apply(script, self.replacements(script))
