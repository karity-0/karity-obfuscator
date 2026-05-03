import re
from luaparser import ast
from .base import PostPass

class MinifyPass(PostPass):
    def run(self, script: str) -> str:
        tree = ast.parse(script)
        source = ast.to_lua_source(tree)
        return self._minify(source)

    def _minify(self, source: str) -> str:
        source = re.sub(r'\n\s*', ' ', source)
        source = re.sub(r' *(\.\.|\+|\*|/|%|\^|&|\||~|<<|>>|<=|>=|==|~=|<|>|=) *', r'\1', source)
        source = re.sub(r' - (?!-)', '-', source)
        source = re.sub(r' *([,;]) *', r'\1', source)
        source = re.sub(r'\( ', '(', source)
        source = re.sub(r' \)', ')', source)
        source = re.sub(r'\[ ', '[', source)
        source = re.sub(r' \]', ']', source)
        source = re.sub(r'\{ ', '{', source)
        source = re.sub(r' \}', '}', source)
        source = re.sub(r'\} ', '}', source)
        source = re.sub(r'  +', ' ', source)
        return source.strip()