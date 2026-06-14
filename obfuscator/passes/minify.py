import re
from .base import PostPass

_COMMENT_TOKEN_RE = re.compile(
    r'(?P<longcmt>--\[(?P<ceq>=*)\[.*?\](?P=ceq)\])'
    r'|(?P<cmt>--[^\n]*)'
    r'|(?P<longstr>\[(?P<leq>=*)\[.*?\](?P=leq)\])'
    r'|(?P<str>"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\')'
    r'|(?P<other>[^\-\[\"\'\n]+|\n|.)',
    re.DOTALL,
)


def _strip_comments(src: str) -> str:
    parts = []
    for m in _COMMENT_TOKEN_RE.finditer(src):
        if m.group('longcmt'):
            pass
        elif m.group('cmt'):
            parts.append('\n')
        else:
            parts.append(m.group(0))
    return ''.join(parts)


class MinifyPass(PostPass):
    def run(self, script: str) -> str:
        script = _strip_comments(script)
        return self._minify(script)

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