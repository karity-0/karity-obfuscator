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
_RUNTIME_MARKER_RE = re.compile(
    r'--<<(?:END)?TARGET_51_NATIVE_[A-Z0-9_]+>>\s*$'
)
_COMPACT_OPERATOR_RE = re.compile(
    r' *((?<!\.)\.\.(?!\.)|\+|\*|/|%|\^|&|\||~|<<|>>|<=|>=|==|~=|<|>|=) *'
)


def _strip_comments(src: str) -> str:
    parts = []
    for m in _COMMENT_TOKEN_RE.finditer(src):
        if m.group('longcmt'):
            pass
        elif m.group('cmt'):
            comment = m.group(0)
            parts.append(comment if _RUNTIME_MARKER_RE.fullmatch(comment) else '\n')
        else:
            parts.append(m.group(0))
    return ''.join(parts)


class MinifyPass(PostPass):
    def run(self, script: str) -> str:
        script = _strip_comments(script)
        return self._minify(script)

    def _minify(self, source: str) -> str:
        # Whitespace and operator-looking text inside either form of Lua
        # string is data. Hide literals while compacting the surrounding code.
        literal_prefix = '__KARITY_MINIFY_LITERAL_'
        while literal_prefix in source:
            literal_prefix = '_' + literal_prefix
        literals = []

        def stash_literal(match):
            if not (match.group('str') or match.group('longstr')):
                return match.group(0)
            index = len(literals)
            literals.append(match.group(0))
            return f'{literal_prefix}{index}__'

        source = _COMMENT_TOKEN_RE.sub(stash_literal, source)
        markers = []

        def stash_marker(match):
            token = f"__TARGET_HOOK_MARKER_{len(markers)}__"
            markers.append((token, match.group(1)))
            return token + "\n"

        # Target hooks are line comments whose newline is syntactically
        # significant. Protect the tag while whitespace is compacted, then
        # restore it with its terminating newline intact.
        source = re.sub(
            r'(--<<(?:END)?TARGET_51_NATIVE_[A-Z0-9_]+>>)[ \t]*(?:\r?\n|$)',
            stash_marker,
            source,
        )
        source = re.sub(r'\n\s*', ' ', source)
        # Concatenation must remain separate from numeric literals (17.. is
        # malformed, and 1...2 is ambiguous). Ellipses are vararg tokens.
        source = _COMPACT_OPERATOR_RE.sub(
            lambda match: ' .. ' if match.group(1) == '..' else match.group(1),
            source,
        )
        # Removing the gap between subtraction and unary negation would
        # introduce a Lua line comment, e.g. `3 - - 2` becoming `3 --2`.
        source = re.sub(r'(?<!-) - (?!-)', '-', source)
        source = re.sub(r' *([,;]) *', r'\1', source)
        source = re.sub(r'\( ', '(', source)
        source = re.sub(r' \)', ')', source)
        source = re.sub(r'\[ ', '[', source)
        source = re.sub(r' \]', ']', source)
        source = re.sub(r'\{ ', '{', source)
        source = re.sub(r' \}', '}', source)
        source = re.sub(r'\} ', '}', source)
        source = re.sub(r'  +', ' ', source)
        source = source.strip()
        for token, marker in markers:
            source = re.sub(
                re.escape(token) + r'\s*',
                lambda _match, marker=marker: marker + '\n',
                source,
                count=1,
            )
        return re.sub(
            re.escape(literal_prefix) + r'(\d+)__',
            lambda match: literals[int(match.group(1))],
            source,
        )
