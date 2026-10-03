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
        source = source.strip()
        for token, marker in markers:
            source = re.sub(
                re.escape(token) + r'\s*',
                lambda _match, marker=marker: marker + '\n',
                source,
                count=1,
            )
        return source
