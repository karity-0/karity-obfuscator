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
# Scan protected literals/comments and whitespace once. Ordinary code runs
# need no individual identifier/operator tokens; only their adjacent boundary
# characters determine whether deleting a gap would merge Lua lexical tokens.
_MINIFY_TOKEN_RE = re.compile(
    r'(?P<longcmt>--\[(?P<ceq>=*)\[.*?\](?P=ceq)\])'
    r'|(?P<cmt>--[^\n]*)'
    r'|(?P<longstr>\[(?P<leq>=*)\[.*?\](?P=leq)\])'
    r'|(?P<str>"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\')'
    r'|(?P<gap>[ \t\r\n\v\f]+)'
    r'|(?P<code>[^ \t\r\n\v\f\-\[\"\']+|.)', re.DOTALL,
)
_MERGED_OPERATORS = frozenset({'--', '..', '//', '<<', '>>', '<=', '>=', '==', '~=', '::', '[['})


def _compact_tokens(source):
    parts = []
    pending_gap = False
    previous = ''
    for match in _MINIFY_TOKEN_RE.finditer(source):
        kind = match.lastgroup
        token = match.group(0)
        if kind == 'gap' or kind == 'longcmt':
            pending_gap = True
            continue
        if kind == 'cmt':
            if _RUNTIME_MARKER_RE.fullmatch(token):
                # Native target hooks must retain a terminating newline.
                if previous and previous != '\n':
                    parts.append('\n')
                parts.append(token + '\n')
                previous = '\n'
                pending_gap = False
            else:
                pending_gap = True
            continue
        first = token[0]
        if pending_gap and previous:
            word_left = previous.isalnum() or previous == '_'
            word_right = first.isalnum() or first == '_'
            # Numeric tokens accept dots/exponents; concatenation must stay
            # separate. Keep dot boundaries conservatively, also for varargs.
            if ((word_left and word_right) or previous == '.' or first == '.'
                    or previous + first in _MERGED_OPERATORS
                    or (previous == '[' and first == '=')):
                parts.append(' ')
        parts.append(token)
        previous = token[-1]
        pending_gap = False
    return ''.join(parts)



class MinifyPass(PostPass):
    def run(self, script: str) -> str:
        return _compact_tokens(script)

    def _minify(self, source: str) -> str:
        return _compact_tokens(source)
