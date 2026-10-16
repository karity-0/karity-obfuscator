import re
from .base import PostPass, Replacement

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


def _compact_tokens(source, *, edits=None):
    parts = []
    pending_gap = False
    previous = ''
    position = 0
    def append(text, start, end):
        parts.append(text)
        if edits is not None and source[start:end] != text:
            edits.append(Replacement(start, end - 1, text))
    for match in _MINIFY_TOKEN_RE.finditer(source):
        kind = match.lastgroup
        token = match.group(0)
        if kind == 'gap' or kind == 'longcmt':
            pending_gap = True
            continue
        if kind == 'cmt':
            if _RUNTIME_MARKER_RE.fullmatch(token):
                # Native target hooks must retain a terminating newline.
                append('\n' if previous and previous != '\n' else '', position, match.start())
                append(token + '\n', match.start(), match.end())
                position = match.end()
                previous = '\n'
                pending_gap = False
            else:
                pending_gap = True
            continue
        first = token[0]
        gap = ''
        if pending_gap and previous:
            word_left = previous.isalnum() or previous == '_'
            word_right = first.isalnum() or first == '_'
            # Numeric tokens accept dots/exponents; concatenation must stay
            # separate. Keep dot boundaries conservatively, also for varargs.
            if ((word_left and word_right) or previous == '.' or first == '.'
                    or previous + first in _MERGED_OPERATORS
                    or (previous == '[' and first == '=')):
                gap = ' '
        append(gap, position, match.start())
        append(token, match.start(), match.end())
        position = match.end()
        previous = token[-1]
        pending_gap = False
    append('', position, len(source))
    return ''.join(parts)



class MinifyPass(PostPass):
    def replacements(self, source):
        edits = []
        _compact_tokens(source, edits=edits)
        return edits

    def run(self, script: str) -> str:
        return _compact_tokens(script)

    def _minify(self, source: str) -> str:
        return _compact_tokens(source)
