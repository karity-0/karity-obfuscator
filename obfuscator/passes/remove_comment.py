import re
from .base import PrePass

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


class RemoveCommentPass(PrePass):
    def run(self, script: str) -> str:
        parts = []
        for m in _COMMENT_TOKEN_RE.finditer(script):
            if m.group('longcmt'):
                pass  # long comment 제거
            elif m.group('cmt'):
                comment = m.group(0)
                parts.append(
                    comment if _RUNTIME_MARKER_RE.fullmatch(comment) else '\n'
                )  # target hook boundaries survive until target lowering
            else:
                parts.append(m.group(0))
        return ''.join(parts)
