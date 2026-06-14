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


class RemoveCommentPass(PrePass):
    def run(self, script: str) -> str:
        parts = []
        for m in _COMMENT_TOKEN_RE.finditer(script):
            if m.group('longcmt'):
                pass  # long comment 제거
            elif m.group('cmt'):
                parts.append('\n')  # 줄바꿈 보존 (토큰 분리 유지)
            else:
                parts.append(m.group(0))
        return ''.join(parts)