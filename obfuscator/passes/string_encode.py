from luaparser import astnodes
from .base import BasePass, Replacement


def _encode(raw: str) -> str:
    """
    Lua 문자열 리터럴(따옴표 포함)을 \\NNN 이스케이프 시퀀스로 인코딩한다.
    
    예) '"hello"' → '"\\104\\101\\108\\108\\111"'
    """
    return '"' + "".join(f"\\{ord(c)}" for c in raw) + '"'


class StringEncodePass(BasePass):
    """문자열 리터럴을 ASCII 이스케이프 시퀀스로 난독화하는 pass."""

    def run(self, script: str, tree) -> list[Replacement]:
        replacements: list[Replacement] = []

        for node in self.walk(tree):
            if isinstance(node, astnodes.String):
                replacements.append(Replacement(
                    start    = node.start_char,
                    end      = node.stop_char,
                    new_text = _encode(node.raw),
                ))

        return replacements