from .base import BasePass, Replacement
from .string_obfuscation import parse_lua_string


def _encode(raw: str) -> str:
    """
    Lua 문자열 리터럴(따옴표 포함)을 \\NNN 이스케이프 시퀀스로 인코딩한다.

    Lua 문자열은 바이트열이므로 실제 런타임 바이트 단위로 인코딩한다(한글 등
    멀티바이트/이스케이프도 안전). 항상 3자리로 zero-pad해서 뒤따르는 숫자와
    묶이는 모호성을 없앤다.

    예) '"hello"' → '"\\104\\101\\108\\108\\111"'
    """
    return '"' + "".join(f"\\{b:03d}" for b in parse_lua_string(raw)) + '"'


class StringEncodePass(BasePass):
    """문자열 리터럴을 ASCII 이스케이프 시퀀스로 난독화하는 pass."""

    # Lua hexadecimal floats produced by number_obf cannot be read by
    # luaparser's Python-number converter. Keep this textual pass on Lua syntax.
    parser = "treesitter"

    def run(self, script: str, tree) -> list[Replacement]:
        replacements: list[Replacement] = []

        for node in tree.walk():
            if node.type == "string":
                literal = tree.text(node)
                replacements.append(Replacement(
                    start    = tree.cs(node),
                    end      = tree.ce(node),
                    new_text = _encode(literal),
                ))

        return replacements
