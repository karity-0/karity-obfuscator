import random
from luaparser import astnodes
from .base import BasePass, Replacement


_CHUNK_SIZE = 4  # string.char() 하나당 묶을 바이트 수


def parse_lua_string(raw: str) -> bytes:
    if raw[0] in ('"', "'"):
        raw = raw[1:-1]

    out = bytearray()
    i = 0
    while i < len(raw):
        if raw[i] != '\\':
            out.append(ord(raw[i]))
            i += 1
            continue

        i += 1
        c = raw[i]

        if c.isdigit():
            j = i
            while j < len(raw) and raw[j].isdigit() and j - i < 3:
                j += 1

            num = raw[i:j]
            out.append(int(num, 10))
            i = j
        elif c == 'n':
            out.append(10)
            i += 1
        elif c == 't':
            out.append(9)
            i += 1
        elif c == '\\':
            out.append(92)
            i += 1
        elif c == '"':
            out.append(34)
            i += 1
        else:
            out.append(ord(c))
            i += 1

    return bytes(out)

def _xor_expr(n: int) -> str:
    """정수 n을 (a~b) XOR 연산식으로 표현."""
    a = random.randint(10_000, 9_999_999)
    return f"({a}~{a ^ n})"


def _encode(data: bytes) -> str:
    """
    바이트열을 청크로 쪼개 string.char(xor식, ...) 형태로 인코딩한다.

    예) b"hi" ->
        string.char((123456~123497),(789012~789083))

    청크가 여럿이면 .. 으로 이어붙인다:
        string.char(...)..string.char(...)

    빈 문자열은 "" 로 그대로 둔다.
    """
    if not data:
        return '""'

    chunks = [
        data[i : i + _CHUNK_SIZE]
        for i in range(0, len(data), _CHUNK_SIZE)
    ]
    parts = [
        "string.char(" + ",".join(_xor_expr(b) for b in chunk) + ")"
        for chunk in chunks
    ]
    return "..".join(parts)


class StringObfuscationPass(BasePass):
    """
    문자열 리터럴을 string.char(XOR식, ...) 형태로 난독화한다.

    before:
        print("hello")

    after:
        print(string.char((177718~177641),(834217~834166),(873852~873744),(186485~186449))..string.char((505048~505121)))
    """

    def run(self, script: str, tree) -> list[Replacement]:
        replacements: list[Replacement] = []

        for node in self.walk(tree):
            if not isinstance(node, astnodes.String):
                continue
            if node.start_char is None:
                continue

            replacements.append(Replacement(
                start    = node.start_char,
                end      = node.stop_char,
                new_text = _encode(parse_lua_string(node.raw)),
            ))

        return replacements