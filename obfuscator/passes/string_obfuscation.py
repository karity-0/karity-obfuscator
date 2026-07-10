import random
from .base import BasePass, Replacement


_CHUNK_SIZE = 16  # string.char() 하나당 묶을 바이트 수


# 단일 문자 이스케이프 → 바이트 값.
_SIMPLE_ESCAPES = {
    'a': 7, 'b': 8, 'f': 12, 'n': 10, 'r': 13, 't': 9, 'v': 11,
    '\\': 92, '"': 34, "'": 39,
}


def _long_bracket_len(raw: str) -> int:
    """raw가 long string(`[[`, `[=[`, `[==[` …)이면 여는 대괄호 길이
    (`[` + `=`*n + `[`)를, 아니면 0을 반환한다."""
    if not raw.startswith('['):
        return 0
    i = 1
    while i < len(raw) and raw[i] == '=':
        i += 1
    if i < len(raw) and raw[i] == '[':
        return i + 1
    return 0


def parse_lua_string(raw: str) -> bytes:
    """Lua 문자열 리터럴(따옴표/long bracket 포함 원문)을 실제 런타임 바이트열로
    디코드한다. Lua 문자열은 바이트열이므로 한글 등 멀티바이트 문자는 UTF-8
    바이트 단위로 처리한다(코드포인트를 바이트로 취급하지 않는다)."""
    if not raw:
        return b""

    # --- long string: 이스케이프 없음, 내용은 그대로 바이트 ---------------
    bl = _long_bracket_len(raw)
    if bl:
        inner = raw[bl:-bl]           # 닫는 대괄호 길이는 여는 것과 동일
        if inner.startswith('\r\n'):  # 첫 줄바꿈은 Lua가 스킵
            inner = inner[2:]
        elif inner[:1] in ('\n', '\r'):
            inner = inner[1:]
        return inner.encode('utf-8')

    # --- short string: 따옴표 제거 후 이스케이프 디코드 -------------------
    if raw[0] in ('"', "'"):
        raw = raw[1:-1]

    out = bytearray()
    i = 0
    n = len(raw)
    while i < n:
        ch = raw[i]
        if ch != '\\':
            out.extend(ch.encode('utf-8'))
            i += 1
            continue

        i += 1
        if i >= n:
            break
        c = raw[i]

        if c.isdigit():                       # \ddd (십진 1~3자리)
            j = i
            while j < n and raw[j].isdigit() and j - i < 3:
                j += 1
            out.append(int(raw[i:j], 10) & 0xFF)
            i = j
        elif c == 'x':                        # \xHH (16진 1~2자리)
            j = i + 1
            while j < n and j - (i + 1) < 2 and raw[j] in '0123456789abcdefABCDEF':
                j += 1
            out.append(int(raw[i + 1:j], 16) if j > i + 1 else 0)
            i = j
        elif c == 'z':                        # \z: 이어지는 공백 스킵
            i += 1
            while i < n and raw[i] in ' \t\r\n\f\v':
                i += 1
        elif c == 'u':                        # \u{XXXX}: 코드포인트 → UTF-8
            j = raw.find('}', i)
            if raw[i + 1:i + 2] == '{' and j != -1:
                out.extend(chr(int(raw[i + 2:j], 16)).encode('utf-8'))
                i = j + 1
            else:
                out.extend(b'u')
                i += 1
        elif c in _SIMPLE_ESCAPES:
            out.append(_SIMPLE_ESCAPES[c])
            i += 1
        elif c in ('\n', '\r'):               # 줄 연속(\ + 개행) → 개행 바이트
            out.append(10)
            i += 1
        else:                                  # 알 수 없는 이스케이프: 문자 그대로
            out.extend(c.encode('utf-8'))
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

    parser = "treesitter"

    def run(self, script: str, tree) -> list[Replacement]:
        replacements: list[Replacement] = []

        for node in tree.walk():
            if node.type != "string":
                continue

            replacements.append(Replacement(
                start    = tree.cs(node),
                end      = tree.ce(node),
                new_text = _encode(parse_lua_string(tree.text(node))),
            ))

        return replacements