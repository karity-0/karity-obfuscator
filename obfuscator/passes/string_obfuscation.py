import random
import re
from contextlib import nullcontext

from ..names import NameAllocator
from .string_reconstruction import reconstruct
from .base import BasePass, Replacement


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
        inner = re.sub(r'\r\n|\n\r|\r', '\n', inner)
        if inner.startswith('\n'):  # 첫 줄바꿈은 Lua가 스킵
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

        if c in '0123456789':                       # \ddd (십진 1~3자리)
            j = i
            while j < n and raw[j] in '0123456789' and j - i < 3:
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
                out.extend(chr(int(raw[i + 2:j], 16)).encode('utf-8', errors='surrogatepass'))
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
            if i < n and raw[i] in ('\n', '\r') and raw[i] != c:
                i += 1
        else:                                  # 알 수 없는 이스케이프: 문자 그대로
            out.extend(c.encode('utf-8'))
            i += 1

    return bytes(out)


def _encode(data: bytes, allocator: NameAllocator | None = None) -> str:
    from .numeric_provenance import CodeText
    from .literal_mosaic import ACTIVE
    expression = reconstruct(data, allocator)
    mosaic = ACTIVE.get()
    if mosaic is not None:
        expression = mosaic.transform_generated(expression)
    return CodeText(expression, getattr(expression,'protected',()),
                    reconstructions=[(0,len(expression))],
                    origins=getattr(expression,'origins',()) or [(0,len(expression),'string_constant')])


class StringObfuscationPass(BasePass):
    """Lower each literal to a fresh, bounded multi-statement reconstruction."""

    parser = "treesitter"

    def run(self, script: str, tree) -> list[Replacement]:
        from .literal_mosaic import ACTIVE
        replacements: list[Replacement] = []
        allocator = NameAllocator.for_source(script, seed=random.getrandbits(64))
        mosaic = ACTIVE.get()

        for node in tree.walk():
            if node.type != "string":
                continue

            with mosaic.at(tree.cs(node),tree.ce(node)+1) if mosaic is not None else nullcontext():
                expression = _encode(parse_lua_string(tree.text(node)),allocator)
            replacements.append(Replacement(
                start    = tree.cs(node),
                end      = tree.ce(node),
                new_text = expression,
            ))

        return replacements
