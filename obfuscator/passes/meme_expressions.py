"""Shared UTF-8 string-length expression generator; no activation policy."""
import random
import re

# Lua measures UTF-8 bytes, so Unicode phrases must use their encoded length.
MEME_STRINGS = (
    # 1
    "?", "gg", "ez", "lol", "bruh", "nah", "what", "bro", "wow", "uwu",
    "nice try", "skill issue", "almost", "wrong way", "hello world",
    "ai slop", "vibe coded", "vibe coding", "ask chatgpt",
    "why is this here", "keep looking", "definitely important",
    "bro really tried", "nice skid", "trust me bro", "free robux",
    "admin pls", "ban speedrun", "boy why you so obf 😭", "chill guy",
    "never gonna give you up", "why are you reading this",

    # program
    "loadstring", "print('hi')",
    "access denied", "license_valid",
    "it works on my machine", "undefined behavior",
    "decrypt_key", "vm_dispatch", "opcode_table", "secret_key",

    # pls
    "its loadstring obf", "js leave me alone", "pls no deob",
    ".l", "this is uncrackable", "stop dumping", "totally encrypted",

    # RLO reverses the displayed phrase; PDF ends it inside the Lua literal.
    "\u202ewrong way\u202c", "\u202ekeep looking\u202c",
    "\u202etrust me bro\u202c", "\u202eskill issue\u202c",
    "\u202estop dumping\u202c", "\u202etotally encrypted\u202c",
)

STRINGS_BY_LENGTH: dict[int, tuple[str, ...]] = {
    size: tuple(text for text in MEME_STRINGS if len(text.encode("utf-8")) == size)
    for size in sorted({len(text.encode("utf-8")) for text in MEME_STRINGS})
}
_INTEGER_TOKEN = re.compile(r"(?:[0-9]+|0[xX][0-9a-fA-F]+)\Z")


class MemeExpressionEngine:
    def generated_int(self, value: int, *, lua_version='5.3', depth=1) -> str:
        if lua_version == '5.3':
            return self._integer(value, depth)
        # Lua 5.1 has doubles and no unsigned hexadecimal wraparound. Keep
        # arithmetic exact for working words, otherwise use a zero correction.
        if abs(value) > (1 << 53) - 256:
            return self.float_zero(str(value))
        choices = STRINGS_BY_LENGTH.get(value)
        if choices:
            return f'({self._length(random.choice(choices))})'
        phrase = random.choice(MEME_STRINGS)
        size = len(phrase.encode('utf-8'))
        return f'({self._length(phrase)} + ({value - size}))'

    def float_zero(self, token: str) -> str:
        size = random.choice(tuple(STRINGS_BY_LENGTH))
        choices = STRINGS_BY_LENGTH[size]
        left, right = (self._length(random.choice(choices)) for _ in range(2))
        return f'(({token}) + ({left} - {right}))'

    @staticmethod
    def _length(phrase: str) -> str:
        escaped = phrase.replace('\\', '\\\\').replace('"', '\\"')
        escaped = escaped.replace('\n', '\\n').replace('\r', '\\r')
        return f'#"{escaped}"'

    def _integer(self, value: int, depth: int = 2) -> str:
        choices = STRINGS_BY_LENGTH.get(value)
        if choices:
            return f'({self._length(random.choice(choices))})'
        if depth == 0:
            # Hex literals and arithmetic both wrap modulo 2^64 in Lua 5.3.
            # A decimal residual beyond INT64_MAX would instead become a float.
            return f'0x{value & ((1 << 64) - 1):x}'
        phrase = random.choice(MEME_STRINGS)
        size = len(phrase.encode('utf-8'))
        op = random.choice(('+', '-'))
        residual = value - size if op == '+' else size - value
        return f'({self._length(phrase)} {op} {self._integer(residual, depth - 1)})'

    def obfuscate_token(self, token: str) -> str:
        if _INTEGER_TOKEN.fullmatch(token):
            try:
                is_hex = token.lower().startswith('0x')
                value = int(token, 16 if is_hex else 10)
                if is_hex or value <= (1 << 63) - 1:
                    return self._integer(value)
            except ValueError:
                return token
        # Adding an exactly integer zero preserves float rounding and type,
        # including overflowed decimal literals. Unary minus remains outside.
        return self.float_zero(token)

