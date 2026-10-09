"""Replace a random subset of numeric literals with fun string arithmetic."""
import random
import re

from .base import BasePass, Replacement


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
)

STRINGS_BY_LENGTH: dict[int, tuple[str, ...]] = {
    size: tuple(text for text in MEME_STRINGS if len(text.encode("utf-8")) == size)
    for size in sorted({len(text.encode("utf-8")) for text in MEME_STRINGS})
}
_INTEGER_TOKEN = re.compile(r"(?:[0-9]+|0[xX][0-9a-fA-F]+)\Z")


class MemeStringsPass(BasePass):
    parser = "treesitter"
    replacement_rate = 0.35

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
        size = random.choice(tuple(STRINGS_BY_LENGTH))
        choices = STRINGS_BY_LENGTH[size]
        left, right = (self._length(random.choice(choices)) for _ in range(2))
        return f'(({token}) + ({left} - {right}))'

    def run(self, script: str, tree) -> list[Replacement]:
        replacements = []
        for node in tree.walk():
            if node.type != "number":
                continue
            token = tree.text(node)
            if random.random() >= self.replacement_rate:
                continue
            # Parentheses preserve precedence in powers and adjacent unary ops.
            replacements.append(Replacement(
                tree.cs(node), tree.ce(node), self.obfuscate_token(token),
            ))
        return replacements
