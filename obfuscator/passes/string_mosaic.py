"""Shared Lua string spelling policy; never calls a runtime API.

Byte decoding stays in parse_lua_string. This service only spells known bytes,
with explicit constraints for literal-only and source-line-sensitive callers.
"""
from dataclasses import dataclass
import random


_SHORT = {7: r'\a', 8: r'\b', 9: r'\t', 10: r'\n', 11: r'\v',
          12: r'\f', 13: r'\r', 34: r'\"', 39: r"\'", 92: r'\\'}


def _unicode_unit(data, index):
    """Only canonical UTF-8 scalars round-trip through a Unicode escape."""
    first = data[index]
    if first < 128:
        return first, 1
    size = (2 if 194 <= first <= 223 else
            3 if 224 <= first <= 239 else 4 if 240 <= first <= 244 else 0)
    if not size or index + size > len(data):
        return None
    try:
        text = data[index:index + size].decode('utf8')
    except UnicodeDecodeError:
        return None
    return ord(text), size


def encode_quoted(data, lua_version='5.3', *, mode=None, allow_newlines=False):
    if lua_version not in {'5.1', '5.3'}:
        raise ValueError('String Encode target must be Lua 5.1 or 5.3')
    if mode not in {None, 'decimal', 'short', 'hex', 'unicode'}:
        raise ValueError('unknown string encoding form')
    if lua_version == '5.1' and mode in {'hex', 'unicode'}:
        raise ValueError('this string encoding form requires Lua 5.3')
    quote = random.choice(('"', "'"))
    parts = [quote]
    index = 0
    while index < len(data):
        byte = data[index]
        unicode = _unicode_unit(data, index) if lua_version == '5.3' else None
        forms = ['decimal']
        if byte in _SHORT:
            forms.append('short')
        if lua_version == '5.3':
            forms.append('hex')
            if unicode is not None:
                forms.append('unicode')
        form = mode if mode in forms else 'decimal' if mode is not None else random.choice(forms)
        size = 1
        if form == 'short':
            token = _SHORT[byte]
        elif form == 'hex':
            token = r'\x' + format(byte, '02X' if random.getrandbits(1) else '02x')
        elif form == 'unicode':
            value, size = unicode
            digits = format(value, 'X' if random.getrandbits(1) else 'x')
            token = r'\u{' + '0' * random.randrange(4) + digits + '}'
        else:
            # Every following unit starts with a backslash, so 1..3 digits
            # cannot absorb the next byte, even for adjacent ASCII digits.
            digits = str(byte)
            token = '\\' + digits.zfill(random.randint(len(digits), 3))
        parts.append(token)
        index += size
        if mode is None and lua_version == '5.3' and index < len(data) and random.randrange(12) == 0:
            # Emit canonical LF only: host text I/O may translate it to CRLF.
            # Embedding CRLF here would be translated twice on Windows.
            parts.append(r'\z' + random.choice((' ', '\t', ' \t ', '\n') if allow_newlines else (' ', '\t', ' \t ')))
    parts.append(quote)
    return ''.join(parts)



def quote_plain(data, quote='"', *, preserve_utf8=False):
    """Deterministic, portable spelling for generators whose style is disabled."""
    if preserve_utf8:
        try:
            text = data.decode('utf8')
        except UnicodeDecodeError:
            pass
        else:
            return quote + ''.join('\\' + c if c in (quote, '\\') else
                '\\' + str(ord(c)).zfill(3) if ord(c) < 32 or ord(c) == 127 else c for c in text) + quote
    return quote + ''.join(chr(b) if 32 <= b < 127 and b not in (ord(quote), 92)
                           else '\\' + str(b).zfill(3) for b in data) + quote


@dataclass(frozen=True)
class StringPolicy:
    lua_version: str = '5.3'
    enabled: bool = True
    allow_fragments: bool = True
    allow_newlines: bool = True
    max_fragments: int = 4

    def __post_init__(self):
        if self.lua_version not in {'5.1', '5.3'}:
            raise ValueError('String Mosaic target must be Lua 5.1 or 5.3')
        if not 1 <= self.max_fragments <= 4:
            raise ValueError('String Mosaic supports one through four fragments')


class StringMosaic:
    def __init__(self, policy=None):
        self.policy = policy or StringPolicy()

    def _long(self, data):
        try:
            content = data.decode('utf8')
        except UnicodeDecodeError:
            return None
        # Lua normalizes physical line endings. CR and raw control bytes must
        # stay escaped; canonical UTF-8 and LF can be represented exactly.
        if any(ord(c) < 32 and c not in '\n\t' or ord(c) == 127 for c in content):
            return None
        if not self.policy.allow_newlines and '\n' in content:
            return None
        if content.startswith('\n') or (self.policy.allow_newlines and random.randrange(3) == 0):
            content = '\n' + content
        levels = list(range(5))
        random.shuffle(levels)
        for level in levels:
            equals = '=' * level
            close = ']' + equals + ']'
            # Also reject terminators starting at the tail of the content.
            if (content + close).find(close) == len(content):
                return '[' + equals + '[' + content + close
        return None

    def fragments(self, data, *, literal_only=False):
        if isinstance(data, str):
            data = data.encode('utf8')
        if not self.policy.enabled:
            return (quote_plain(data),)
        count = 1
        if self.policy.allow_fragments and not literal_only and len(data) > 1 and random.getrandbits(1):
            count = random.randint(2, min(self.policy.max_fragments, len(data))) if self.policy.max_fragments > 1 else 1
        cuts = [0, *sorted(random.sample(range(1, len(data)), count - 1)), len(data)]
        tokens = []
        for start, end in zip(cuts, cuts[1:]):
            chunk = data[start:end]
            style = random.choice(('plain', 'escaped') if literal_only else ('plain', 'escaped', 'long'))
            token = self._long(chunk) if style == 'long' else None
            if token is None:
                token = (quote_plain(chunk, random.choice(('"', "'"))) if style == 'plain' else
                         encode_quoted(chunk, self.policy.lua_version, allow_newlines=self.policy.allow_newlines))
            tokens.append(token)
        return tuple(tokens)

    def expression(self, data, *, literal_only=False):
        tokens = self.fragments(data, literal_only=literal_only)
        # Long strings need parentheses in bracket keys (t[[[key]]] is a
        # different Lua grammar production). Concat also needs precedence and
        # shorthand-call argument protection. Exactly one result is produced.
        return render_fragments(tokens)


def render_fragments(tokens):
    if len(tokens) == 1 and tokens[0].startswith(('"', "'")):
        return tokens[0]
    return '(' + '..'.join(tokens) + ')'


def lua_string(data, *, lua_version='5.3', enabled=False, line_safe=True, literal_only=False):
    """Shared entry point for generated byte/text values, never Lua source text."""
    return StringMosaic(StringPolicy(lua_version=lua_version, enabled=enabled,
        allow_newlines=not line_safe)).expression(data, literal_only=literal_only)


def generated_string(data, *, literal_only=False, preserve_utf8=False):
    """Follow the caller's active policy for generated strings, with no new lines."""
    from .literal_mosaic import ACTIVE
    service = ACTIVE.get()
    if service is not None and service.strings().policy.enabled:
        return service.strings(line_safe=True).expression(data, literal_only=literal_only)
    if isinstance(data, str):
        data = data.encode('utf8')
    return quote_plain(data, preserve_utf8=preserve_utf8)
