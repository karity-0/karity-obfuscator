"""Per-constant storage encryption, rebound with the finalized runtime identity.

The envelope is independent of the outer blob cipher. It is an obfuscation
boundary, not a secret key provisioned outside the attacker-controlled host.
All arithmetic is exactly representable on both supported Lua number models.
"""
import random
import struct

MODULUS = 2147483647


def _key(seed: int, script: int, line: int) -> int:
    return (seed + script % MODULUS + (line % MODULUS) * 17) % (MODULUS - 1) + 1


def _transform(data: bytes, state: int, direction: int) -> bytes:
    out = bytearray()
    for byte in data:
        state = state * 48271 % MODULUS
        out.append((byte + direction * (state % 251 + 1)) % 256)
    return bytes(out)


def _tag(data: bytes, key: int) -> int:
    value = (key + len(data)) % MODULUS
    for byte in data:
        value = ((value ^ byte) * 65599) % MODULUS
    return value


def encode(value: str | bytes, script: int = 0, line: int = 0, *, seed: int | None = None) -> bytes:
    data = value.encode('utf8') if isinstance(value, str) else value
    seed = random.randrange(1, MODULUS) if seed is None else seed
    key = _key(seed, script, line)
    encrypted = _transform(data, key, 1)
    return struct.pack('<II', seed, _tag(encrypted, key)) + encrypted


def decode(envelope: bytes, script: int = 0, line: int = 0) -> bytes:
    if len(envelope) < 8:
        raise ValueError('truncated protected string')
    seed, tag = struct.unpack_from('<II', envelope)
    key = _key(seed, script, line)
    if not 0 < seed < MODULUS or tag != _tag(envelope[8:], key):
        raise ValueError('protected string integrity mismatch')
    return _transform(envelope[8:], key, -1)


def rebind(envelope: bytes, old_script: int, old_line: int, script: int, line: int) -> bytes:
    seed = struct.unpack_from('<I', envelope)[0]
    return encode(decode(envelope, old_script, old_line), script, line, seed=seed)
