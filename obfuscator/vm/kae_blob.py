import os


def gf_mul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _gf_inv(x: int) -> int:
    if x == 0:
        return 0
    r, base, exp = 1, x, 254
    while exp:
        if exp & 1:
            r = gf_mul(r, base)
        base = gf_mul(base, base)
        exp >>= 1
    return r


def _aes_affine(x: int) -> int:
    c, result = 0x63, 0
    for i in range(8):
        bit = ((x >> i) & 1) ^ \
              ((x >> ((i + 4) % 8)) & 1) ^ \
              ((x >> ((i + 5) % 8)) & 1) ^ \
              ((x >> ((i + 6) % 8)) & 1) ^ \
              ((x >> ((i + 7) % 8)) & 1) ^ \
              ((c >> i) & 1)
        result |= (bit << i)
    return result


SBOX = [_aes_affine(_gf_inv(i)) for i in range(256)]

_PRIMES = [0x07, 0x0B, 0x0D, 0x11, 0x13, 0x17, 0x1D, 0x1F]


def derive_keys(key_bytes: list[int], length: int) -> list[int]:
    K, prev = [], 0x6A
    for i in range(length):
        k0  = key_bytes[i % len(key_bytes)]
        raw = gf_mul(SBOX[(k0 ^ i ^ (i >> 3)) & 0xFF], _PRIMES[i % 8])
        ki  = raw ^ ((prev << 3 | prev >> 5) & 0xFF) ^ ((i * 0x97) & 0xFF)
        K.append(ki)
        prev = ki
    return K


def encrypt_blob(data: bytes, key: str, nonce: bytes | None = None) -> tuple[bytes, bytes]:
    """
    Returns (nonce, ciphertext)
    """
    if nonce is None:
        nonce = os.urandom(8)

    nonce_ints = list(nonce)
    key_ints   = [ord(c) for c in key]
    n          = len(data)

    blended = [
        (key_ints[i % len(key_ints)] ^
         nonce_ints[i % 8] ^
         SBOX[i & 0xFF]) & 0xFF
        for i in range(n + 8)
    ]
    RK = derive_keys(blended, n)

    ct = bytes(b ^ RK[i] for i, b in enumerate(data))
    return nonce, ct


def decrypt_blob(nonce: bytes, ct: bytes, key: str) -> bytes:
    _, pt = encrypt_blob(ct, key, nonce)
    return pt


if __name__ == "__main__":
    KEY  = "karityObfuscator"
    data = b"\x1bLua\x53hello world bytecode test\x00\x01\x02\x03"

    nonce, ct = encrypt_blob(data, KEY)
    pt        = decrypt_blob(nonce, ct, KEY)

    print(f"original : {data.hex()}")
    print(f"nonce    : {nonce.hex()}")
    print(f"ct       : {ct.hex()}")
    print(f"decrypted: {pt.hex()}")
    print(f"match    : {data == pt}")