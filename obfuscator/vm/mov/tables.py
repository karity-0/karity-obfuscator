"""Build-time nibble tables; no runtime arithmetic table construction."""


STATE_COUNTS = (2, 2, 2, 2, 2, 3, 3, 16, 4, 4)


def banks(encode: tuple[int, ...]) -> list[list]:
    result = []
    for kind, state_count in enumerate(STATE_COUNTS):
        bank = [None] * 16
        for x in range(16):
            ys = [None] * 16
            for y in range(16):
                states = []
                for carry in range(state_count):
                    if kind == 0:
                        n = x + y + carry
                        pair = (n & 15, n >> 4)
                    elif kind == 1:
                        n = x - y - carry
                        pair = (n & 15, int(n < 0))
                    elif kind < 5:
                        n = (x & y, x | y, x ^ y)[kind - 2]
                        pair = (n, 0)
                    elif kind < 7:
                        a, b = (x ^ 8, y ^ 8) if kind == 6 else (x, y)
                        pair = (0, carry if a == b else (1 if a < b else 2))
                    elif kind == 7:
                        n = x * y + carry
                        pair = (n & 15, n >> 4)
                    elif kind == 8:
                        pair = (((x << carry) | (y >> (4 - carry))) & 15, carry)
                    else:
                        pair = (((x >> carry) | (y << (4 - carry))) & 15, carry)
                    states.append((encode[pair[0]], pair[1]))
                ys[encode[y]] = states
            bank[encode[x]] = ys
        result.append(bank)
    return result
