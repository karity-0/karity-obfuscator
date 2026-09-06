"""Execute shift recipes without Lua or any operand-processing HOST helper."""
import random

from obfuscator.vm.mov.ir import Host, Op
from obfuscator.vm.mov.shift import shift
from obfuscator.vm.mov.tables import banks


def check_shift_microcode():
    code = []
    shift(code)
    rng = random.Random(10304)
    mask = (1 << 64) - 1
    counts = list(range(-70, 71)) + [-(1 << 63), (1 << 63) - 1]
    counts += [sign * (1 << bit) for bit in range(7, 63) for sign in (-1, 1)]
    values = [0, 1, -1, -(1 << 63), (1 << 63) - 1]
    values += [rng.getrandbits(64) for _ in range(7)]
    cases = 0
    for _ in range(3):
        encode = tuple(rng.sample(range(16), 16))
        decode = {e: i for i, e in enumerate(encode)}
        bb = [
            {x: {y: {c: {1: p[0], 2: p[1]} for c, p in enumerate(states)}
                 for y, states in enumerate(ys)} for x, ys in enumerate(bank)}
            for bank in banks(encode)
        ]
        base = {1: 0, 17: 1, 18: 2, 21: encode[0], 30: True, 162: bb[1],
                164: {e: i >= 8 for i, e in enumerate(encode)},
                168: {a: {b: a != b for b in (False, True)} for a in (False, True)},
                27: {e: i != 0 for i, e in enumerate(encode)},
                328: {e: i < 4 for i, e in enumerate(encode)},
                329: {e: {b + 1: bool(i & (1 << b)) for b in range(4)}
                      for i, e in enumerate(encode)}, 331: bb[8], 332: bb[9]}
        base.update({32 + i: i for i in range(16)})
        for value in values:
            for count in counts:
                for left in (False, True):
                    ms = dict(base)
                    ms[2] = {i: encode[(value >> (4 * i)) & 15] for i in range(16)}
                    ms[3] = {i: encode[(count >> (4 * i)) & 15] for i in range(16)}
                    ms[333] = left
                    pc = 1
                    for steps in range(512):
                        q = code[pc - 1]
                        pc += 1
                        if q.op == Op.MOVE:
                            ms[q.a] = ms[q.b]
                        elif q.op == Op.LOOKUP:
                            ms[q.a] = ms[q.b][ms[q.c]]
                        elif q.op == Op.SELECT:
                            pc = q.b if ms[q.a] else q.c
                        else:
                            assert q.op == Op.HOST and q.a == Host.COMMIT
                            break
                    else:
                        raise AssertionError("shift microcode failed to terminate")
                    actual = sum(decode[ms[64 + i]] << (4 * i) for i in range(16))
                    magnitude = abs(count)
                    direction = left != (count < 0)
                    expected = 0 if magnitude >= 64 else (
                        (value & mask) << magnitude if direction else (value & mask) >> magnitude
                    ) & mask
                    assert actual == expected, (value, count, left, actual, expected)
                    cases += 1
    print(f"mov-shift-microcode-ok cases={cases} alphabets=3", flush=True)
