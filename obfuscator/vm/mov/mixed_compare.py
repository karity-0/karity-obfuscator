"""Exact integer/binary64 ordering without converting integers to floats."""
from .ir import Instruction as I, Op


def tables(encode: tuple[int, ...]) -> str:
    mask = "{" + ",".join(f"[{encode[i]}]={encode[i & 7]}" for i in range(16)) + "}"
    steps = []
    for shift in range(64):
        exponent = 1086 - shift  # binary64 bias + highest integer bit
        digits = [encode[(exponent >> (4 * i)) & 15] for i in range(3)]
        steps.append(f"[{shift}]={{{min(shift + 1, 63)},{','.join(map(str, digits))}}}")
    return "\n".join((
        f"_ms[193]={mask}",
        "_ms[194]={" + ",".join(steps) + "}",
        "_ms[196]=_mov_banks[9]",
        f"_ms[197]={{[false]={encode[0]},[true]={encode[8]}}}",
    ))


def compare(out: list[I]) -> None:
    """Build exact 80-bit ordering keys: sign, exponent, 63 fraction bits.

    Integers retain all 64 significant bits, including the implicit leading
    one; binary64 fractions are padded with eleven zero bits. Integer
    normalization shifts through the addition lookup bank and reads exponent
    digits from a precomputed transition table. Scratch 300..315 holds the
    current operand, 316 the normalization step, and 200..239 both keys.
    """
    def move(dst, src):
        out.append(I(Op.MOVE, dst, src))

    def lookup(dst, table, key):
        out.append(I(Op.LOOKUP, dst, table, key))

    def boolean(dst, lhs, rhs, bank):
        lookup(6, bank, lhs)
        lookup(dst, 6, rhs)

    def choose(condition):
        index = len(out)
        out.append(I(Op.SELECT, condition, index + 2))
        return index

    def finish(index):
        old = out[index]
        out[index] = I(Op.SELECT, old.a, old.b, len(out) + 1)

    def jump_to(index, target):
        out[index] = I(Op.SELECT, 30, target, target)

    def arithmetic(negate=False):
        move(4, 1)
        for digit in range(16):
            lookup(6, 162 if negate else 25, 21 if negate else 300 + digit)
            lookup(6, 6, 300 + digit)
            lookup(9, 6, 4)
            lookup(300 + digit, 9, 17)
            lookup(4, 9, 18)

    for operand, floating, base, nonzero, nan in (
        (2, 198, 200, 188, 190), (3, 199, 220, 189, 191),
    ):
        for digit in range(16):
            lookup(300 + digit, operand, 32 + digit)
        for digit in range(20):
            move(base + digit, 21)
        lookup(160, 164, 315)
        move(nonzero, 163)
        move(nan, 163)
        float_branch = choose(floating)

        # Float magnitude and NaN classification are entirely table based.
        lookup(nonzero, 183, 315)
        lookup(nan, 182, 315)
        move(14, 163)
        for digit in range(15):
            lookup(11, 27, 300 + digit)
            boolean(nonzero, nonzero, 11, 185)
            if digit < 13:
                boolean(14, 14, 11, 185)
            else:
                lookup(11, 180 if digit == 13 else 181, 300 + digit)
                boolean(nan, nan, 11, 184)
        boolean(nan, nan, 14, 184)
        # Align the 52 fraction bits with an integer's 63 fraction bits.
        for digit in range(2, 16):
            lookup(6, 196, 21 if digit == 15 else 300 + digit - 2)
            lookup(6, 6, 21 if digit == 2 else 300 + digit - 3)
            lookup(9, 6, 35)  # shift three bits plus two whole nibbles
            lookup(base + digit, 9, 17)
        move(base + 16, 313)
        move(base + 17, 314)
        lookup(base + 18, 193, 315)
        float_done = choose(30)
        finish(float_branch)

        for digit in range(16):
            lookup(11, 27, 300 + digit)
            boolean(nonzero, nonzero, 11, 185)
        negative = choose(160)
        arithmetic(negate=True)
        finish(negative)
        not_zero = choose(nonzero)
        move(316, 1)
        loop = len(out) + 1
        lookup(11, 164, 315)
        normalized = choose(11)
        # True branches to the key construction after the shift loop.
        shift_jump = choose(30)
        finish(normalized)
        arithmetic()
        lookup(6, 194, 316)
        lookup(316, 6, 17)
        out.append(I(Op.SELECT, 30, loop, loop))
        jump_to(shift_jump, len(out) + 1)
        for digit in range(15):
            move(base + digit, 300 + digit)
        lookup(base + 15, 193, 315)
        lookup(6, 194, 316)
        lookup(base + 16, 6, 18)
        lookup(base + 17, 6, 35)
        lookup(base + 18, 6, 36)
        finish(not_zero)
        jump_to(float_done, len(out) + 1)

        lookup(base + 19, 197, 160)
        lookup(12, 177, 160)
        lookup(13, 178, 160)
        for digit in range(20):
            lookup(base + digit, 13 if digit == 19 else 12, base + digit)

    move(4, 1)
    for digit in range(20):
        lookup(6, 16 if digit == 19 else 5, 200 + digit)
        lookup(6, 6, 220 + digit)
        lookup(9, 6, 4)
        lookup(4, 9, 18)
    boolean(11, 188, 189, 185)
    index = len(out)
    out.append(I(Op.SELECT, 11, index + 3, index + 2))
    move(4, 1)
    lookup(11, 15, 4)
    boolean(10, 190, 191, 185)
    lookup(10, 175, 10)
    boolean(11, 11, 10, 184)
    out.append(I(Op.SELECT, 11, 19, 20, mode=1))
