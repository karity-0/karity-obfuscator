"""IEEE binary64 comparison microcode; native Lua only supplies a bitcast."""
from .ir import Instruction as I, Op


def tables(encode: tuple[int, ...]) -> str:
    def table(values):
        return "{" + ",".join(
            f"[{encode[i]}]={str(value).lower()}" for i, value in enumerate(values)
        ) + "}"

    identity = table(encode)
    invert = table([encode[i ^ 15] for i in range(16)])
    invert_top = table([encode[i ^ 7] for i in range(16)])
    return "\n".join((
        f"_ms[177]={{[false]={identity},[true]={invert}}}",
        f"_ms[178]={{[false]={identity},[true]={invert_top}}}",
        "_ms[180]=" + table([i == 15 for i in range(16)]),
        "_ms[181]=" + table([i == 15 for i in range(16)]),
        "_ms[182]=" + table([(i & 7) == 7 for i in range(16)]),
        "_ms[183]=" + table([bool(i & 7) for i in range(16)]),
        "_ms[184]={[false]={[false]=false,[true]=false},[true]={[false]=false,[true]=true}}",
        "_ms[185]={[false]={[false]=false,[true]=true},[true]={[false]=true,[true]=true}}",
    ))


def compare(out: list[I]) -> None:
    """Normalize ordering keys with lookup, then compare signed nibble words.

    Positive IEEE words already sort in numeric order. For negative words,
    complement the magnitude bits while retaining the sign bit. NaNs are
    unordered and both signs of zero compare equal. Scratch 188/189 stores
    nonzero magnitudes, 190/191 NaNs, and 200..231 the two ordering keys.
    """
    def move(dst, src):
        out.append(I(Op.MOVE, dst, src))

    def lookup(dst, table, key):
        out.append(I(Op.LOOKUP, dst, table, key))

    def boolean(dst, lhs, rhs, bank):
        lookup(6, bank, lhs)
        lookup(dst, 6, rhs)

    for operand, base, nonzero, nan in ((2, 200, 188, 190), (3, 216, 189, 191)):
        lookup(7, operand, 47)
        lookup(11, 164, 7)  # sign bit
        lookup(12, 177, 11)
        lookup(13, 178, 11)
        lookup(nonzero, 183, 7)  # magnitude bits in the top nibble
        lookup(nan, 182, 7)  # high three exponent bits
        move(14, 163)  # nonzero fraction
        for digit in range(16):
            lookup(7, operand, 32 + digit)
            lookup(base + digit, 13 if digit == 15 else 12, 7)
            if digit < 15:
                lookup(11, 27, 7)
                boolean(nonzero, nonzero, 11, 185)
            if digit < 13:
                boolean(14, 14, 11, 185)
            elif digit == 13:
                lookup(11, 180, 7)
                boolean(nan, nan, 11, 184)
            elif digit == 14:
                lookup(11, 181, 7)
                boolean(nan, nan, 11, 184)
        boolean(nan, nan, 14, 184)

    move(4, 1)
    for digit in range(16):
        lookup(6, 16 if digit == 15 else 5, 200 + digit)
        lookup(6, 6, 216 + digit)
        lookup(9, 6, 4)
        lookup(4, 9, 18)
    # If both magnitudes are zero, overwrite -0/+0 ordering with equality.
    boolean(11, 188, 189, 185)
    index = len(out)
    out.append(I(Op.SELECT, 11, index + 3, index + 2))
    move(4, 1)
    lookup(11, 15, 4)
    boolean(10, 190, 191, 185)
    lookup(10, 175, 10)
    boolean(11, 11, 10, 184)
    out.append(I(Op.SELECT, 11, 19, 20, mode=1))
