"""Signed shift counts and a six-stage 64-bit barrel shifter in microcode."""
from .ir import Host, Instruction as I, Op


def tables(encode: tuple[int, ...]) -> str:
    valid = ",".join(f"[{e}]={str(i < 4).lower()}" for i, e in enumerate(encode))
    flags = ",".join(
        f"[{e}]={{" + ",".join(str(bool(i & (1 << b))).lower() for b in range(4)) + "}"
        for i, e in enumerate(encode)
    )
    return f"_ms[328]={{{valid}}}\n_ms[329]={{{flags}}}\n_ms[331]=_mov_banks[9]; _ms[332]=_mov_banks[10]"


def shift(out: list[I]) -> None:
    def move(dst, src):
        out.append(I(Op.MOVE, dst, src))

    def lookup(dst, table, key):
        out.append(I(Op.LOOKUP, dst, table, key))

    def branch(condition):
        index = len(out)
        out.append(I(Op.SELECT, condition))
        return index

    def patch(index, yes, no):
        out[index] = I(Op.SELECT, out[index].a, yes, no)

    # The unsigned magnitude can represent abs(mininteger) without overflow.
    for digit in range(16):
        lookup(64 + digit, 2, 32 + digit)
        lookup(336 + digit, 3, 32 + digit)
    lookup(334, 164, 351)
    lookup(6, 168, 333)
    lookup(335, 6, 334)
    signed = branch(334)
    negate = len(out) + 1
    move(4, 1)
    lookup(5, 162, 21)
    for digit in range(16):
        lookup(6, 5, 336 + digit)
        lookup(9, 6, 4)
        lookup(336 + digit, 9, 17)
        lookup(4, 9, 18)
    range_check = len(out) + 1
    patch(signed, negate, range_check)
    oversized = []
    for digit in range(15, 1, -1):
        lookup(11, 27, 336 + digit)
        index = branch(11)
        oversized.append(index)
        patch(index, 0, len(out) + 1)
    lookup(11, 328, 337)
    high = branch(11)
    choose = len(out) + 1
    direction = branch(335)

    def stages(left):
        start = len(out) + 1
        for bit in range(6):
            lookup(352, 329, 336 + bit // 4)
            lookup(11, 352, (17, 18, 35, 36)[bit % 4])
            skip = branch(11)
            work = len(out) + 1
            distance = 1 << bit
            # In-place traversal reads each neighbor before overwriting it.
            for digit in (range(15, -1, -1) if left else range(16)):
                if distance >= 4:
                    source = digit - distance // 4 if left else digit + distance // 4
                    move(64 + digit, 64 + source if 0 <= source < 16 else 21)
                else:
                    neighbor = digit - 1 if left else digit + 1
                    lookup(6, 331 if left else 332, 64 + digit)
                    lookup(6, 6, 64 + neighbor if 0 <= neighbor < 16 else 21)
                    lookup(9, 6, 17 if distance == 1 else 18)
                    lookup(64 + digit, 9, 17)
            patch(skip, work, len(out) + 1)
        out.append(I(Op.HOST, Host.COMMIT))
        return start

    left, right = stages(True), stages(False)
    patch(direction, left, right)
    zero = len(out) + 1
    for digit in range(16):
        move(64 + digit, 21)
    out.append(I(Op.HOST, Host.COMMIT))
    patch(high, choose, zero)
    for index in oversized:
        patch(index, zero, out[index].c)
