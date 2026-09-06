"""Signed 64-bit floor division using only MOVE/LOOKUP/SELECT in the core.

Restoring division consumes one dividend bit per iteration. Nibble addition
shifts the dividend, remainder and quotient; subtraction supplies the unsigned
comparison through its borrow bit. Signed correction follows Lua floor rules.
"""
from .ir import Host, Instruction as I, Op


def divide(out: list[I]) -> None:
    # 80..159 hold five private digit vectors. 160/161 are operand signs,
    # 169 is their XOR, 170 is the MOD selector set at the input boundary,
    # and 171 records a nonzero remainder. 162/164/165/168/172 are immutable
    # table references installed by the frame; 163=false and 173=64.
    dividend, divisor, quotient, remainder, difference = 80, 96, 112, 128, 144

    def move(dst, src):
        out.append(I(Op.MOVE, dst, src))

    def lookup(dst, table, key):
        out.append(I(Op.LOOKUP, dst, table, key))

    def choose(condition):
        index = len(out)
        out.append(I(Op.SELECT, condition, index + 2))
        return index

    def finish(index):
        old = out[index]
        out[index] = I(Op.SELECT, old.a, old.b, len(out) + 1)

    def jump():
        return choose(30)

    def jump_to(index, target):
        out[index] = I(Op.SELECT, 30, target, target)

    def pair(dst, lhs, rhs, bank):
        lookup(6, bank, lhs)
        lookup(6, 6, rhs)
        lookup(9, 6, 4)
        lookup(dst, 9, 17)
        lookup(4, 9, 18)

    def arithmetic(dst, lhs, rhs, bank, carry=1):
        move(4, carry)
        for digit in range(16):
            pair(dst + digit, lhs + digit if lhs else 21,
                 rhs + digit if rhs else 21, bank)

    def copy(dst, src):
        for digit in range(16):
            move(dst + digit, src + digit)

    for digit in range(16):
        lookup(dividend + digit, 2, 32 + digit)
        lookup(divisor + digit, 3, 32 + digit)
        move(quotient + digit, 21)
        move(remainder + digit, 21)
    lookup(160, 164, dividend + 15)
    lookup(161, 164, divisor + 15)
    lookup(6, 168, 160)
    lookup(169, 6, 161)  # different signs

    for start, sign in ((dividend, 160), (divisor, 161)):
        branch = choose(sign)
        arithmetic(start, None, start, 162)
        finish(branch)

    # Detect zero using the digit nonzero table, not native division.
    nonzero = []
    for digit in range(16):
        lookup(11, 27, divisor + digit)
        index = len(out)
        out.append(I(Op.SELECT, 11, 0, index + 2))
        nonzero.append(index)
    out.append(I(Op.HOST, Host.DIVZERO))
    for index in nonzero:
        old = out[index]
        out[index] = I(Op.SELECT, 11, len(out) + 1, old.c)

    move(166, 173)
    # Leading zero nibbles would only shift zero quotient/remainder words.
    # Skip four such bit rounds with digit moves and a counter-table lookup.
    # This keeps small operands cheap without introducing native arithmetic.
    leading = len(out) + 1
    lookup(11, 27, dividend + 15)
    significant = len(out)
    out.append(I(Op.SELECT, 11, 0, significant + 2))
    for digit in range(15, 0, -1):
        move(dividend + digit, dividend + digit - 1)
    move(dividend, 21)
    lookup(6, 165, 166)
    lookup(166, 6, 35)
    lookup(11, 6, 36)
    exhausted = len(out)
    out.append(I(Op.SELECT, 11, leading))
    loop = len(out) + 1
    out[significant] = I(Op.SELECT, 11, loop, significant + 2)
    arithmetic(dividend, dividend, dividend, 25)
    # Carry out of the dividend is the incoming low remainder bit.
    arithmetic(remainder, remainder, remainder, 25, carry=4)
    arithmetic(quotient, quotient, quotient, 25)
    arithmetic(difference, remainder, divisor, 162)
    lookup(11, 172, 4)  # no borrow means remainder >= divisor
    branch = choose(11)
    copy(remainder, difference)
    move(4, 17)
    pair(quotient, quotient, 21, 25)  # shifted quotient is even
    finish(branch)
    lookup(6, 165, 166)
    lookup(166, 6, 17)
    lookup(11, 6, 18)
    out.append(I(Op.SELECT, 11, loop, len(out) + 2))
    out[exhausted] = I(Op.SELECT, 11, leading, len(out) + 1)

    # Reduce the remainder to a boolean without materializing a Lua integer.
    move(171, 163)
    for digit in range(16):
        lookup(11, 27, remainder + digit)
        branch = choose(11)
        move(171, 30)
        finish(branch)

    modulo = choose(170)
    # Lua modulo has the divisor's sign, including opposite-sign operands.
    nonempty = choose(171)
    differing = choose(169)
    arithmetic(remainder, divisor, remainder, 162)
    finish(differing)
    finish(nonempty)
    negative = choose(161)
    arithmetic(remainder, None, remainder, 162)
    finish(negative)
    copy(64, remainder)
    done = jump()
    finish(modulo)

    negative = choose(169)
    arithmetic(quotient, None, quotient, 162)
    nonempty = choose(171)
    arithmetic(quotient, quotient, None, 162, carry=17)
    finish(nonempty)
    finish(negative)
    copy(64, quotient)
    jump_to(done, len(out) + 1)
    out.append(I(Op.HOST, Host.COMMIT))
