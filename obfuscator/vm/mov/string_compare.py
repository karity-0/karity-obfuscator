"""Binary string comparison over encoded byte lists using only microcode.

The input boundary constructs nodes {present, low_nibble, high_nibble, next}.
An explicit terminal node distinguishes a prefix from a byte containing NUL.
Ordering is used only under C/POSIX collation; equality is locale independent.
"""
from .ir import Instruction as I, Op


def compare(out: list[I]) -> None:
    def lookup(dst, table, key):
        out.append(I(Op.LOOKUP, dst, table, key))

    def move(dst, src):
        out.append(I(Op.MOVE, dst, src))

    def branch(condition):
        index = len(out)
        out.append(I(Op.SELECT, condition))
        return index

    def patch(index, yes, no):
        old = out[index]
        out[index] = I(Op.SELECT, old.a, yes, no)

    loop = len(out) + 1
    lookup(11, 2, 17)
    left = branch(11)
    left_present = len(out) + 1
    lookup(11, 3, 17)
    right = branch(11)
    both_present = len(out) + 1
    move(4, 1)
    for digit in (18, 35):
        lookup(7, 2, digit)
        lookup(8, 3, digit)
        lookup(6, 5, 7)
        lookup(6, 6, 8)
        lookup(9, 6, 4)
        lookup(4, 9, 18)
    lookup(11, 321, 4)
    equal = branch(11)
    advance = len(out) + 1
    lookup(2, 2, 36)
    lookup(3, 3, 36)
    out.append(I(Op.SELECT, 30, loop, loop))

    right_ended = len(out) + 1
    move(4, 18)
    greater = branch(30)
    left_ended = len(out) + 1
    lookup(11, 3, 17)
    remaining = branch(11)
    less = len(out) + 1
    move(4, 17)
    shorter = branch(30)
    same = len(out) + 1
    move(4, 1)
    finish = len(out) + 1
    lookup(11, 15, 4)
    out.append(I(Op.SELECT, 11, 19, 20, mode=1))
    patch(left, left_present, left_ended)
    patch(right, both_present, right_ended)
    patch(equal, advance, finish)
    patch(greater, finish, finish)
    patch(remaining, less, same)
    patch(shorter, finish, finish)
