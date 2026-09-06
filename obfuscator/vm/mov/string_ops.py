"""Length counting and byte-list concatenation in MOV microcode."""
from .ir import Host, Instruction as I, Op


def length(out: list[I]) -> None:
    for digit in range(16):
        out.append(I(Op.MOVE, 64 + digit, 21))
    loop = len(out) + 1
    out.append(I(Op.LOOKUP, 11, 2, 17))
    present = len(out)
    out.append(I(Op.SELECT, 11, present + 2))
    out.append(I(Op.MOVE, 4, 17))
    carries = []
    for digit in range(16):
        out.extend((
            I(Op.LOOKUP, 6, 25, 64 + digit),
            I(Op.LOOKUP, 6, 6, 21),
            I(Op.LOOKUP, 9, 6, 4),
            I(Op.LOOKUP, 64 + digit, 9, 17),
            I(Op.LOOKUP, 4, 9, 18),
        ))
        if digit < 15:
            out.append(I(Op.LOOKUP, 11, 172, 4))
            carries.append(len(out))
            out.append(I(Op.SELECT, 11, 0, len(out) + 2))
    advance = len(out) + 1
    out.append(I(Op.LOOKUP, 2, 2, 36))
    out.append(I(Op.SELECT, 30, loop, loop))
    out[present] = I(Op.SELECT, 11, present + 2, len(out) + 1)
    for index in carries:
        out[index] = I(Op.SELECT, 11, advance, out[index].c)
    out.append(I(Op.HOST, Host.COMMIT))


def concatenate(out: list[I]) -> None:
    # Input: private copies of each operand's byte list, linked as
    # {present, byte_head, next_operand}. The dummy result head is slot 322;
    # slot 324 holds the final terminal node. Only next pointers are written.
    out.append(I(Op.MOVE, 323, 322))
    operand = len(out) + 1
    out.append(I(Op.LOOKUP, 11, 2, 17))
    operands_left = len(out)
    out.append(I(Op.SELECT, 11, operands_left + 2))
    out.append(I(Op.LOOKUP, 3, 2, 18))
    byte = len(out) + 1
    out.append(I(Op.LOOKUP, 11, 3, 17))
    bytes_left = len(out)
    out.append(I(Op.SELECT, 11, bytes_left + 2))
    out.append(I(Op.MOVE, 323, 36, 3, mode=1))
    out.append(I(Op.MOVE, 323, 3))
    out.append(I(Op.LOOKUP, 3, 3, 36))
    out.append(I(Op.SELECT, 30, byte, byte))
    out[bytes_left] = I(Op.SELECT, 11, bytes_left + 2, len(out) + 1)
    out.append(I(Op.LOOKUP, 2, 2, 35))
    out.append(I(Op.SELECT, 30, operand, operand))
    out[operands_left] = I(Op.SELECT, 11, operands_left + 2, len(out) + 1)
    out.append(I(Op.MOVE, 323, 36, 324, mode=1))
    out.append(I(Op.HOST, Host.COMMIT_STRING))
