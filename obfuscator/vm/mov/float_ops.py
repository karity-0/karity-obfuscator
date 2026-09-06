"""Binary64 unary negation: copy the payload and toggle the sign by lookup."""
from .ir import Host, Instruction as I, Op


def negate(out: list[I]) -> None:
    for digit in range(16):
        out.append(I(Op.LOOKUP, 64 + digit, 2, 32 + digit))
    out.extend((
        I(Op.LOOKUP, 6, 327, 79),
        I(Op.LOOKUP, 6, 6, 326),
        I(Op.LOOKUP, 9, 6, 1),
        I(Op.LOOKUP, 79, 9, 17),
        I(Op.HOST, Host.COMMIT_FLOAT),
    ))
