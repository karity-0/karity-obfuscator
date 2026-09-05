"""Lower relocated Lua instructions; share expanded recipes within a prototype."""
from .ir import Host, Instruction as I, Op, Program

# ADD, SUB, MUL, BAND, BOR, BXOR, SHL, SHR, UNM, BNOT, EQ, LT, LE.
LOWERED = frozenset((13, 14, 15, 20, 21, 22, 23, 24, 25, 26, 31, 32, 33))


def _recipe(op: int) -> str:
    return "multiply" if op == 15 else "compare" if op >= 31 else "integer"


def _multiply(out: list[I]) -> None:
    # Schoolbook multiplication modulo 2^64. Only the lower triangular
    # products contribute. Zero multiplier digits skip an entire row.
    for digit in range(16):
        out.append(I(Op.MOVE, 64 + digit, 21))
    for y in range(16):
        out.extend((I(Op.LOOKUP, 8, 3, 32 + y), I(Op.LOOKUP, 11, 27, 8)))
        skip = len(out)
        out.append(I(Op.SELECT, 11, len(out) + 2))
        out.append(I(Op.MOVE, 4, 1))
        for x in range(16 - y):
            dst = 64 + x + y
            out.extend((
                I(Op.LOOKUP, 7, 2, 32 + x),
                I(Op.LOOKUP, 6, 24, 7),
                I(Op.LOOKUP, 6, 6, 8),
                I(Op.LOOKUP, 9, 6, 4),
                I(Op.LOOKUP, 12, 9, 17),
                I(Op.LOOKUP, 10, 9, 18),
                I(Op.LOOKUP, 6, 25, 12),
                I(Op.LOOKUP, 6, 6, dst),
                I(Op.LOOKUP, 9, 6, 1),
                I(Op.LOOKUP, dst, 9, 17),
                I(Op.LOOKUP, 13, 9, 18),
                I(Op.LOOKUP, 10, 28, 10),
                I(Op.LOOKUP, 6, 25, 10),
                I(Op.LOOKUP, 6, 6, 21),
                I(Op.LOOKUP, 9, 6, 13),
                I(Op.LOOKUP, 4, 9, 17),
                I(Op.LOOKUP, 4, 29, 4),
            ))
        out[skip] = I(Op.SELECT, 11, out[skip].b, len(out) + 1)
    out.append(I(Op.HOST, Host.COMMIT))


def lower(code: list[int], vm_id: int = 0) -> Program:
    out: list[I] = []
    entries: list[int] = []
    pending: list[tuple[int, int]] = []
    jumps: list[tuple[int, int]] = []
    for ip, raw in enumerate(code, 1):
        entries.append(len(out) + 1)
        op = raw & 63
        if op in LOWERED:
            out.append(I(Op.HOST, Host.PREPARE, ip))
            pending.append((len(out), op))
            out.append(I(Op.SELECT, 11, 0, len(out) + 2))
            out.append(I(Op.HOST, Host.EXEC, ip))
        elif op == 0:
            out.append(I(Op.HOST, Host.COPY, ip))
        elif op in (34, 35):
            out.append(I(Op.HOST, Host.TEST, ip))
            out.append(I(Op.SELECT, 11, 19, 20, mode=1))
        elif op == 30:
            if (raw >> 6) & 255:
                out.append(I(Op.HOST, Host.CLOSE, ip))
            jumps.append((len(out), ip + 1 + ((raw >> 14) & 0x3FFFF) - 131071))
            out.append(I(Op.SELECT, 30))
        else:
            out.append(I(Op.HOST, Host.EXEC, ip))

    # Falling off malformed bytecode must not enter an arithmetic recipe.
    entries.append(len(out) + 1)
    out.append(I(Op.HOST, Host.EXEC, len(code) + 1))
    for index, target in jumps:
        if not 1 <= target <= len(entries):
            raise ValueError(f"MOV jump target outside prototype: {target}")
        out[index] = I(Op.SELECT, 30, entries[target - 1], entries[target - 1])
    recipes: dict[str, int] = {}
    for kind in sorted({_recipe(op) for _, op in pending}):
        recipes[kind] = len(out) + 1
        if kind == "multiply":
            _multiply(out)
            continue
        comparison = kind == "compare"
        for digit in range(16):
            if comparison and digit == 15:
                out.append(I(Op.MOVE, 5, 16))  # signed most significant digit
            out.extend((
                I(Op.LOOKUP, 7, 2, 32 + digit),
                I(Op.LOOKUP, 8, 3, 32 + digit),
                I(Op.LOOKUP, 6, 5, 7),
                I(Op.LOOKUP, 6, 6, 8),
                I(Op.LOOKUP, 9, 6, 4),
                I(Op.LOOKUP, 64 + digit, 9, 17),
                I(Op.LOOKUP, 4, 9, 18),
            ))
        if comparison:
            out.append(I(Op.LOOKUP, 11, 15, 4))
            out.append(I(Op.SELECT, 11, 19, 20, mode=1))
        else:
            out.append(I(Op.HOST, Host.COMMIT))
    for index, op in pending:
        old = out[index]
        out[index] = I(Op.SELECT, 11, recipes[_recipe(op)], old.c)
    return Program(entries, out, len(pending) + len(jumps), vm_id, recipes)
