"""Validate linked microcode control addresses and the runtime scratch ABI."""
from .ir import Host, Op, Program

SCRATCH_LIMIT = 352


def validate_program(program: Program) -> None:
    size = len(program.code)
    def address(value):
        if not 1 <= value <= size:
            raise ValueError(f"MOV target outside program: {value}")
    def slot(value):
        if not 1 <= value <= SCRATCH_LIMIT:
            raise ValueError(f"MOV scratch slot outside ABI: {value}")
    for entry in program.entries:
        address(entry)
    for entry in program.recipe_offsets.values():
        address(entry)
    for index, instruction in enumerate(program.code):
        if not isinstance(instruction.op, Op) or instruction.mode not in (0, 1):
            raise ValueError("invalid MOV operation or mode")
        if instruction.op == Op.SELECT:
            slot(instruction.a)
            if instruction.mode and (instruction.b not in (19, 20) or instruction.c not in (19, 20)):
                raise ValueError("invalid MOV continuation slot")
            check = slot if instruction.mode else address
            check(instruction.b)
            check(instruction.c)
        elif instruction.op in (Op.MOVE, Op.LOOKUP):
            if instruction.op == Op.LOOKUP and instruction.mode:
                raise ValueError("invalid MOV lookup mode")
            slot(instruction.a)
            slot(instruction.b)
            if instruction.op == Op.LOOKUP or instruction.mode:
                slot(instruction.c)
        else:
            try:
                Host(instruction.a)
            except ValueError as exc:
                raise ValueError("invalid MOV host boundary") from exc
            if instruction.mode:
                raise ValueError("invalid MOV host mode")
            if instruction.a in (Host.EXEC, Host.PREPARE, Host.COPY, Host.READ_TRUTH, Host.CLOSE):
                if not 1 <= instruction.b <= len(program.entries):
                    raise ValueError("invalid MOV host instruction reference")
            if instruction.a == Host.PREPARE:
                if index + 2 >= size:
                    raise ValueError("missing MOV representation guard")
                guard, fallback = program.code[index + 1:index + 3]
                if (guard.op != Op.SELECT or guard.a != 11 or guard.mode
                        or fallback.op != Op.HOST or fallback.a != Host.EXEC
                        or fallback.b != instruction.b):
                    raise ValueError("invalid MOV encoded/native representation boundary")
