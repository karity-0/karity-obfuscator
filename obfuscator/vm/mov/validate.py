"""Validate linked microcode control addresses and the runtime scratch ABI."""
from .ir import Host, Op, Program

SCRATCH_LIMIT = 352
READ_ONLY_SHARED_TABLES = frozenset((177, 178, 180, 181))


def _validate_code(code, entry_count: int) -> None:
    size = len(code)
    def address(value):
        if not 1 <= value <= size:
            raise ValueError(f"MOV target outside program: {value}")
    def slot(value):
        if not 1 <= value <= SCRATCH_LIMIT:
            raise ValueError(f"MOV scratch slot outside ABI: {value}")
    for index, instruction in enumerate(code):
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
            if (instruction.op == Op.MOVE and instruction.mode
                    and instruction.a in READ_ONLY_SHARED_TABLES):
                raise ValueError("MOV store targets a shared read-only lookup table")
        else:
            try:
                Host(instruction.a)
            except ValueError as exc:
                raise ValueError("invalid MOV host boundary") from exc
            if instruction.mode:
                raise ValueError("invalid MOV host mode")
            if instruction.a in (Host.EXEC, Host.PREPARE, Host.COPY, Host.READ_TRUTH, Host.CLOSE):
                if not 1 <= instruction.b <= entry_count:
                    raise ValueError("invalid MOV host instruction reference")
            if instruction.a == Host.PREPARE:
                if index + 2 >= size:
                    raise ValueError("missing MOV representation guard")
                guard, fallback = code[index + 1:index + 3]
                if (guard.op != Op.SELECT or guard.a != 11 or guard.mode
                        or fallback.op != Op.HOST or fallback.a != Host.EXEC
                        or fallback.b != instruction.b):
                    raise ValueError("invalid MOV encoded/native representation boundary")


def validate_program(program: Program) -> None:
    size = len(program.code)
    if not program.entries or not size:
        raise ValueError("MOV program has no host entry or microcode")
    for entry in (*program.entries, *program.recipe_offsets.values()):
        if not 1 <= entry <= size:
            raise ValueError(f"MOV target outside program: {entry}")
    _validate_code(program.code, len(program.entries))


def validate_linked(programs, kits, linked) -> None:
    """Check the emitted tape, codebooks and exact program-to-tape linking."""
    from .optimizer import link_programs

    if not 1 <= len(kits) <= 256:
        raise ValueError("MOV linked VM count is invalid")
    seen_opcodes = set()
    seen_alphabets = set()
    for kit in kits:
        if (len(kit.opcodes) != len(Op)
                or any(type(op) is not Op for op in kit.opcodes)
                or set(kit.opcodes) != set(Op)):
            raise ValueError("MOV opcode codebook is incomplete")
        for encoded in kit.opcodes.values():
            if (type(encoded) is not int or not 0x100 <= encoded <= 0xFFFF
                    or encoded in seen_opcodes):
                raise ValueError("MOV opcode codebook contains an invalid or reused ID")
            seen_opcodes.add(encoded)
        alphabet = kit.encode
        if (not isinstance(alphabet, tuple) or len(alphabet) != 16
                or any(type(digit) is not int for digit in alphabet)
                or set(alphabet) != set(range(16))
                or alphabet == tuple(range(16)) or alphabet in seen_alphabets):
            raise ValueError("MOV digit codebook is not a distinct permutation")
        seen_alphabets.add(alphabet)
    if (not isinstance(linked, tuple) or len(linked) != 3
            or len(linked[0]) != len(kits) or len(linked[1]) != len(programs)):
        raise ValueError("MOV linked tape shape differs from the programs and VMs")
    for program in programs:
        validate_program(program)
        if not 0 <= program.vm_id < len(kits):
            raise ValueError("MOV program references a missing VM codebook")
    if linked != link_programs(programs, len(kits)):
        raise ValueError("MOV linked tape differs from its microprograms")
    tapes, entries, _ = linked
    for vm_id, tape in enumerate(tapes):
        max_entries = max((len(program.entries) for program in programs
                           if program.vm_id == vm_id), default=0)
        _validate_code(tape, max_entries)
    for program, addresses in zip(programs, entries):
        size = len(tapes[program.vm_id])
        if any(not 1 <= address <= size for address in addresses):
            raise ValueError("MOV linked entry is outside its VM tape")


def validate_host_bindings(program: Program, host_slots) -> None:
    """Bind microcode HOST references to semantic/control adapter slots."""
    from .lower import LOWERED, _recipe

    validate_program(program)
    if len(program.entries) != len(host_slots) + 1:
        raise ValueError("MOV entry count differs from physical host slots")

    for ip, raw in enumerate(host_slots, 1):
        first = program.code[program.entries[ip - 1] - 1]
        operation = raw.operation
        if operation in LOWERED:
            expected = Host.PREPARE
        elif operation == "MOVE":
            expected = Host.COPY
        elif operation in {"LOGICAL_NOT", "TEST", "TEST_SET"}:
            expected = Host.READ_TRUTH
        elif operation == "JUMP":
            expected = Host.CLOSE if raw.close_from is not None else None
        else:
            expected = Host.EXEC
        if expected is None:
            if first.op != Op.SELECT or first.a != 30 or first.mode:
                raise ValueError("MOV jump entry differs from physical control slot")
        elif first.op != Op.HOST or first.a != expected or first.b != ip:
            raise ValueError("MOV entry differs from physical host operation")

        if operation == "JUMP":
            target = raw.target_pc
            if target is None or not 1 <= target <= len(program.entries):
                raise ValueError("MOV semantic jump target is invalid")
            address = program.entries[ip - 1] + int(raw.close_from is not None)
            branch = program.code[address - 1]
            destination = program.entries[target - 1]
            if (branch.op != Op.SELECT or branch.a != 30 or branch.mode
                    or branch.b != destination or branch.c != destination):
                raise ValueError("MOV jump continuation differs from semantic target")

    sentinel = program.code[program.entries[-1] - 1]
    if (sentinel.op != Op.HOST or sentinel.a != Host.EXEC
            or sentinel.b != len(program.entries)):
        raise ValueError("MOV terminal host entry is invalid")

    entry_addresses = set(program.entries)
    fallback_addresses = {
        program.entries[ip - 1] + 2
        for ip, raw in enumerate(host_slots, 1)
        if raw.operation in LOWERED
    }
    allowed_exec_addresses = entry_addresses | fallback_addresses
    for index, instruction in enumerate(program.code):
        if instruction.op != Op.HOST or instruction.a not in (
                Host.EXEC, Host.PREPARE, Host.COPY, Host.READ_TRUTH, Host.CLOSE):
            continue
        ip = instruction.b
        if ip == len(program.entries):
            if instruction.a != Host.EXEC:
                raise ValueError("MOV terminal entry has an invalid host boundary")
            continue
        operation = host_slots[ip - 1].operation
        expected = {
            Host.PREPARE: operation in LOWERED,
            Host.COPY: operation in {"MOVE", "TEST_SET"},
            Host.READ_TRUTH: operation in {"LOGICAL_NOT", "TEST", "TEST_SET"},
            Host.CLOSE: operation == "JUMP" and host_slots[ip - 1].close_from is not None,
            Host.EXEC: True,
        }[Host(instruction.a)]
        if not expected:
            raise ValueError("MOV host boundary differs from physical operation")
        if (instruction.a == Host.EXEC
                and index + 1 not in allowed_exec_addresses):
            raise ValueError("MOV executable host boundary is outside its entry or fallback")
        if instruction.a == Host.PREPARE:
            guard = program.code[index + 1]
            recipe = program.recipe_offsets.get(_recipe(operation))
            if (recipe is None or guard.b != recipe
                    or guard.c != index + 3):
                raise ValueError("MOV recipe continuation differs from operation")
