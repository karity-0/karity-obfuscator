from __future__ import annotations
from ...parser import Proto
from ..ir import (IRValue, IROperand, IRInstruction, IRBlock, IRFunction,
                  SemanticIR, IRValidationError, normalize_semantic_ir)

LUA53_OPCODES = (
    "MOVE", "LOAD_CONST", "LOAD_CONST_EXTRA", "LOAD_BOOL", "LOAD_NIL",
    "GET_UPVALUE", "GET_UPVALUE_TABLE", "GET_TABLE", "SET_UPVALUE_TABLE",
    "SET_UPVALUE", "SET_TABLE", "NEW_TABLE", "SELF", "ADD", "SUB",
    "MUL", "MOD", "POW", "DIV", "FLOOR_DIV", "BIT_AND", "BIT_OR",
    "BIT_XOR", "SHIFT_LEFT", "SHIFT_RIGHT", "NEGATE", "BIT_NOT",
    "LOGICAL_NOT", "LENGTH", "CONCAT", "JUMP", "EQUAL", "LESS_THAN",
    "LESS_EQUAL", "TEST", "TEST_SET", "CALL", "TAIL_CALL", "RETURN",
    "FOR_LOOP", "FOR_PREP", "ITER_CALL", "ITER_LOOP", "SET_LIST",
    "CLOSURE", "VARARG", "EXTRA_ARGUMENT",
)

_JUMP_OPS = frozenset((30, 39, 40, 42))
_TEST_OPS = frozenset((31, 32, 33, 34, 35))
_RETURN_OPS = frozenset((37, 38))


def _decode(raw: int) -> tuple[int, int, int, int, int]:
    op = raw & 0x3F
    a = (raw >> 6) & 0xFF
    c = (raw >> 14) & 0x1FF
    b = (raw >> 23) & 0x1FF
    bx = (raw >> 14) & 0x3FFFF
    return op, a, b, c, bx


def _successor_indices(code: list[int], index: int) -> tuple[int, ...]:
    op, _a, _b, c, bx = _decode(code[index])
    size = len(code)
    following = index + 1
    if op in _RETURN_OPS:
        return ()
    if op in _JUMP_OPS:
        target = following + (bx - 131071)
        if not 0 <= target < size:
            raise IRValidationError(f"jump target outside function at {index}")
        targets = [target]
        if op in (39, 42):
            targets.append(following)
        return tuple(i for i in targets if 0 <= i < size)
    if op in _TEST_OPS:
        return tuple(i for i in (following, index + 2) if i < size)
    if op == 3 and c:
        return (index + 2,) if index + 2 < size else ()
    return (following,) if following < size else ()


def _rw(proto: Proto, index: int) -> tuple[set[int], set[int]]:
    """Conservative register reads and writes for a Lua 5.3 instruction."""
    op, a, b, c, bx = _decode(proto.code[index])
    maximum = proto.max_stack_size

    def reg(value: int) -> set[int]:
        return {value} if value < maximum else set()

    def regs(lo: int, hi: int) -> set[int]:
        if hi < lo:
            return set()
        return set(range(max(0, lo), min(maximum - 1, hi) + 1))

    reads: set[int] = set()
    writes: set[int] = set()
    if op == 0:
        reads |= reg(b); writes |= reg(a)
    elif op in {1, 2, 3, 5, 11}:
        writes |= reg(a)
    elif op == 4:
        writes |= regs(a, a + b)
    elif op == 6:
        reads |= reg(c); writes |= reg(a)
    elif op == 7:
        reads |= reg(b) | reg(c); writes |= reg(a)
    elif op == 8:
        reads |= reg(b) | reg(c)
    elif op == 9:
        reads |= reg(a)
    elif op == 10:
        reads |= reg(a) | reg(b) | reg(c)
    elif op == 12:
        reads |= reg(b) | reg(c); writes |= reg(a) | reg(a + 1)
    elif 13 <= op <= 24:
        reads |= reg(b) | reg(c); writes |= reg(a)
    elif 25 <= op <= 28:
        reads |= reg(b); writes |= reg(a)
    elif op == 29:
        reads |= regs(b, c); writes |= reg(a)
    elif 31 <= op <= 33:
        reads |= reg(b) | reg(c)
    elif op == 34:
        reads |= reg(a)
    elif op == 35:
        reads |= reg(b); writes |= reg(a)
    elif op == 36:
        reads |= reg(a) | regs(a + 1, maximum - 1 if b == 0 else a + b - 1)
        writes |= regs(a, maximum - 1 if c == 0 else a + c - 2)
    elif op == 37:
        reads |= regs(a, maximum - 1 if b == 0 else a + b - 1)
    elif op == 38:
        reads |= regs(a, maximum - 1 if b == 0 else a + b - 2)
    elif op == 39:
        reads |= regs(a, a + 3); writes |= reg(a) | reg(a + 3)
    elif op == 40:
        reads |= reg(a) | reg(a + 2); writes |= reg(a)
    elif op == 41:
        reads |= regs(a, a + 2); writes |= regs(a + 3, a + 2 + c)
    elif op == 42:
        reads |= reg(a) | reg(a + 1); writes |= reg(a)
    elif op == 43:
        reads |= regs(a, maximum - 1 if b == 0 else a + b)
    elif op == 44:
        writes |= reg(a)
        if bx < len(proto.protos):
            reads |= {
                upvalue.idx for upvalue in proto.protos[bx].upvalues
                if upvalue.instack and upvalue.idx < maximum
            }
    elif op == 45:
        writes |= regs(a, maximum - 1 if b == 0 else a + b - 2)
    return reads, writes


def _operands(proto: Proto, index: int) -> tuple[IROperand, ...]:
    op, a, b, c, bx = _decode(proto.code[index])
    result = []
    def add(role, kind, value, count=None):
        result.append(IROperand(role, kind, value, count))
    def r(role, value): add(role, "register", value)
    def rk(role, value): add(role, "constant" if value >= 256 else "register", value - 256 if value >= 256 else value)
    def imm(role, value): add(role, "immediate", value)
    def span(role, start, count): add(role, "register_range", start, count)
    if op == 0: r("destination", a); r("source", b)
    elif op in (1, 2):
        r("destination", a)
        add("value", "constant", bx if op == 1 else proto.code[index + 1] >> 6)
    elif op == 3: r("destination", a); imm("value", bool(b)); imm("skip", bool(c))
    elif op == 4: span("destination", a, b + 1)
    elif op == 5: r("destination", a); add("source", "upvalue", b)
    elif op == 6: r("destination", a); add("table", "upvalue", b); rk("key", c)
    elif op == 7: r("destination", a); r("table", b); rk("key", c)
    elif op == 8: add("table", "upvalue", a); rk("key", b); rk("value", c)
    elif op == 9: r("source", a); add("destination", "upvalue", b)
    elif op == 10: r("table", a); rk("key", b); rk("value", c)
    elif op == 11: r("destination", a); imm("array_hint", b); imm("hash_hint", c)
    elif op == 12: span("destination", a, 2); r("receiver", b); rk("key", c)
    elif 13 <= op <= 24: r("destination", a); rk("left", b); rk("right", c)
    elif 25 <= op <= 28: r("destination", a); r("source", b)
    elif op == 29: r("destination", a); span("sources", b, c - b + 1)
    elif op == 30: imm("close_from", a - 1 if a else None)
    elif 31 <= op <= 33: imm("expected", bool(a)); rk("left", b); rk("right", c)
    elif op == 34: r("condition", a); imm("expected", bool(c))
    elif op == 35: r("destination", a); r("condition", b); imm("expected", bool(c))
    elif op in (36, 37):
        r("callee", a); span("arguments", a + 1, None if b == 0 else b - 1)
        if op == 36: span("results", a, None if c == 0 else c - 1)
    elif op == 38: span("values", a, None if b == 0 else b - 1)
    elif op in (39, 40): span("loop_state", a, 3); r("iteration", a + 3)
    elif op == 41: span("iterator", a, 3); span("results", a + 3, c)
    elif op == 42: r("control", a); r("result", a + 1)
    elif op == 43:
        r("table", a); span("values", a + 1, None if b == 0 else b)
        imm("batch", c if c else proto.code[index + 1] >> 6)
    elif op == 44:
        r("destination", a); add("child", "proto", bx)
        for binding in proto.protos[bx].upvalues:
            add("capture", "register" if binding.instack else "upvalue", binding.idx)
    elif op == 45: span("results", a, None if b == 0 else b - 1)
    return tuple(result)


def _build_function(proto: Proto, path: tuple[int, ...]) -> IRFunction:
    function_id = "f" + ".".join(map(str, path))
    register_values = tuple(
        IRValue(f"{function_id}:r{index}", "register", index)
        for index in range(proto.max_stack_size)
    )
    constant_values = tuple(
        IRValue(f"{function_id}:k{index}", "constant", index, literal=proto.constants[index])
        for index in range(len(proto.constants))
    )
    upvalue_values = tuple(
        IRValue(f"{function_id}:u{index}", "upvalue", index, upvalue.name)
        for index, upvalue in enumerate(proto.upvalues)
    )

    consumed = set()
    for index, raw in enumerate(proto.code):
        if index in consumed:
            continue
        op, a, b, c, bx = _decode(raw)
        if op >= len(LUA53_OPCODES):
            raise IRValidationError(f"unknown Lua opcode at {function_id}:{index}")
        if op == 2 or (op == 43 and c == 0):
            if index + 1 >= len(proto.code) or _decode(proto.code[index + 1])[0] != 46:
                raise IRValidationError(f"missing EXTRAARG at {function_id}:{index}")
            consumed.add(index + 1)
        elif op == 46:
            raise IRValidationError(f"orphan EXTRAARG at {function_id}:{index}")
    leaders = {0} if proto.code else set()
    successors = [_successor_indices(proto.code, i) for i in range(len(proto.code))]
    for index in range(len(successors)):
        if index + 1 in consumed:
            successors[index] = (index + 2,) if index + 2 < len(proto.code) else ()
    for index, targets in enumerate(successors):
        if index in consumed:
            continue
        if any(target in consumed for target in targets):
            raise IRValidationError(f"branch into EXTRAARG at {function_id}:{index}")
        ordinary = (index + 1,) if index + 1 < len(proto.code) else ()
        operation = _decode(proto.code[index])[0]
        if targets != ordinary or operation in _JUMP_OPS | _TEST_OPS | _RETURN_OPS:
            leaders.update(targets)
            if index + 1 < len(proto.code) and index + 1 not in consumed:
                leaders.add(index + 1)
    starts = sorted(leaders)
    ranges = [
        (start, starts[i + 1] if i + 1 < len(starts) else len(proto.code))
        for i, start in enumerate(starts)
    ]
    index_to_block = {
        instruction_index: f"{function_id}:b{block_index}"
        for block_index, (start, end) in enumerate(ranges)
        for instruction_index in range(start, end)
    }
    blocks: list[IRBlock] = []
    for block_index, (start, end) in enumerate(ranges):
        instructions: list[IRInstruction] = []
        active_indices = [i for i in range(start, end) if i not in consumed]
        for index in active_indices:
            raw = proto.code[index]
            op, a, b, c, bx = _decode(raw)
            operation = LUA53_OPCODES[op]
            reads, writes = _rw(proto, index)
            operands = _operands(proto, index)
            target_ids = (
                tuple(index_to_block[target] for target in successors[index])
                if index == active_indices[-1] else ()
            )
            instructions.append(IRInstruction(
                id=f"{function_id}:i{index}",
                operation="LOAD_CONST" if op == 2 else operation,
                operands=operands,
                inputs=tuple(f"{function_id}:r{item}" for item in sorted(reads)),
                outputs=tuple(f"{function_id}:r{item}" for item in sorted(writes)),
                constants=tuple(
                    f"{function_id}:k{item.value}" for item in operands if item.kind == "constant"
                ),
                targets=target_ids,
                metadata={
                    "source_pc": index,
                    "source_line": proto.lineinfo[index] if index < len(proto.lineinfo) else None,
                },
            ))
        tail_successors = instructions[-1].targets if instructions else ()
        blocks.append(IRBlock(
            id=f"{function_id}:b{block_index}",
            instructions=tuple(instructions),
            successors=tail_successors,
        ))

    children = tuple(
        _build_function(child, (*path, index))
        for index, child in enumerate(proto.protos)
    )
    return IRFunction(
        id=function_id,
        params=proto.num_params,
        vararg=bool(proto.is_vararg),
        max_stack_size=proto.max_stack_size,
        values=register_values + constant_values + upvalue_values,
        blocks=tuple(blocks),
        children=children,
        upvalue_bindings=tuple(("register" if u.instack else "upvalue", u.idx) for u in proto.upvalues),
        debug_metadata={"lines": tuple(proto.lineinfo), "locals": tuple((v.name, v.startpc, v.endpc) for v in proto.locvars), "line_defined": proto.line_defined, "last_line_defined": proto.last_line_defined},
        source=(
            proto.source.decode("utf-8", errors="replace")
            if isinstance(proto.source, bytes) else proto.source
        ),
    )


def build_semantic_ir(proto: Proto) -> SemanticIR:
    ir = SemanticIR("semantic-v2", _build_function(proto, (0,)))
    return normalize_semantic_ir(ir)


