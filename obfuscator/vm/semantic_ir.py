"""Backend-neutral semantic view of parsed Lua 5.3 bytecode.

The production VM still uses the parsed :class:`Proto` as its lossless source
artifact while the migration is in progress.  This module deliberately keeps
Lua instruction words in frontend metadata only; backend decisions and MOV
micro-operations do not belong in the semantic model.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from ..parser import Proto


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


@dataclass(frozen=True)
class IRValue:
    id: str
    kind: str
    index: int
    name: str = ""


@dataclass(frozen=True)
class IRInstruction:
    id: str
    operation: str
    inputs: tuple[str, ...] = ()
    outputs: tuple[str, ...] = ()
    constants: tuple[str, ...] = ()
    targets: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict, compare=False)


@dataclass(frozen=True)
class IRBlock:
    id: str
    instructions: tuple[IRInstruction, ...]
    successors: tuple[str, ...] = ()


@dataclass(frozen=True)
class IRFunction:
    id: str
    params: int
    vararg: bool
    max_stack_size: int
    values: tuple[IRValue, ...]
    blocks: tuple[IRBlock, ...]
    children: tuple["IRFunction", ...] = ()
    source: str = ""


@dataclass(frozen=True)
class SemanticIR:
    version: str
    root: IRFunction
    # Temporary lossless bridge for existing serializers. It is intentionally
    # excluded from repr/equality and all dumps.
    source_proto: Proto = field(repr=False, compare=False)

    def functions(self) -> Iterable[IRFunction]:
        def walk(function: IRFunction) -> Iterable[IRFunction]:
            yield function
            for child in function.children:
                yield from walk(child)

        return walk(self.root)

    def dump(self) -> str:
        lines = [f"semantic-ir {self.version}"]
        for function in self.functions():
            lines.append(
                f"function {function.id} params={function.params} "
                f"vararg={int(function.vararg)} stack={function.max_stack_size}"
            )
            for value in function.values:
                suffix = f" name={value.name!r}" if value.name else ""
                lines.append(
                    f"  value {value.id} kind={value.kind} index={value.index}{suffix}"
                )
            for block in function.blocks:
                successors = ",".join(block.successors) or "-"
                lines.append(f"  block {block.id} successors={successors}")
                for instruction in block.instructions:
                    inputs = ",".join(instruction.inputs) or "-"
                    outputs = ",".join(instruction.outputs) or "-"
                    constants = ",".join(instruction.constants) or "-"
                    targets = ",".join(instruction.targets) or "-"
                    operand_text = ",".join(
                        f"{key}={instruction.metadata[key]}"
                        for key in ("a", "b", "c", "bx", "sbx")
                    )
                    lines.append(
                        f"    {instruction.id} {instruction.operation} "
                        f"in={inputs} out={outputs} const={constants} "
                        f"targets={targets} [{operand_text}]"
                    )
        return "\n".join(lines) + "\n"


class IRValidationError(ValueError):
    """Raised when the semantic IR violates a structural invariant."""


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
        reads |= reg(a) | reg(b); writes |= reg(a)
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


def _constant_indices(proto: Proto, index: int) -> tuple[int, ...]:
    op, _a, b, c, bx = _decode(proto.code[index])
    result: list[int] = []
    if op == 1:
        result.append(bx)
    elif op in {6, 7, 8, 10, *range(13, 25), 31, 32, 33}:
        for operand in (b, c):
            if operand >= 256:
                result.append(operand - 256)
    return tuple(i for i in result if 0 <= i < len(proto.constants))


def _build_function(proto: Proto, path: tuple[int, ...]) -> IRFunction:
    function_id = "f" + ".".join(map(str, path))
    register_values = tuple(
        IRValue(f"{function_id}:r{index}", "register", index)
        for index in range(proto.max_stack_size)
    )
    constant_values = tuple(
        IRValue(f"{function_id}:k{index}", "constant", index)
        for index in range(len(proto.constants))
    )
    upvalue_values = tuple(
        IRValue(f"{function_id}:u{index}", "upvalue", index, upvalue.name)
        for index, upvalue in enumerate(proto.upvalues)
    )

    leaders = {0} if proto.code else set()
    successors = [_successor_indices(proto.code, i) for i in range(len(proto.code))]
    for index, targets in enumerate(successors):
        ordinary = (index + 1,) if index + 1 < len(proto.code) else ()
        if targets != ordinary:
            leaders.update(targets)
            if index + 1 < len(proto.code):
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
        for index in range(start, end):
            raw = proto.code[index]
            op, a, b, c, bx = _decode(raw)
            if op >= len(LUA53_OPCODES):
                operation = f"UNKNOWN_{op}"
            else:
                operation = LUA53_OPCODES[op]
            reads, writes = _rw(proto, index)
            target_ids = (
                tuple(index_to_block[target] for target in successors[index])
                if index == end - 1 else ()
            )
            instructions.append(IRInstruction(
                id=f"{function_id}:i{index}",
                operation=operation,
                inputs=tuple(f"{function_id}:r{item}" for item in sorted(reads)),
                outputs=tuple(f"{function_id}:r{item}" for item in sorted(writes)),
                constants=tuple(
                    f"{function_id}:k{item}" for item in _constant_indices(proto, index)
                ),
                targets=target_ids,
                metadata={
                    "a": a, "b": b, "c": c, "bx": bx,
                    "sbx": bx - 131071,
                    # This is frontend provenance used by compatibility lowerers.
                    "lua53_word": raw,
                    "lua53_opcode": op,
                    "pc": index,
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
        source=(
            proto.source.decode("utf-8", errors="replace")
            if isinstance(proto.source, bytes) else proto.source
        ),
    )


def build_semantic_ir(proto: Proto) -> SemanticIR:
    ir = SemanticIR("lua53-semantic-v1", _build_function(proto, (0,)), proto)
    validate_semantic_ir(ir)
    return ir


def normalize_semantic_ir(ir: SemanticIR) -> SemanticIR:
    """Normalization boundary for passes that require canonical block form.

    Construction already emits ordered functions, stable IDs and canonical
    basic blocks, so the first version validates and returns the same immutable
    object. Keeping the boundary explicit avoids coupling future normalization
    passes to a backend lowerer.
    """
    validate_semantic_ir(ir)
    return ir


def validate_semantic_ir(ir: SemanticIR) -> None:
    function_ids: set[str] = set()
    for function in ir.functions():
        if function.id in function_ids:
            raise IRValidationError(f"duplicate function id: {function.id}")
        function_ids.add(function.id)
        value_ids = {value.id for value in function.values}
        if len(value_ids) != len(function.values):
            raise IRValidationError(f"duplicate value id in {function.id}")
        block_ids = {block.id for block in function.blocks}
        if len(block_ids) != len(function.blocks):
            raise IRValidationError(f"duplicate block id in {function.id}")
        instruction_ids: set[str] = set()
        for block in function.blocks:
            if not block.instructions:
                raise IRValidationError(f"empty block: {block.id}")
            if any(target not in block_ids for target in block.successors):
                raise IRValidationError(f"invalid successor in {block.id}")
            if block.successors != block.instructions[-1].targets:
                raise IRValidationError(f"block successor mismatch in {block.id}")
            for offset, instruction in enumerate(block.instructions):
                if instruction.id in instruction_ids:
                    raise IRValidationError(f"duplicate instruction id: {instruction.id}")
                instruction_ids.add(instruction.id)
                references = (*instruction.inputs, *instruction.outputs, *instruction.constants)
                if any(reference not in value_ids for reference in references):
                    raise IRValidationError(f"undefined value in {instruction.id}")
                if any(target not in block_ids for target in instruction.targets):
                    raise IRValidationError(f"invalid target in {instruction.id}")
                if instruction.targets and offset != len(block.instructions) - 1:
                    raise IRValidationError(f"non-terminal control flow in {instruction.id}")
