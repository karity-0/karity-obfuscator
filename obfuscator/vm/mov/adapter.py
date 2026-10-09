"""Bind stable semantic operations to MOV's serialized HOST/control slots.

The semantic operation, successor block, and upvalue-close boundary select
micro lowering. Physical layout contributes HOST slot indices, validated
block-entry placements, and auxiliary slots introduced by serialization.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..backends.runtime_layout import iter_functions


_INTEGRITY_STREAM = frozenset((
    "GET_SCRIPT_HASH", "GET_VM_COUNT", "GET_LAYOUT", "GET_SEED",
    "GET_VM_ID", "GET_CODE_LENGTH", "INTEGRITY_XOR", "INTEGRITY_ADD",
    "INTEGRITY_MUL", "LOAD_ENCODED_CONSTANT",
))
_INTEGRITY_STREAM_SEQUENCE = (
    "GET_SCRIPT_HASH", "GET_VM_COUNT", "INTEGRITY_XOR", "GET_LAYOUT",
    "INTEGRITY_ADD", "GET_SEED", "INTEGRITY_XOR", "GET_VM_ID",
    "INTEGRITY_ADD", "GET_CODE_LENGTH", "INTEGRITY_MUL",
    "LOAD_ENCODED_CONSTANT", "INTEGRITY_XOR",
)
_LAYOUT_CONTROL = frozenset(("BLOCK_ROUTE", "BLOCK_GOTO"))
_CONDITIONALS = frozenset((
    "EQUAL", "LESS_THAN", "LESS_EQUAL", "TEST", "TEST_SET",
))
_LOOP_BRANCHES = frozenset(("FOR_LOOP", "FOR_PREP", "ITER_LOOP"))


@dataclass(frozen=True)
class MovHostSlot:
    operation: str
    close_from: int | None
    sbx: int
    source_id: str
    origin: str
    target_pc: int | None = None


@dataclass(frozen=True)
class MovFunctionSlots:
    function: str
    vm_id: int
    slots: tuple[MovHostSlot, ...]

    def dump(self) -> str:
        return "".join(
            f"mov-host {self.function}:p{index} vm={self.vm_id} "
            f"source={slot.source_id or '-'} origin={slot.origin} "
            f"operation={slot.operation}"
            f"{f' close-from={slot.close_from}' if slot.close_from is not None else ''}"
            f"{f' target={slot.target_pc}' if slot.target_pc is not None else ''}\n"
            for index, slot in enumerate(self.slots)
        )


def _logical_jump_targets(semantic, handler) -> dict[int, str]:
    """Bind each handler-link jump to a semantic successor block."""
    by_source: dict[str, list[int]] = {}
    for index, instruction in enumerate(handler.code):
        if instruction.operation == "JUMP":
            by_source.setdefault(instruction.source_id, []).append(index)
    targets = {}
    for block_index, block in enumerate(semantic.blocks):
        next_block = (semantic.blocks[block_index + 1].id
                      if block_index + 1 < len(semantic.blocks) else None)
        for instruction in block.instructions:
            if instruction.operation == "JUMP":
                expected = instruction.targets[:1] + (
                    instruction.targets[1:2]
                    if len(instruction.targets) > 1
                    and instruction.targets[1] != next_block else ()
                )
            elif instruction.operation in _CONDITIONALS:
                expected = instruction.targets
            elif instruction.operation in _LOOP_BRANCHES:
                expected = (instruction.targets[1:2]
                            if len(instruction.targets) > 1
                            and instruction.targets[1] != next_block else ())
            else:
                expected = (instruction.targets[:1]
                            if instruction.targets
                            and instruction.targets[0] != next_block else ())
            linked = by_source.pop(instruction.id, [])
            if len(linked) != len(expected):
                raise ValueError("MOV linker jumps differ from semantic successors")
            for logical_index, block_id in zip(linked, expected):
                target = handler.block_entries.get(block_id)
                if target is None:
                    raise ValueError("MOV semantic jump targets a missing handler block")
                logical = handler.code[logical_index]
                if logical_index + 1 + logical.sbx != target:
                    raise ValueError("MOV handler jump differs from semantic successor")
                targets[logical_index] = block_id
    if by_source:
        raise ValueError("MOV linker jumps lack semantic successors")
    return targets


def bind_slots(protected_ir, layout) -> tuple[MovFunctionSlots, ...]:
    semantic_functions = {function.id: function
                          for function in protected_ir.semantic_ir.functions()}
    bound = []
    for physical in iter_functions(layout.functions):
        semantic = semantic_functions.get(physical.source.id)
        if semantic is None:
            raise ValueError("MOV physical function has no semantic function")
        operations = {
            instruction.id: instruction
            for block in semantic.blocks for instruction in block.instructions
        }
        if len(physical.canonical) != len(physical.source.code):
            raise ValueError("MOV logical-to-physical control map is incomplete")
        for logical_index, physical_index in enumerate(physical.canonical):
            if not 0 <= physical_index < len(physical.code):
                raise ValueError("MOV logical control entry is outside the layout")
            placed = physical.code[physical_index]
            if (placed.logical_index != logical_index
                    and not (placed.logical_index is None
                             and placed.instruction.operation == "BLOCK_ROUTE")):
                raise ValueError("MOV logical control entry differs from physical origin")
        jump_targets = _logical_jump_targets(semantic, physical.source)
        stream = tuple(
            item.instruction.operation for item in physical.code
            if not item.instruction.source_id
            and item.instruction.operation in _INTEGRITY_STREAM
        )
        width = len(_INTEGRITY_STREAM_SEQUENCE)
        if (len(stream) % width
                or any(stream[index:index + width] != _INTEGRITY_STREAM_SEQUENCE
                       for index in range(0, len(stream), width))):
            raise ValueError("MOV integrity stream differs from its planned HOST boundary")
        slots = []
        for physical_index, item in enumerate(physical.code):
            raw = item.instruction
            source = operations.get(raw.source_id)
            physical_operation = raw.operation
            if source is None:
                if (not raw.source_id and physical_operation in _INTEGRITY_STREAM
                        and physical.stream_integrity):
                    origin = "integrity-stream"
                elif (not raw.source_id and physical_operation in _LAYOUT_CONTROL
                        and physical.routes):
                    origin = "layout-control"
                else:
                    raise ValueError("MOV physical slot lacks a valid semantic origin")
                operation = physical_operation
            elif physical_operation == source.operation:
                origin, operation = "semantic", source.operation
            elif physical_operation == "JUMP" and source.targets:
                origin, operation = "linker-control", "JUMP"
            elif (physical_operation in {"LOAD_CONST_EXTENDED", "EXTENSION"}
                  and source.operation == "LOAD_CONST") or (
                    physical_operation == "EXTENSION" and source.operation == "SET_LIST"):
                origin, operation = "semantic-extension", physical_operation
            elif (physical_operation == "LOAD_INTEGRITY"
                  and source.operation == "LOAD_CONST"
                  and raw.bx in physical.integrity_indices):
                origin, operation = "integrity-load", physical_operation
            else:
                raise ValueError("MOV physical operation differs from semantic origin")
            target_pc = None
            close_from = None
            if operation == "JUMP":
                # MOV's CLOSE microtarget is a semantic upvalue boundary, not
                # a decision to rediscover from the shared physical A field.
                # Linker-inserted jumps from conditional/loop edges never close.
                close_from = (
                    next(operand.value for operand in source.operands
                         if operand.role == "close_from")
                    if source.operation == "JUMP" else None
                )
                if raw.a != (0 if close_from is None else close_from + 1):
                    raise ValueError("MOV physical close boundary differs from semantic jump")
                logical_index = item.logical_index
                if logical_index not in jump_targets:
                    raise ValueError("MOV physical jump lacks a semantic control link")
                logical = physical.source.code[logical_index]
                if logical.source_id != raw.source_id:
                    raise ValueError("MOV physical jump differs from its logical origin")
                target_block = jump_targets[logical_index]
                target_logical = physical.source.block_entries[target_block]
                if not 0 <= target_logical < len(physical.canonical):
                    raise ValueError("MOV semantic jump target is outside the layout")
                target_physical = physical.canonical[target_logical]
                if not 0 <= target_physical < len(physical.code):
                    raise ValueError("MOV physical control entry is outside the layout")
                if raw.sbx != target_physical - physical_index - 1:
                    raise ValueError("MOV physical jump differs from semantic control target")
                target_pc = target_physical + 1
            slots.append(MovHostSlot(
                operation, close_from, raw.sbx, raw.source_id, origin, target_pc,
            ))
        bound.append(MovFunctionSlots(semantic.id, physical.vm_id, tuple(slots)))
    return tuple(bound)
