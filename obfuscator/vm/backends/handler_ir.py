"""Typed instruction layout shared by the existing handler runtimes.

The operation IDs are the runtime ABI, not an input bytecode decoder. The
lowerer consumes semantic operands and links semantic block edges.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace

from ..ir import IRFunction, IRInstruction, SemanticIR


OPERATIONS = (
    "MOVE", "LOAD_CONST", "LOAD_CONST_EXTENDED", "LOAD_BOOL", "LOAD_NIL",
    "GET_UPVALUE", "GET_UPVALUE_TABLE", "GET_TABLE", "SET_UPVALUE_TABLE",
    "SET_UPVALUE", "SET_TABLE", "NEW_TABLE", "SELF", "ADD", "SUB", "MUL",
    "MOD", "POW", "DIV", "FLOOR_DIV", "BIT_AND", "BIT_OR", "BIT_XOR",
    "SHIFT_LEFT", "SHIFT_RIGHT", "NEGATE", "BIT_NOT", "LOGICAL_NOT", "LENGTH",
    "CONCAT", "JUMP", "EQUAL", "LESS_THAN", "LESS_EQUAL", "TEST", "TEST_SET",
    "CALL", "TAIL_CALL", "RETURN", "FOR_LOOP", "FOR_PREP", "ITER_CALL",
    "ITER_LOOP", "SET_LIST", "CLOSURE", "VARARG", "EXTENSION",
    "LOAD_INTEGRITY", "GET_SCRIPT_HASH", "GET_VM_COUNT", "GET_LAYOUT",
    "GET_SEED", "GET_VM_ID", "GET_CODE_LENGTH", "INTEGRITY_XOR",
    "INTEGRITY_ADD", "INTEGRITY_MUL", "LOAD_ENCODED_CONSTANT",
    "BLOCK_ROUTE", "BLOCK_GOTO", "GLOBAL_GET", "GLOBAL_SET", "PACK_VARARG",
)
OPERATION_IDS = {name: index for index, name in enumerate(OPERATIONS)}


@dataclass(frozen=True)
class HandlerInstruction:
    op: int
    a: int = 0
    b: int = 0
    c: int = 0
    source_id: str = ""

    @property
    def operation(self) -> str:
        return OPERATIONS[self.op]

    @property
    def bx(self) -> int:
        return self.b * 512 + self.c

    @property
    def sbx(self) -> int:
        return self.bx - 131071

    def with_bx(self, value: int) -> HandlerInstruction:
        if not 0 <= value <= 0x3FFFF:
            raise ValueError(f"handler offset exceeds encoding range: {value}")
        return replace(self, b=value // 512, c=value % 512)


@dataclass(frozen=True)
class HandlerUpvalue:
    instack: int
    idx: int
    name: str = ""


@dataclass
class HandlerFunction:
    id: str
    num_params: int
    is_vararg: int
    max_stack_size: int
    code: list[HandlerInstruction]
    constants: list
    upvalues: list[HandlerUpvalue]
    protos: list[HandlerFunction]
    block_entries: dict[str, int] = field(default_factory=dict)


def _lower_instruction(instruction: IRInstruction) -> list[HandlerInstruction]:
    operands = {item.role: item for item in instruction.operands if item.role != "capture"}
    operation = instruction.operation
    a = b = c = 0

    def value(role):
        return operands[role].value

    def rk(role):
        operand = operands[role]
        return operand.value + (256 if operand.kind == "constant" else 0)

    def arity(role, bias=1):
        count = operands[role].count
        return 0 if count is None else count + bias

    extension = None
    if operation == "MOVE": a, b = value("destination"), value("source")
    elif operation == "LOAD_CONST":
        a = value("destination")
        index = value("value")
        if index > 0x3FFFF:
            operation, extension = "LOAD_CONST_EXTENDED", index
        else:
            b, c = divmod(index, 512)
    elif operation == "LOAD_BOOL": a, b, c = value("destination"), int(value("value")), int(value("skip"))
    elif operation == "LOAD_NIL": a, b = value("destination"), arity("destination", -1)
    elif operation == "GET_UPVALUE": a, b = value("destination"), value("source")
    elif operation == "GET_UPVALUE_TABLE": a, b, c = value("destination"), value("table"), rk("key")
    elif operation == "GET_TABLE": a, b, c = value("destination"), value("table"), rk("key")
    elif operation == "SET_UPVALUE_TABLE": a, b, c = value("table"), rk("key"), rk("value")
    elif operation == "SET_UPVALUE": a, b = value("source"), value("destination")
    elif operation == "SET_TABLE": a, b, c = value("table"), rk("key"), rk("value")
    elif operation == "NEW_TABLE": a, b, c = value("destination"), value("array_hint"), value("hash_hint")
    elif operation == "SELF": a, b, c = value("destination"), value("receiver"), rk("key")
    elif operation in {"ADD", "SUB", "MUL", "MOD", "POW", "DIV", "FLOOR_DIV", "BIT_AND", "BIT_OR", "BIT_XOR", "SHIFT_LEFT", "SHIFT_RIGHT"}:
        a, b, c = value("destination"), rk("left"), rk("right")
    elif operation in {"NEGATE", "BIT_NOT", "LOGICAL_NOT", "LENGTH"}: a, b = value("destination"), value("source")
    elif operation == "CONCAT": a, b, c = value("destination"), value("sources"), value("sources") + arity("sources", -1)
    elif operation == "JUMP": a = 0 if value("close_from") is None else value("close_from") + 1
    elif operation in {"EQUAL", "LESS_THAN", "LESS_EQUAL"}: a, b, c = int(value("expected")), rk("left"), rk("right")
    elif operation == "TEST": a, c = value("condition"), int(value("expected"))
    elif operation == "TEST_SET": a, b, c = value("destination"), value("condition"), int(value("expected"))
    elif operation in {"CALL", "TAIL_CALL"}:
        a, b = value("callee"), arity("arguments")
        c = arity("results") if operation == "CALL" else 0
    elif operation == "RETURN": a, b = value("values"), arity("values")
    elif operation in {"FOR_LOOP", "FOR_PREP"}: a = value("loop_state")
    elif operation == "ITER_CALL": a, c = value("iterator"), arity("results", 0)
    elif operation == "ITER_LOOP": a = value("control")
    elif operation == "SET_LIST":
        a, b, c = value("table"), arity("values", 0), value("batch")
        if c > 511: extension, c = c, 0
    elif operation == "CLOSURE": a = value("destination"); b, c = divmod(value("child"), 512)
    elif operation == "VARARG": a, b = value("results"), arity("results")
    elif operation in {"GLOBAL_GET", "GLOBAL_SET"}:
        a=value("destination" if operation=="GLOBAL_GET" else "source")
        b,c=divmod(value("key"),512)
    elif operation == "PACK_VARARG": a=value("destination")
    else: raise ValueError(f"unsupported handler operation: {operation}")
    result = [HandlerInstruction(OPERATION_IDS[operation], a, b, c, instruction.id)]
    if extension is not None:
        result.append(HandlerInstruction(OPERATION_IDS["EXTENSION"], extension // 262144, (extension // 512) % 512, extension % 512, instruction.id))
    return result


def lower_handler_ir(ir: SemanticIR) -> HandlerFunction:
    def lower(function: IRFunction) -> HandlerFunction:
        code = []
        entries = {}
        jumps = []
        for block_index, block in enumerate(function.blocks):
            entries[block.id] = len(code)
            next_block = function.blocks[block_index + 1].id if block_index + 1 < len(function.blocks) else None
            def jump(target, source):
                jumps.append((len(code), target))
                code.append(HandlerInstruction(OPERATION_IDS["JUMP"], 0, source_id=source).with_bx(131071))
            for instruction in block.instructions:
                operation = instruction.operation
                lowered = _lower_instruction(instruction)
                if operation in {"JUMP", "FOR_LOOP", "FOR_PREP", "ITER_LOOP"}:
                    jumps.append((len(code), instruction.targets[0]))
                    code.extend(lowered)
                    if len(instruction.targets) > 1 and instruction.targets[1] != next_block:
                        jump(instruction.targets[1], instruction.id)
                elif operation in {"EQUAL", "LESS_THAN", "LESS_EQUAL", "TEST", "TEST_SET"}:
                    if len(instruction.targets) != 2:
                        raise ValueError("conditional semantic instruction requires two targets")
                    code.extend(lowered)
                    # A skip always crosses one linker-owned jump slot. Source
                    # blocks may now contain arbitrary protected instructions.
                    jump(instruction.targets[0], instruction.id)
                    jump(instruction.targets[1], instruction.id)
                else:
                    if operation == "LOAD_BOOL":
                        lowered[0] = replace(lowered[0], c=0)
                    code.extend(lowered)
                    if instruction.targets and instruction.targets[0] != next_block:
                        jump(instruction.targets[0], instruction.id)
        for index, target in jumps:
            code[index] = code[index].with_bx(entries[target] - index - 1 + 131071)
        return HandlerFunction(
            function.id, function.params, int(function.vararg), function.max_stack_size,
            code, [v.literal for v in function.values if v.kind == "constant"],
            [HandlerUpvalue(int(kind == "register"), index) for kind, index in function.upvalue_bindings],
            [lower(child) for child in function.children], entries,
        )
    return lower(ir.root)


def serialization_targets(program: HandlerFunction, plan) -> dict[int, dict]:
    """Resolve semantic selections to instruction positions in the handler ABI."""
    result = {}
    def walk(function):
        target = {
            "vm_assignment": plan.functions[function.id]["vm_assignment"],
            "integrity_constants": {
                index for index in range(len(function.constants))
                if plan.values.get(f"{function.id}:k{index}", {}).get("integrity_encoded", False)
            },
            "alias_variants": {}, "block_variants": {}, "avalanche_slots": {},
            "instruction_forms": {}, "graph_families": {}, "occurrence_descriptors": {},
            "open_register_extent": plan.functions[function.id].get("open_register_extent", False),
        }
        for index, instruction in enumerate(function.code):
            state = plan.instructions.get(instruction.source_id, {})
            target["alias_variants"][index] = state.get("alias_variant", 0)
            target["block_variants"][index] = state.get("block_variant_selected", False)
            target["avalanche_slots"][index] = tuple(range(function.max_stack_size, min(255, function.max_stack_size + state.get("avalanche_arity", 0))))
            target["instruction_forms"][index] = state.get("instruction_forms", (("normal", 1),))
            target["graph_families"][index] = state.get("graph_family", 0)
            target["occurrence_descriptors"][index] = state.get("occurrence_descriptors", ())
        result[id(function)] = target
        for child in function.protos:
            walk(child)
    walk(program)
    return result


def validate_handler_ir(program: HandlerFunction) -> None:
    if not 0 <= program.num_params <= program.max_stack_size <= 255:
        raise ValueError(f"invalid handler frame: {program.id}")
    for index, instruction in enumerate(program.code):
        if not 0 <= instruction.op < len(OPERATIONS):
            raise ValueError(f"unknown handler operation: {program.id}:{index}")
        if not (0 <= instruction.a <= 255 and 0 <= instruction.b <= 511 and 0 <= instruction.c <= 511):
            raise ValueError(f"handler operand exceeds encoding: {program.id}:{index}")
        if instruction.operation in {"JUMP", "FOR_LOOP", "FOR_PREP", "ITER_LOOP"}:
            target = index + 1 + instruction.sbx
            if not 0 <= target < len(program.code):
                raise ValueError(f"invalid handler jump: {program.id}:{index}")
    for child in program.protos:
        validate_handler_ir(child)
