from .model import SemanticIR
from .operations import OPERATIONS, operation_errors

class IRValidationError(ValueError):
    pass

def validate_semantic_ir(ir: SemanticIR) -> None:
    function_ids: set[str] = set()
    for function in ir.functions():
        if function.id in function_ids:
            raise IRValidationError(f"duplicate function id: {function.id}")
        function_ids.add(function.id)
        if type(function.params) is not int or type(function.max_stack_size) is not int or not 0 <= function.params <= function.max_stack_size:
            raise IRValidationError(f"invalid parameter range in {function.id}")
        value_ids = {value.id for value in function.values}
        if len(value_ids) != len(function.values):
            raise IRValidationError(f"duplicate value id in {function.id}")
        for kind in ("register", "constant", "upvalue"):
            indices=[value.index for value in function.values if value.kind==kind]
            expected=function.max_stack_size if kind=="register" else len(indices)
            if any(type(index) is not int for index in indices) or sorted(indices)!=list(range(expected)):
                raise IRValidationError(f"invalid {kind} value indices in {function.id}")
        upvalue_count=sum(value.kind=="upvalue" for value in function.values)
        if len(function.upvalue_bindings)!=upvalue_count:
            raise IRValidationError(f"upvalue binding count mismatch in {function.id}")
        for kind,index in function.upvalue_bindings:
            if kind not in ("register","upvalue") or type(index) is not int or index<0:
                raise IRValidationError(f"invalid upvalue binding in {function.id}")
        for child in function.children:
            for kind,index in child.upvalue_bindings:
                limit=function.max_stack_size if kind=="register" else upvalue_count
                if kind not in ("register","upvalue") or type(index) is not int or not 0<=index<limit:
                    raise IRValidationError(f"invalid parent capture in {child.id}")
        block_ids = {block.id for block in function.blocks}
        if len(block_ids) != len(function.blocks):
            raise IRValidationError(f"duplicate block id in {function.id}")
        kinds = {"register", "register_range", "constant", "upvalue", "proto", "immediate"}
        counts = {kind: sum(v.kind == kind for v in function.values)
                  for kind in ("constant", "upvalue")}
        counts["proto"] = len(function.children)
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
                for error in operation_errors(instruction):
                    raise IRValidationError(f"{error} in {instruction.id}")
                if offset==len(block.instructions)-1 and OPERATIONS[instruction.operation].edges is None and len(instruction.targets)!=1:
                    raise IRValidationError(f"missing fallthrough edge in {instruction.id}")
                references = (*instruction.inputs, *instruction.outputs, *instruction.constants)
                if any(reference not in value_ids for reference in references):
                    raise IRValidationError(f"undefined value in {instruction.id}")
                if any(target not in block_ids for target in instruction.targets):
                    raise IRValidationError(f"invalid target in {instruction.id}")
                if instruction.targets and offset != len(block.instructions) - 1:
                    raise IRValidationError(f"non-terminal control flow in {instruction.id}")
                for operand in instruction.operands:
                    if operand.kind not in kinds:
                        raise IRValidationError(f"invalid operand kind in {instruction.id}")
                    if operand.kind!="register_range" and operand.count is not None:
                        raise IRValidationError(f"unexpected range count in {instruction.id}")
                    if operand.kind == "immediate":
                        continue
                    if type(operand.value) is not int or operand.value < 0:
                        raise IRValidationError(f"invalid operand index in {instruction.id}")
                    if operand.kind == "register_range":
                        if operand.count is not None and (not isinstance(operand.count, int) or operand.count < 0):
                            raise IRValidationError(f"invalid range count in {instruction.id}")
                        end = operand.value + (operand.count or 0)
                        if end > function.max_stack_size:
                            raise IRValidationError(f"register range exceeds stack in {instruction.id}")
                    elif operand.kind == "register":
                        if operand.value >= function.max_stack_size:
                            raise IRValidationError(f"register exceeds stack in {instruction.id}")
                    elif operand.value >= counts[operand.kind]:
                        raise IRValidationError(f"invalid {operand.kind} operand in {instruction.id}")
                if instruction.operation=="CLOSURE":
                    child_index=next(value.value for value in instruction.operands if value.role=="child")
                    captures=tuple((value.kind,value.value) for value in instruction.operands if value.role=="capture")
                    if captures!=function.children[child_index].upvalue_bindings:
                        raise IRValidationError(f"closure capture mismatch in {instruction.id}")
                if instruction.operation=="JUMP":
                    first=next(value.value for value in instruction.operands if value.role=="close_from")
                    if first is not None and first>function.max_stack_size:
                        raise IRValidationError(f"close boundary exceeds stack in {instruction.id}")
                if instruction.operation in {"RETURN", "TAIL_CALL"}:
                    if offset != len(block.instructions) - 1 or instruction.targets:
                        raise IRValidationError(f"invalid return terminator in {instruction.id}")
