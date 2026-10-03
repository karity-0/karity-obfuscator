"""Apply planned, version-independent semantic protection transforms."""
from dataclasses import replace
from .model import IRInstruction, IROperand
from .normalize import normalize_semantic_ir


def apply_protection(ir, plan, resolution):
    if plan.generation != ir.generation:
        raise ValueError("semantic protection plan generation mismatch")
    if not resolution.is_active("junk_instructions"):
        return ir
    def transform(function):
        blocks = []
        for block in function.blocks:
            instructions = []
            for instruction in block.instructions:
                registers = plan.instructions[instruction.id].get("junk_before", ())
                for index, register in enumerate(registers):
                    value_id = f"{function.id}:r{register}"
                    instructions.append(IRInstruction(
                        f"{instruction.id}:junk{index}", "MOVE", (value_id,), (value_id,),
                        operands=(IROperand("destination", "register", register),
                                  IROperand("source", "register", register)),
                        metadata={"protection_origin": "junk", "protected_instruction": instruction.id},
                    ))
                instructions.append(replace(instruction, metadata={
                    **instruction.metadata, "junk_before_applied": tuple(registers)}))
            blocks.append(replace(block, instructions=tuple(instructions)))
        return replace(function, blocks=tuple(blocks), children=tuple(transform(child) for child in function.children))
    return normalize_semantic_ir(replace(ir, root=transform(ir.root)))
