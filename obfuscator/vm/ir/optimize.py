"""Conservative constant propagation on typed semantic basic blocks."""
from dataclasses import replace
import math
from .model import IROperand, IRValue
from .operations import OPERATIONS
from .validate import validate_semantic_ir

_MASK=(1<<64)-1


def _integer(value):
    value &= _MASK
    return value-(1<<64) if value >= 1<<63 else value


def _number(value):
    return type(value) in (int,float)


def _fold(operation, operands):
    if operation=="LOGICAL_NOT":
        value=operands[0]
        return value is None or value is False
    if not all(_number(value) for value in operands):
        raise ValueError("unproven arithmetic")
    integer=all(type(value) is int for value in operands)
    values=operands if integer else [float(value) for value in operands]
    if operation=="NEGATE": result=-values[0]
    elif operation=="ADD": result=values[0]+values[1]
    elif operation=="SUB": result=values[0]-values[1]
    elif operation=="MUL": result=values[0]*values[1]
    else: raise ValueError("unsupported constant fold")
    # Avoid introducing target-specific NaN payloads or infinity literals.
    if not integer and not math.isfinite(result):
        raise ValueError("non-finite constant fold")
    return _integer(result) if integer else result


def optimize_semantic_ir(ir):
    validate_semantic_ir(ir)
    def optimize(function):
        values=list(function.values)
        constants={value.index:value.literal for value in values if value.kind=="constant"}
        blocks=[]
        for block in function.blocks:
            known={}
            instructions=[]
            for instruction in block.instructions:
                operands={value.role:value for value in instruction.operands if value.role!="capture"}
                operation=instruction.operation
                def literal(role):
                    value=operands[role]
                    return constants[value.value] if value.kind=="constant" else known[value.value]
                result=instruction
                computed=False
                value=None
                # Explicitly selected protection instructions must keep their
                # representation effects and identities.
                protected="protection_origin" in instruction.metadata
                if not protected:
                    try:
                        if operation=="LOAD_CONST":
                            value=literal("value");computed=True
                        elif operation=="LOAD_BOOL":
                            value=operands["value"].value;computed=True
                        elif operation=="MOVE":
                            value=literal("source");computed=True
                        elif operation in ("ADD","SUB","MUL"):
                            value=_fold(operation,[literal("left"),literal("right")]);computed=True
                        elif operation in ("NEGATE","LOGICAL_NOT"):
                            value=_fold(operation,[literal("source")]);computed=True
                    except (KeyError,ValueError,OverflowError):
                        pass
                if computed and operation not in ("LOAD_CONST","LOAD_BOOL"):
                    # Comparing values with == would merge 0 and -0, booleans
                    # and integers. Fresh constants preserve exact literal kind.
                    index=len(constants)
                    constants[index]=value
                    values.append(IRValue(f"{function.id}:k{index}","constant",index,literal=value))
                    result=replace(instruction,operation="LOAD_CONST",inputs=(),
                        constants=(f"{function.id}:k{index}",),
                        operands=(operands["destination"],IROperand("value","constant",index)),
                        metadata={**instruction.metadata,"constant_folded_from":operation})
                if "call" in OPERATIONS[operation].effects and not computed:
                    known.clear()
                if "upvalue_write" in OPERATIONS[operation].effects:
                    known.clear()
                for output in instruction.outputs:
                    if output.startswith(function.id+":r"):
                        known.pop(int(output.rsplit(":r",1)[1]),None)
                if computed:
                    known[operands["destination"].value]=value
                instructions.append(result)
            blocks.append(replace(block,instructions=tuple(instructions)))
        return replace(function,values=tuple(values),blocks=tuple(blocks),
                       children=tuple(optimize(child) for child in function.children))
    result=replace(ir,root=optimize(ir.root))
    validate_semantic_ir(result)
    return result
