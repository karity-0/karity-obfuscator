"""Separate truth testing from the edge-local operand assignment."""
from dataclasses import replace
from .model import IRBlock,IROperand


def transform(ctx,rate):
    blocks=[];extras=[]
    for block in ctx.function.blocks:
        last=block.instructions[-1]
        if last.operation!='TEST_SET' or not ctx.selected(last,rate):
            blocks.append(block);continue
        if not ctx.admit(1,1,('TEST','MOVE')):
            blocks.append(block);continue
        operands={v.role:v for v in last.operands}
        assign=ctx.identifier(block.id)
        test=ctx.make(last,'TEST',(operands['condition'],operands['expected']),(assign,last.targets[1]))
        move=ctx.make(last,'MOVE',(operands['destination'],IROperand('source','register',operands['condition'].value)),(last.targets[0],))
        blocks.append(replace(block,instructions=(*block.instructions[:-1],test),successors=test.targets))
        extras.append(IRBlock(assign,(move,),move.targets))
    return ctx.finish((*blocks,*extras)) if extras else ctx.function
