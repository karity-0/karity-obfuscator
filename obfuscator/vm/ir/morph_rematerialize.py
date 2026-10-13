"""Break a shared pure definition's scalar use without moving side effects."""
from dataclasses import replace
from collections import Counter
from .model import IROperand
from .facts import _INTEGER_OPS


def transform(ctx,rate):
    uses=Counter()
    register_indices={v.id:v.index for v in ctx.function.values if v.kind=='register'}
    for block in ctx.function.blocks:
        for instruction in block.instructions:
            if instruction.id not in ctx.analysis.definitions:continue
            for name in set(instruction.inputs) & register_indices.keys():
                r=register_indices[name];defs=ctx.analysis.definitions[instruction.id][r]
                if len(defs)==1:uses[(r,next(iter(defs)))]+=1
    edits={};done=set()
    for block in ctx.function.blocks:
        for consumer in block.instructions:
            if consumer.id not in ctx.analysis.definitions:continue
            for operand in consumer.operands:
                if operand.kind!='register' or operand.role not in {'source','left','right','condition'}:continue
                name=f'{ctx.function.id}:r{operand.value}'
                defs=ctx.analysis.definitions[consumer.id][operand.value]
                if len(defs)!=1 or uses[(operand.value,next(iter(defs)))]<2:continue
                producer=ctx.analysis.producers.get(next(iter(defs)))
                if producer is None or producer.id in done or producer.operation not in _INTEGER_OPS:continue
                if consumer.metadata.get('morph_depth',0)>=ctx.options['ir_morph_max_depth']:
                    ctx.skip('depth');continue
                if not ctx.analysis.effects[producer.id].pure:ctx.skip('impure_producer');continue
                if any(ctx.analysis.operand(producer,v.role).kind!='integer' for v in producer.operands if v.role!='destination'):
                    ctx.skip('unproven_integer');continue
                pblock,ppos=ctx.analysis.locations[producer.id]
                if not ctx.analysis.dominates(pblock,block.id) or pblock==block.id and ppos>=ctx.analysis.locations[consumer.id][1]:continue
                if any(ctx.analysis.definitions[producer.id][v.value]!=ctx.analysis.definitions[consumer.id][v.value]
                       for v in producer.operands if v.kind=='register' and v.role!='destination'):
                    ctx.skip('operand_redefined');continue
                if not ctx.selected(producer,rate):continue
                if not ctx.can_scratch(1):continue
                if not ctx.admit(1,0,(producer.operation,)):continue
                temp=ctx.scratch(1)[0]
                operands=tuple(IROperand('destination','register',temp) if v.role=='destination' else v for v in producer.operands)
                clone=ctx.make(producer,producer.operation,operands)
                operands=tuple(replace(v,value=temp) if v.kind=='register' and v.role in {'source','left','right','condition'} and v.value==operand.value else v for v in consumer.operands)
                inputs=tuple(f'{ctx.function.id}:r{temp}' if v==name else v for v in consumer.inputs)
                rewritten=replace(consumer,inputs=tuple(dict.fromkeys(inputs)),operands=operands,
                    metadata={**consumer.metadata,'protection_origin':'ir_morph','morph_origin':ctx.strategy,'morph_parent':consumer.id,
                              'morph_depth':consumer.metadata.get('morph_depth',0)+1})
                edits[consumer.id]=(clone,rewritten);done.add(producer.id);break
    if not edits:return ctx.function
    return ctx.finish(replace(b,instructions=tuple(x for i in b.instructions for x in edits.get(i.id,(i,)))) for b in ctx.function.blocks)
