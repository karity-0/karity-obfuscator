"""Redirect one predecessor to an acyclic join's independent block clone."""
from dataclasses import replace
from .model import IRBlock


def transform(ctx,rate):
    blocks=list(ctx.function.blocks);clones=[];redirects={}
    for block in ctx.function.blocks[1:]:
        predecessors=ctx.analysis.predecessors[block.id]
        if len(predecessors)<2:continue
        if any(ctx.analysis.reaches(block.id,p) for p in predecessors):
            ctx.skip('cyclic_join');continue
        if any(i.id not in ctx.analysis.effects or ctx.analysis.effects[i.id].boundaries
               or ctx.analysis.liveness.captured_before[i.id] for i in block.instructions):
            ctx.skip('lifetime_or_top_boundary');continue
        if any(i.metadata.get('morph_depth',0)>=ctx.options['ir_morph_max_depth'] for i in block.instructions):
            ctx.skip('depth');continue
        last=block.instructions[-1]
        if not ctx.selected(last,rate) or not ctx.admit(len(block.instructions),1,[i.operation for i in block.instructions]):continue
        predecessor=ctx.rng.choice(sorted(predecessors))
        name=ctx.identifier(block.id)
        instructions=tuple(replace(i,id=ctx.identifier(i.id),metadata={**i.metadata,
            'protection_origin':'ir_morph','morph_origin':ctx.strategy,'morph_parent':i.id,
            'morph_depth':i.metadata.get('morph_depth',0)+1}) for i in block.instructions)
        clones.append(IRBlock(name,instructions,block.successors))
        redirects[(predecessor,block.id)]=name
    if not clones:return ctx.function
    for index,block in enumerate(blocks):
        targets=tuple(redirects.get((block.id,t),t) for t in block.successors)
        if targets!=block.successors:
            blocks[index]=replace(block,successors=targets,instructions=(*block.instructions[:-1],replace(block.instructions[-1],targets=targets)))
    return ctx.finish((*blocks,*clones))
