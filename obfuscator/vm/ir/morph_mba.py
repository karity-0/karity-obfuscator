"""Integer identities change actual IR operations, not handler implementations."""
from dataclasses import replace
from .model import IROperand

# Destination/operand symbols: x,y are original operands; a,b are scratch.
PATTERNS={
 'BIT_XOR': (
  (('BIT_OR','a','x','y'),('BIT_AND','b','x','y'),('BIT_NOT','b','b'),('BIT_AND','d','a','b')),
  (('BIT_NOT','a','y'),('BIT_AND','a','x','a'),('BIT_NOT','b','x'),('BIT_AND','b','y','b'),('BIT_OR','d','a','b')),
  (('BIT_OR','a','x','y'),('BIT_AND','b','x','y'),('SUB','d','a','b'))),
 'BIT_AND': (
  (('BIT_OR','a','x','y'),('BIT_XOR','b','x','y'),('SUB','d','a','b')),
  (('BIT_NOT','a','x'),('BIT_NOT','b','y'),('BIT_OR','a','a','b'),('BIT_NOT','d','a'))),
 'BIT_OR': (
  (('ADD','a','x','y'),('BIT_AND','b','x','y'),('SUB','d','a','b')),
  (('BIT_AND','a','x','y'),('BIT_XOR','b','x','y'),('ADD','d','a','b'))),
 'ADD': (
  (('BIT_XOR','a','x','y'),('BIT_AND','b','x','y'),('ADD','b','b','b'),('ADD','d','a','b')),
  (('BIT_OR','a','x','y'),('BIT_AND','b','x','y'),('ADD','d','a','b'))),
 'SUB': (
  (('BIT_AND','a','x','y'),('SUB','b','y','a'),('SUB','a','x','a'),('SUB','d','a','b')),
  (('BIT_NOT','a','x'),('BIT_NOT','b','y'),('SUB','d','b','a')),
  (('BIT_XOR','a','x','y'),('BIT_NOT','b','x'),('BIT_AND','b','b','y'),('ADD','b','b','b'),('SUB','d','a','b'))),
}


def transform(ctx,rate):
    if ctx.analysis.version!='5.3':ctx.skip('target_has_no_integer_domain');return ctx.function
    edits={}
    for block in ctx.function.blocks:
        for original in block.instructions:
            if original.operation not in PATTERNS:continue
            if not ctx.selected(original,rate):continue
            if any(ctx.analysis.operand(original,r).kind!='integer' for r in ('left','right')):
                ctx.skip('unproven_integer');continue
            if not ctx.can_scratch(2):continue
            operands={v.role:v for v in original.operands}
            kinds={'x':operands['left'].kind,'y':operands['right'].kind}
            # Unary IR operands are registers, unlike binary RK operands.
            # Preserve constants as RK operands rather than emitting an invalid
            # BIT_NOT constant or allocating a third scratch register.
            valid=[p for p in PATTERNS[original.operation] if not any(
                len(step)==3 and kinds.get(step[2],'register')!='register' for step in p)]
            if not valid:ctx.skip('unary_constant_operand');continue
            patterns=ctx.rng.sample(valid,len(valid))
            pattern=next((p for p in patterns if ctx.admit(len(p)-1,0,[v[0] for v in p])),None)
            if pattern is None:continue
            a,b=ctx.scratch(2)
            symbols={'x':operands['left'],'y':operands['right'],'d':operands['destination'],
                     'a':IROperand('value','register',a),'b':IROperand('value','register',b)}
            sequence=[]
            for op,dst,*args in pattern:
                roles=('source',) if len(args)==1 else ('left','right')
                ops=(replace(symbols[dst],role='destination'),*(replace(symbols[arg],role=role) for arg,role in zip(args,roles)))
                sequence.append(ctx.make(original,op,ops))
            sequence[-1]=replace(sequence[-1],targets=original.targets)
            edits[original.id]=tuple(sequence)
    if not edits:return ctx.function
    return ctx.finish(replace(b,instructions=tuple(x for i in b.instructions for x in edits.get(i.id,(i,)))) for b in ctx.function.blocks)
