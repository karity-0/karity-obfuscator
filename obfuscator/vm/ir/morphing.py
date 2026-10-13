"""Compose bounded, independent semantic strategies over shared proofs."""
from dataclasses import replace
from collections import Counter
import hashlib
import random
import time
from .model import IRInstruction, IROperand, IRValue
from .validate import validate_semantic_ir

RATES=('ir_test_set_rate','ir_tail_duplication_rate','ir_rematerialization_rate','ir_mba_rate')
DEFAULTS={'ir_morph_max_growth':1.35,'ir_morph_max_added_instructions':128,
          'ir_morph_max_added_blocks':16,'ir_morph_max_transforms':16,
          'ir_morph_max_depth':2,'ir_morph_pass_max_added_instructions':4096,
          'ir_morph_max_new_operations':3}


class MorphContext:
    def __init__(self,function,analysis,options,strategy,rng,base,shared):
        self.function=function;self.analysis=analysis;self.options=options
        self.strategy=strategy;self.rng=rng;self.base=base;self.shared=shared
        self.stats={'strategy':strategy,'applied':0,'failed':0,'skipped':Counter(),'added_instructions':0,'added_blocks':0}
        self.used={i.id for b in function.blocks for i in b.instructions} | {b.id for b in function.blocks}
        self.counter=0;self.stack=function.max_stack_size;self.temps=None

    def skip(self,reason):self.stats['skipped'][reason]+=1

    def selected(self,instruction,rate):
        if instruction.id not in self.analysis.before:
            self.skip('unreachable');return False
        if instruction.metadata.get('morph_depth',0)>=self.options['ir_morph_max_depth']:
            self.skip('depth');return False
        if self.rng.random()>=rate:
            self.skip('rate');return False
        return True

    def admit(self,added,blocks,operations):
        current=sum(len(b.instructions) for b in self.function.blocks)+self.stats['added_instructions']
        block_count=len(self.function.blocks)+self.stats['added_blocks']
        limit=min(int(self.base[0]*self.options['ir_morph_max_growth']),self.base[0]+self.options['ir_morph_max_added_instructions'])
        # At most three handler slots per semantic instruction; keep a factor
        # of two of the signed jump range for linker/control expansion.
        if (current+added>limit or 3*(current+added)>131071//2
                or block_count+blocks>self.base[1]+self.options['ir_morph_max_added_blocks']
                or self.shared['added']+added>self.options['ir_morph_pass_max_added_instructions']):
            self.skip('growth_budget');return False
        if self.stats['applied']>=self.options['ir_morph_max_transforms']:
            self.skip('strategy_limit');return False
        new=set(operations)-self.shared['operations']
        if len(self.shared['introduced'] | new)>self.options['ir_morph_max_new_operations']:
            self.skip('operation_inventory_budget');return False
        self.shared['operations'].update(operations);self.shared['introduced'].update(new)
        self.shared['added']+=added
        self.stats['applied']+=1;self.stats['added_instructions']+=added;self.stats['added_blocks']+=blocks
        return True

    def can_scratch(self,width):
        if self.temps is not None:return len(self.temps)>=width
        if self.analysis.liveness.open_extents:
            self.skip('open_register_top');return False
        limit=max(self.function.max_stack_size,255-self.shared['register_reserve'])
        if self.stack+width>limit:
            self.skip('protection_scratch_budget');return False
        return True

    def scratch(self,width):
        if self.temps is not None:return self.temps[:width]
        if not self.can_scratch(width):raise RuntimeError('IR scratch precondition changed')
        self.temps=tuple(range(self.stack,self.stack+width));self.stack+=width
        return self.temps

    def identifier(self,parent):
        while True:
            self.counter+=1;name=f'{parent}:m:{self.strategy}:{self.counter}'
            if name not in self.used:self.used.add(name);return name

    def make(self,parent,operation,operands,targets=()):
        inputs=[];outputs=[];constants=[]
        for operand in operands:
            if operand.kind=='register':
                (outputs if operand.role=='destination' else inputs).append(f'{self.function.id}:r{operand.value}')
            elif operand.kind=='constant':constants.append(f'{self.function.id}:k{operand.value}')
        return IRInstruction(self.identifier(parent.id),operation,tuple(dict.fromkeys(inputs)),tuple(outputs),
            tuple(constants),tuple(targets),tuple(operands),
            {**parent.metadata,'protection_origin':'ir_morph','morph_origin':self.strategy,
             'morph_parent':parent.id,'morph_depth':parent.metadata.get('morph_depth',0)+1})

    def finish(self,blocks):
        values=self.function.values+tuple(IRValue(f'{self.function.id}:r{r}','register',r)
                    for r in range(self.function.max_stack_size,self.stack))
        return replace(self.function,blocks=tuple(blocks),values=values,max_stack_size=self.stack,
            debug_metadata={**self.function.debug_metadata,'morph_strategies':
                (*self.function.debug_metadata.get('morph_strategies',()),self.strategy)})


def morph_semantic_ir(ir,options,version,*,seed_state=None,register_reserve=0):
    rates={key:float(options.get(key,0)) for key in RATES}
    if not any(rates.values()):return ir,[]
    from .facts import analyze_function
    from .morph_test_set import transform as test_set
    from .morph_tail import transform as tail
    from .morph_rematerialize import transform as rematerialize
    from .morph_mba import transform as mba
    policy={**DEFAULTS,**options}
    seed=hashlib.blake2b(repr(seed_state or random.getstate()).encode(),digest_size=16).digest()
    shared={'added':0,'introduced':set(),'register_reserve':register_reserve,
            'operations':{i.operation for f in ir.functions() for b in f.blocks for i in b.instructions}}
    records=[]
    def visit(function):
        base=(sum(len(b.instructions) for b in function.blocks),len(function.blocks))
        analysis=None
        for key,strategy in zip(RATES,(test_set,tail,rematerialize,mba)):
            if not rates[key]:continue
            started=time.perf_counter()
            if analysis is None:
                analysis=analyze_function(function,version)
                records.append({'phase':'ir_morph_analysis','function':function.id,'elapsed':time.perf_counter()-started})
            rng=random.Random(int.from_bytes(hashlib.blake2b(seed+(function.id+key).encode(),digest_size=16).digest(),'little'))
            ctx=MorphContext(function,analysis,policy,key,rng,base,shared)
            started=time.perf_counter();changed=strategy(ctx,rates[key])
            records.append({'phase':'ir_morph_strategy','function':function.id,'elapsed':time.perf_counter()-started,
                            **ctx.stats,'skipped':dict(ctx.stats['skipped'])})
            if changed is not function:
                function=changed;analysis=None
                validate_semantic_ir(replace(ir,root=function))
        return replace(function,children=tuple(visit(child) for child in function.children))
    result=replace(ir,root=visit(ir.root))
    validate_semantic_ir(result)
    records.append({'phase':'semantic_ir_morphing','added_instructions':shared['added'],
                    'introduced_operations':sorted(shared['introduced']), 'generation':result.generation})
    return result,records
