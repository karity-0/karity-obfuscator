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
        # Conservative pre-planning envelope: worst split/stream widths,
        # variant copies, linker edges and routing slots. The actual planner
        # may choose cheaper forms, but morphing must not consume its margin.
        width=13 if shared['integrity_stream'] else 3 if shared['split_width'] else 1
        self.physical_width=width
        count=sum(len(b.instructions) for b in function.blocks)
        base_width=3 if shared['split_width'] else 1
        raw_cost=sum(width if i.operation=='LOAD_CONST' and shared['integrity_stream'] else base_width
                     for b in function.blocks for i in b.instructions)
        junk_width=base_width if shared.get('junk',False) else 0
        self.physical_cost=(raw_cost+count*junk_width+2*len(function.blocks))*shared['variant_count']
        if shared['variant_count']>1:
            self.physical_cost+=count*(2 if shared.get('junk',False) else 1)*(1+shared['variant_count'])

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
        width=self.physical_width if 'LOAD_CONST' in operations else 3 if self.shared['split_width'] else 1
        if self.shared.get('junk',False):width+=3 if self.shared['split_width'] else 1
        extra_cost=((self.stats['added_instructions']+added)*width
                    +2*(self.stats['added_blocks']+blocks))*self.shared['variant_count']
        if self.shared['variant_count']>1:
            extra_cost+=(self.stats['added_instructions']+added)*(2 if self.shared.get('junk',False) else 1)*(1+self.shared['variant_count'])
        if self.physical_cost+extra_cost+self.shared['bridge_budget']>131071:
            self.skip('physical_cost_budget');return False
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


def morph_semantic_ir(ir,options,version,*,seed_state=None,register_reserve=0,physical_policy=None):
    rates={key:float(options.get(key,0)) for key in RATES}
    if not any(rates.values()):return ir,[]
    started_total=time.perf_counter()
    from .facts import analyze_function,cfg_components,_INTEGER_OPS
    from .morph_test_set import transform as test_set
    from .morph_tail import transform as tail
    from .morph_rematerialize import transform as rematerialize
    from .morph_mba import transform as mba,PATTERNS
    policy={**DEFAULTS,**options}
    seed=hashlib.blake2b(repr(seed_state or random.getstate()).encode(),digest_size=16).digest()
    shared={'added':0,'introduced':set(),'register_reserve':register_reserve,
            **(physical_policy or {'integrity_stream':False,'split_width':False,'variant_count':1,'bridge_budget':0}),
            'operations':{i.operation for f in ir.functions() for b in f.blocks for i in b.instructions}}
    records=[]
    def visit(function):
        base=(sum(len(b.instructions) for b in function.blocks),len(function.blocks))
        analysis=None;cfg=None
        for key,strategy in zip(RATES,(test_set,tail,rematerialize,mba)):
            if not rates[key]:continue
            started=time.perf_counter()
            operations={i.operation for b in function.blocks for i in b.instructions}
            skip=None
            if key=='ir_test_set_rate' and 'TEST_SET' not in operations:skip='no_candidate_operation'
            if key=='ir_mba_rate' and not operations & PATTERNS.keys():skip='no_candidate_operation'
            if key=='ir_rematerialization_rate' and not operations & _INTEGER_OPS:skip='no_candidate_operation'
            if key in ('ir_mba_rate','ir_rematerialization_rate') and any(
                v.kind=='register_range' and v.count is None for b in function.blocks for i in b.instructions for v in i.operands):
                skip='open_register_top'
            if key in ('ir_mba_rate','ir_rematerialization_rate') and version!='5.3':skip='target_has_no_integer_domain'
            if key=='ir_tail_duplication_rate':
                cfg=cfg or cfg_components(function)
                candidates=[b.id for b in function.blocks[1:] if len(cfg[0][b.id])>=2]
                if not any(all(cfg[1][node]!=cfg[1][p] for p in cfg[0][node]) for node in candidates):
                    skip='no_acyclic_join'
            if skip:
                records.append({'phase':'ir_morph_strategy','function':function.id,'elapsed':time.perf_counter()-started,
                    'strategy':key,'applied':0,'failed':0,'added_instructions':0,'added_blocks':0,'skipped':{skip:1}})
                continue
            if analysis is None:
                analysis=analyze_function(function,version,cfg=cfg)
                cfg=(analysis.predecessors,analysis.components)
                records.append({'phase':'ir_morph_analysis','function':function.id,'elapsed':time.perf_counter()-started})
            rng=random.Random(int.from_bytes(hashlib.blake2b(seed+(function.id+key).encode(),digest_size=16).digest(),'little'))
            ctx=MorphContext(function,analysis,policy,key,rng,base,shared)
            started=time.perf_counter();changed=strategy(ctx,rates[key])
            records.append({'phase':'ir_morph_strategy','function':function.id,'elapsed':time.perf_counter()-started,
                            **ctx.stats,'skipped':dict(ctx.stats['skipped'])})
            if changed is not function:
                function=changed;analysis=None;cfg=None
                validate_semantic_ir(replace(ir,root=function))
        return replace(function,children=tuple(visit(child) for child in function.children))
    result=replace(ir,root=visit(ir.root))
    validate_semantic_ir(result)
    generation=result.generation
    records.append({'phase':'semantic_ir_morphing','added_instructions':shared['added'],
                    'introduced_operations':sorted(shared['introduced']), 'generation':generation,
                    'elapsed':time.perf_counter()-started_total})
    return result,records
