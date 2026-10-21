"""Representation-independent protection IR and late-bound constant payloads."""
from dataclasses import dataclass, field, replace
from pathlib import Path
import math
import random
import re
import struct

from .host_guards import inspector_source
from .ir.model import IRBlock, IRFunction, IRInstruction as I, IROperand as O, IRValue, SemanticIR
from .ir.validate import validate_semantic_ir
from .string_storage import MODULUS, encode as encode_string, _key


@dataclass
class SourceProtection:
    slots: dict[str, int]
    sentinel: int
    record_tags: dict[str,int] = field(default_factory=dict)
    bootstrap_slots: dict[int,int] = field(default_factory=dict)
    alphabet: str = ''
    native_source: str = ''
    index_mask: int = 0
    prefix: bytes = b''
    gaps: list[bytes] = field(default_factory=list)
    payload_size: int = 0
    constant_lookup: dict = field(default_factory=dict)
    features: frozenset[str] = frozenset()
    constants: list[object] = field(default_factory=list)
    seeds: list[int] = field(default_factory=list)
    constant_slots: list[int] = field(default_factory=list)
    runtime_id: str = ''
    line_state: int = 0
    script_hash: int = 0

    def add_constant(self, value):
        key=(type(value),value)
        if key in self.constant_lookup:return self.constant_lookup[key]
        self.constants.append(value)
        self.seeds.append(random.randrange(1, MODULUS))
        slot=(self.payload_size+1)^self.index_mask
        self.constant_slots.append(slot)
        self.constant_lookup[key]=slot
        gap=random.randbytes(random.randrange(4))
        self.gaps.append(gap)
        size=13+len(value if isinstance(value,bytes) else value.encode('utf8')) if isinstance(value,(bytes,str)) else 17
        self.payload_size+=size+len(gap)
        return slot

    def printable(self, data):
        return data.hex().translate(str.maketrans('0123456789abcdef',self.alphabet))

    def raw_payload(self):
        records=[self.prefix]
        for value,seed,gap in zip(self.constants,self.seeds,self.gaps):
            if isinstance(value,(str,bytes)):
                data=encode_string(value,self.script_hash,self.line_state,seed=seed)
                record=struct.pack('<BI',self.record_tags['string'],len(data))+data
            else:
                key=_key(seed,self.script_hash,self.line_state)
                encoded=int(value-key)
                record=struct.pack('<BIqI',self.record_tags['number'],seed,encoded,(encoded%MODULUS+key*257)%MODULUS)
            records.extend((record,gap))
        return b''.join(records)

    def payload(self, literal):
        return literal(self.printable(self.raw_payload()))


def _namespace(ir, prefix):
    def rename(function):
        def key(value): return prefix + value
        return replace(function,id=key(function.id),
            values=tuple(replace(v,id=key(v.id)) for v in function.values),
            blocks=tuple(replace(b,id=key(b.id),successors=tuple(map(key,b.successors)),
                instructions=tuple(replace(i,id=key(i.id),inputs=tuple(map(key,i.inputs)),
                    outputs=tuple(map(key,i.outputs)),constants=tuple(map(key,i.constants)),
                    targets=tuple(map(key,i.targets))) for i in b.instructions)) for b in function.blocks),
            children=tuple(rename(c) for c in function.children),
            debug_metadata={**function.debug_metadata,'security_owned':True})
    return replace(ir,root=rename(ir.root))


def prepare(ir, plan, context):
    import string
    names=('guard','constant','write','global_get','global_set','script_hash','setmeta','inspect','fail')
    p=SourceProtection(dict(zip(names,random.sample(range(31,4000),len(names)))),random.randrange(1,2**24))
    p.record_tags=dict(zip(('number','string'),random.sample(range(1,256),2)))
    p.index_mask=random.randrange(2**20,2**31)
    p.prefix=random.randbytes(random.randint(3,15))
    p.payload_size=len(p.prefix)
    p.bootstrap_slots=dict(zip(range(1,14),random.sample(range(31,4000),13)))
    p.alphabet=''.join(random.sample(string.ascii_letters+string.digits,16))
    p.add_constant(p.sentinel)
    operations={i.operation for f in ir.functions() for b in f.blocks for i in b.instructions}
    features={'number'}
    if operations & {'SET_TABLE','SET_UPVALUE_TABLE','GLOBAL_SET'}:features.add('write')
    if operations & {'CALL','TAIL_CALL'}:features.add('setmeta')
    if 'GET_SCRIPT_HASH' in operations:features.add('script_hash')
    if context.target.lua_version=='5.1' and operations & {'GLOBAL_GET','GLOBAL_SET'}:features.add('global_get')
    if context.target.lua_version=='5.1' and 'GLOBAL_SET' in operations:features.add('global_set')
    protected=_instrument(ir,plan,p,context)
    if any(isinstance(v,(str,bytes)) for v in p.constants):features.add('string')
    p.features=frozenset(features)
    text=(Path(__file__).parent/'runtimes/source_security.lua').read_text(encoding='utf8')
    for feature in ('string','write','setmeta','script_hash','global_get','global_set'):
        pattern=r'--<<'+feature+r'>>\n(.*?)--<<END'+feature+r'>>'
        text=re.sub(pattern,lambda m:m[1] if feature in features else '',text,flags=re.S)
    apis={'byte':'string.byte','char':'string.char','sub':'string.sub','concat':'table.concat',
          'info':'debug.getinfo','hook':'debug.gethook','pcall':'pcall'}
    text=text.replace('__SHARED_INSPECTOR__',inspector_source())
    text=text.replace('_ENV_CHECK','envcheck').replace('_ENV_REFRESH','envrefresh')
    used=sorted(set(re.findall(r'\bA\.(\w+)',text)))
    api_slots=dict(zip(used,random.sample(range(31,4000),len(used))))
    text=text.replace('__API__','{'+','.join('['+str(api_slots[k])+']='+apis[k] for k in used)+'}')
    replacements={'__SENTINEL__':str(p.sentinel),'__SENTINEL_SLOT__':str(p.constant_slots[0]),
        '__GUARD_SLOT__':str(p.slots['guard']),
        '__ALPHABET__':repr(p.alphabet),'__INDEX_MASK__':str(p.index_mask),
        '__TNUMBER__':str(p.record_tags['number']),
        '__TSTRING__':str(p.record_tags['string'])}
    for key,value in replacements.items():text=text.replace(key,value)
    text=re.sub(r'function S\.(\w+)\(',r'S.\1=function(',text)
    for name,slot in p.slots.items():text=re.sub(r'\bS\.'+name+r'\b','S['+str(slot)+']',text)
    for name,slot in api_slots.items():text=re.sub(r'\bA\.'+name+r'\b','A['+str(slot)+']',text)
    text=re.sub(r'\bP\[(\d+)\]',lambda m:'P['+str(p.bootstrap_slots[int(m[1])])+']',text)
    p.native_source=text.removeprefix('return ')
    # Only the decisions/call boundaries are dispatched. Repeated byte decoding,
    # table walks and authorized refresh use one shared primitive implementation.
    driver=f'''return function(make,P,self,payload,line)
local S,install=make(P,self,payload,line)
local inspect,fail=S[{p.slots['inspect']}],S[{p.slots['fail']}]
local function guard(force) if not inspect(force) then fail() end end
install(guard);guard(true);return S
end'''
    security=context.target.build_ir(context.target.compile(driver,context.toolchain))
    security=_namespace(security,'security:')
    p.runtime_id=security.root.id
    protected=replace(protected,root=replace(protected.root,children=(*protected.root.children,security.root)))
    validate_semantic_ir(protected)
    return protected,p


def _instrument(ir, plan, protection, context):
    def transform(function, parent_context=None, parent_guard=None):
        values=list(function.values)
        upvalues=sum(v.kind=='upvalue' for v in values)
        context_up,guard_up=upvalues,upvalues+1
        for index in (context_up,guard_up):values.append(IRValue(f'{function.id}:u{index}','upvalue',index))
        bindings=(*function.upvalue_bindings,
            ('upvalue',parent_context) if parent_context is not None else ('register',0),
            ('upvalue',parent_guard) if parent_guard is not None else ('register',0))
        base=function.max_stack_size
        for index in range(base,base+6):values.append(IRValue(f'{function.id}:r{index}','register',index))
        constants={v.index:v.literal for v in values if v.kind=='constant'}
        constant_indices={(type(v),v):k for k,v in constants.items()}
        protected={}
        for value in function.values:
            selected=plan.values.get(value.id,{}).get('integrity_encoded',False)
            number=value.literal
            if (value.kind=='constant' and context.target.lua_version=='5.1'
                    and context.options.get('integrity_constants') and isinstance(number,float)
                    and number.is_integer() and abs(number)<2**52
                    and (number!=0 or math.copysign(1,number)>0)):
                selected=random.random()<float(context.options.get('integrity_constant_rate',0.25))
            if value.kind=='constant' and (isinstance(value.literal,(str,bytes)) or selected):
                protected[value.index]=protection.add_constant(value.literal)
        def constant(value):
            key=(type(value),value)
            if key in constant_indices:return O('value','constant',constant_indices[key])
            index=len(constants);constants[index]=value
            constant_indices[key]=index
            values.append(IRValue(f'{function.id}:k{index}','constant',index,literal=value))
            return O('value','constant',index)
        counter=0
        def make(operation,operands,targets=(),metadata=None):
            nonlocal counter
            counter+=1
            reads=[];writes=[];ks=[]
            for o in operands:
                if o.kind=='constant':ks.append(f'{function.id}:k{o.value}')
                elif o.kind=='upvalue':reads.append(f'{function.id}:u{o.value}')
                elif o.kind in ('register','register_range'):
                    names=[f'{function.id}:r{v}' for v in range(o.value,o.value+(o.count or 0))] if o.kind=='register_range' else [f'{function.id}:r{o.value}']
                    (writes if o.role in ('destination','results') else reads).extend(names)
            return I(f'{function.id}:protection:{counter}',operation,tuple(reads),tuple(writes),tuple(ks),targets,tuple(operands),metadata or {'protection_origin':'source_integrity'})
        def reg(role,index):return O(role,'register',index)
        def compact(out,description):
            out[0]=replace(out[0],metadata={**out[0].metadata,'bare_call':description,
                'bare_call_length':len(out),'bare_call_end':out[-1].id})
            for index in range(1,len(out)):
                out[index]=replace(out[index],metadata={**out[index].metadata,'bare_call_skip':True})
            return out
        def method(name,args,result=None):
            key=constant(protection.slots[name])
            out=[make('GET_UPVALUE_TABLE',(reg('destination',base),O('table','upvalue',context_up),replace(key,role='key')))]
            for n,arg in enumerate(args,base+1):
                out.append(make('LOAD_CONST',(reg('destination',n),replace(arg,role='value'))) if arg.kind=='constant'
                           else make('MOVE',(reg('destination',n),replace(arg,role='source'))))
            out.append(make('CALL',(reg('callee',base),O('arguments','register_range',base+1,len(args)),
                O('results','register_range',result if result is not None else base,1 if result is not None else 0))))
            return compact(out,('method',name,tuple((a.kind,a.value) for a in args),result))
        def guard(force):
            return compact([make('GET_UPVALUE',(reg('destination',base),O('source','upvalue',guard_up))),
                    make('LOAD_BOOL',(reg('destination',base+1),O('value','immediate',force),O('skip','immediate',False))),
                    make('CALL',(reg('callee',base),O('arguments','register_range',base+1,1),O('results','register_range',base,0)))],('guard',force))
        blocks=[]
        for block in function.blocks:
            instructions=guard(block.id==function.blocks[0].id)
            for original in block.instructions:
                start=len(instructions)
                operands=[]
                for o in original.operands:
                    if o.kind=='constant' and o.value in protected:
                        index=base+4+sum(o2.kind=='register' and o2.value>=base+4 for o2 in operands)
                        instructions.extend(method('constant',[constant(protected[o.value])],index))
                        o=replace(o,kind='register',value=index)
                    operands.append(o)
                fields={o.role:o for o in operands}
                op=original.operation
                if op=='LOAD_CONST' and fields['value'].kind=='register':
                    instructions.append(make('MOVE',(fields['destination'],replace(fields['value'],role='source'))))
                elif op in ('GLOBAL_GET','GLOBAL_SET'):
                    args=[fields['key']]+([fields['source']] if op=='GLOBAL_SET' else [])
                    instructions.extend(method('global_get' if op=='GLOBAL_GET' else 'global_set',args,
                        fields['destination'].value if op=='GLOBAL_GET' else None))
                elif op in ('SET_TABLE','SET_UPVALUE_TABLE'):
                    table=fields['table']
                    if table.kind=='upvalue':
                        instructions.append(make('GET_UPVALUE',(reg('destination',base+3),replace(table,role='source'))))
                        table=reg('table',base+3)
                    instructions.extend(method('write',[table,fields['key'],fields['value']]))
                else:
                    if op in ('CALL','TAIL_CALL','RETURN'):instructions.extend(guard(True))
                    changed=replace(original,targets=(),operands=tuple(operands))
                    if operands!=list(original.operands):
                        extra=tuple(f'{function.id}:r{o.value}' for o in operands if o.kind=='register' and o.value>=base)
                        changed=replace(changed,inputs=(*original.inputs,*extra),constants=tuple(
                            f'{function.id}:k{o.value}' for o in operands if o.kind=='constant'))
                    instructions.append(changed)
                    if op=='CALL':instructions.extend(guard(True))
                # Original edges belong only to the final replacement operation.
                if original.targets:
                    instructions[-1]=replace(instructions[-1],targets=original.targets)
                if len(instructions)==start:raise AssertionError('empty protected instruction')
            blocks.append(replace(block,instructions=tuple(instructions)))
        children=tuple(transform(c,context_up,guard_up) for c in function.children)
        # The extra private captures are linked on every original CLOSURE.
        blocks=tuple(replace(b,instructions=tuple(replace(i,operands=(*i.operands,
            O('capture','upvalue',context_up),O('capture','upvalue',guard_up))) if i.operation=='CLOSURE' else i
            for i in b.instructions)) for b in blocks)
        return replace(function,values=tuple(values),blocks=blocks,children=children,upvalue_bindings=bindings,
            max_stack_size=base+6,debug_metadata={**function.debug_metadata,'security_scratch_base':base,
                'security_context_upvalue':context_up,'security_guard_upvalue':guard_up})
    result=replace(ir,root=transform(ir.root))
    validate_semantic_ir(result)
    return result


