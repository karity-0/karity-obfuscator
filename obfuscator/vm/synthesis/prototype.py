"""Executable mechanism prototype, deliberately separate from real VM emitters.

Tests local numeric recipe execution and 48-bit record/operand-table feasibility.
It does not model Karity private state or MOV microcode and must not be presented
as a backend optimization or appended to production handlers.
"""
import random
from ..backends.handler_codec import Writer,INSTRUCTION_BYTES
from ..backends.handler_ir import HandlerInstruction
from .planner import validate_plan

OPERATORS={'ADD':'+','SUB':'-','MUL':'*','NEGATE':'-','BIT_NOT':'~',
           'BIT_AND':'&','BIT_OR':'|','BIT_XOR':'~','SHIFT_LEFT':'<<','SHIFT_RIGHT':'>>'}


def allocate_opcodes(recipes,seed=0,reserved=()):
    used=set(reserved)
    if any(type(v) is not int or not 0<=v<32768 for v in used):
        raise ValueError('invalid reserved vop')
    available=[v for v in range(32768) if v not in used]
    if len(recipes)>len(available):raise ValueError('dynamic opcode space exhausted')
    rng=random.Random(seed)
    selected=rng.sample(available,len(recipes))
    if len({r.id for r in recipes})!=len(recipes):raise ValueError('duplicate recipe ID')
    return {r.id:v for r,v in zip(recipes,selected)}


def encode_occurrence(occurrence,opcode):
    """Prototype 6-byte record plus sparse ULEB binding; production ABI unchanged."""
    if type(opcode) is not int or not 0<=opcode<32768:raise ValueError('opcode range')
    words=Writer();words.instr(HandlerInstruction(0).with_bx(0),opcode&127,opcode>>7)
    assert len(words.data())==INSTRUCTION_BYTES
    return words.data(),encode_bindings(occurrence)


def encode_bindings(occurrence):
    """Binding bytes alone are deterministic; no random instruction padding."""
    binding=Writer();binding.uint(len(occurrence.inputs))
    for v in occurrence.inputs:
        if v.kind not in ('register','constant') or type(v.index) is not int or v.index<0:
            raise ValueError('invalid operand binding')
        binding.u8(0 if v.kind=='register' else 1);binding.uint(v.index)
    binding.uint(len(occurrence.output_registers))
    for r in occurrence.output_registers:
        if type(r) is not int or not 0<=r<255:raise ValueError('invalid output register')
        binding.uint(r)
    return binding.data()


def emit_kernel(recipe):
    lines=['function(binding)']
    for index,kind in enumerate(recipe.input_kinds):
        getter=f'rget(binding.inputs[{index+1}])' if kind=='register' else f'K[binding.inputs[{index+1}]+1]'
        lines.append(f'local i{index}={getter}')
    for index,step in enumerate(recipe.steps):
        args=[('i' if v.kind=='input' else 't')+str(v.index) for v in step.inputs]
        if step.operation in ('NEGATE','BIT_NOT'):expr=OPERATORS[step.operation]+args[0]
        else:expr=args[0]+OPERATORS[step.operation]+args[1]
        lines.append(f'local t{index}={expr}')
    for index,value in enumerate(recipe.outputs):lines.append(f'rset(binding.outputs[{index+1}],t{value})')
    return lines[0]+'\n'+';'.join(lines[1:])+'\nend'


def emit_region_benchmark(ir,plan,occurrence,*,mode='synthesis',iterations=10000,
                          instrument=False,seed=0):
    """Decoded region microbenchmark. Fusion mode retains two operand records.

    The outer driver varies the first register input and accumulates into the
    second. Caller must compare against the matching native numeric fixture.
    Full programs/stack semantics are not emulated by this prototype harness.
    """
    validate_plan(ir,plan,lua_version=plan.version)
    if occurrence not in plan.occurrences:raise ValueError('unbound occurrence')
    if mode not in ('ordinary','fusion','synthesis'):raise ValueError('prototype mode')
    if type(iterations) is not int or not 1<=iterations<=1000000:raise ValueError('prototype iterations')
    function=next(f for f in ir.functions() if f.id==occurrence.function)
    instructions={i.id:i for b in function.blocks for i in b.instructions}
    constants={v.index:v.literal for v in function.values if v.kind=='constant'}
    if any(type(constants[v.index]) not in (int,float) for v in occurrence.inputs if v.kind=='constant'):
        raise ValueError('prototype only supports numeric constants')
    regs=[v.index for v in occurrence.inputs if v.kind=='register']
    if len(regs)!=2 or len(occurrence.output_registers)!=1 or occurrence.output_registers[0]!=regs[1]:
        raise ValueError('benchmark requires iterator input and accumulator input/output')
    def n(v):return repr(v) if type(v) is float else str(v)
    text=['local regs,K={},{}','local dispatches,reads,writes=0,0,0']
    for index,value in constants.items():
        if type(value) in (int,float):text.append(f'K[{index+1}]={n(value)}')
    text += [f'local function rget(i) {"reads=reads+1;" if instrument else ""}return regs[i] end',
             f'local function rset(i,v) {"writes=writes+1;" if instrument else ""}regs[i]=v end']
    recipes={r.id:r for r in plan.recipes}
    handlers=[];program=[]
    if mode=='synthesis':
        opcode=allocate_opcodes(plan.recipes,seed,reserved=range(64))[occurrence.recipe]
        handlers.append(f'[{opcode}]={emit_kernel(recipes[occurrence.recipe])}')
        inp=','.join(str(v.index) for v in occurrence.inputs)
        out=','.join(str(r) for r in occurrence.output_registers)
        text.append('local binding={inputs={'+inp+'},outputs={'+out+'}}')
        program=[opcode]
    else:
        # Distinct scalar handlers and a two-record fusion-shaped handler. This
        # is not a claim that production alias/decode/state costs are identical.
        source=[instructions[key] for key in occurrence.source_ids]
        def expression(i):
            operands={v.role:v for v in i.operands}
            def value(role):
                v=operands[role]
                return f'rget({v.value})' if v.kind=='register' else f'K[{v.value+1}]'
            expr=OPERATORS[i.operation]+value('source') if i.operation in ('NEGATE','BIT_NOT') else value('left')+OPERATORS[i.operation]+value('right')
            return f'rset({operands["destination"].value},{expr})'
        width=2 if mode=='fusion' else 1
        for index in range(0,len(source),width):
            statements=';'.join(expression(i) for i in source[index:index+width])
            opcode=index+1;handlers.append(f'[{opcode}]=function() {statements} end');program.append(opcode)
        text.append('local binding=nil')
    text += ['local handlers={'+','.join(handlers)+'}',
             'local program={'+','.join(str(x) for x in program)+'}',
             f'regs[{regs[1]}]=0',f'for i=1,{iterations} do',f'regs[{regs[0]}]=i',
             'for pc=1,#program do',
             'dispatches=dispatches+1' if instrument else '',
             'handlers[program[pc]](binding)','end','end',
             f'print(regs[{regs[1]}],dispatches,reads,writes)']
    return '\n'.join(text)+'\n'
