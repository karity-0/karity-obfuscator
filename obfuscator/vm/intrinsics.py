"""Resolve reserved direct calls before semantic optimization and protection."""
from dataclasses import replace
import re

from ..kes import INTRINSICS, Parser
from .ir import IROperand as O, IRInstruction as I
from .ir.validate import validate_semantic_ir

INFO_OPERATIONS = {
    'KARITY_GET_SCRIPT_HASH': 'GET_SCRIPT_HASH',
    'KARITY_GET_VM_COUNT': 'GET_VM_COUNT',
    'KARITY_GET_VM_ID': 'GET_VM_ID',
    'KARITY_GET_LAYOUT_HASH': 'GET_LAYOUT',
    'KARITY_GET_CODE_LENGTH': 'GET_CODE_LENGTH',
}


def _callee_definitions(function):
    """Reaching definitions include disconnected/unreachable compiler blocks."""
    predecessors={block.id:[] for block in function.blocks}
    for block in function.blocks:
        for target in block.successors:predecessors[target].append(block.id)
    outgoing={block.id:{} for block in function.blocks};calls={};changed=True
    while changed:
        changed=False
        for block in function.blocks:
            incoming=[outgoing[key] for key in predecessors[block.id]]
            current={r:frozenset().union(*(state.get(r,frozenset()) for state in incoming)) for r in range(function.max_stack_size)}
            if block is function.blocks[0]:
                for r in current:current[r]=current[r] | {f'{function.id}:entry:r{r}'}
            for instruction in block.instructions:
                if instruction.operation in ('CALL','TAIL_CALL'):
                    register=next(o.value for o in instruction.operands if o.role=='callee')
                    calls[instruction.id]=current[register]
                for output in instruction.outputs:
                    if output.startswith(function.id+':r'):
                        current[int(output.rsplit(':r',1)[1])]=frozenset((instruction.id,))
            if outgoing[block.id]!=current:
                outgoing[block.id]=current;changed=True
    return calls


def mark_intrinsics(source, version):
    """Mark only parsed bare calls, never a table's coincidentally named key."""
    if 'KARITY_' not in source:return source,{}
    parser=Parser(source,version)
    parser.parse()
    mapping={};edits=[]
    for public,position in parser.calls:
        private=next((key for key,value in mapping.items() if value==public),None)
        if private is None:
            private=f'__kes_intrinsic_{len(mapping)}'
            while private in source or private in mapping:private+='x'
            mapping[private]=public
        edits.append((position,position+len(public),private))
    for start,end,text in sorted(edits,reverse=True):source=source[:start]+text+source[end:]
    return source,mapping


def resolve_intrinsics(ir, markers=None):
    markers=markers or {}
    if not markers:return ir
    def resolve(function):
        constants={v.index:v.literal for v in function.values if v.kind=='constant'}
        refs={}
        for block in function.blocks:
            for ins in block.instructions:
                operands={o.role:o for o in ins.operands}
                key=operands.get('key')
                if ins.operation not in ('GLOBAL_GET','GET_UPVALUE_TABLE','GET_TABLE') or key is None or key.kind!='constant':continue
                name=constants[key.value]
                if isinstance(name,bytes):name=name.decode('ascii',errors='replace')
                if name in markers:refs[ins.id]=markers[name]
        if not refs:return replace(function,children=tuple(resolve(c) for c in function.children))
        definitions_by_call=_callee_definitions(function)
        used=set();blocks=[]
        reg=lambda r:f'{function.id}:r{r}'
        for block in function.blocks:
            instructions=[];successors=block.successors
            for ins in block.instructions:
                if ins.id in refs:
                    destination=next(o.value for o in ins.operands if o.role=='destination')
                    instructions.append(replace(ins,operation='LOAD_NIL',inputs=(),constants=(),operands=(O('destination','register_range',destination,1),),metadata={**ins.metadata,'intrinsic_reference':refs[ins.id]}))
                    continue
                if ins.operation not in ('CALL','TAIL_CALL'):
                    instructions.append(ins);continue
                operands={o.role:o for o in ins.operands}
                a=operands['callee'].value
                definitions=definitions_by_call.get(ins.id,frozenset())
                matches=definitions & refs.keys()
                if not matches:
                    instructions.append(ins);continue
                if len(definitions)!=1:
                    raise ValueError('KES intrinsic callee has ambiguous compiler definitions')
                ref=next(iter(matches));name=refs[ref];used.add(ref)
                arguments=operands['arguments'];tail=ins.operation=='TAIL_CALL'
                if arguments.count!=INTRINSICS[name]:
                    raise ValueError(f'KES {name}: compiler argument count is not fixed at {INTRINSICS[name]}')
                results=O('results','register_range',a,None if tail else operands['results'].count)
                metadata={**ins.metadata,'intrinsic':name}
                if name in INFO_OPERATIONS:
                    instructions.append(I(ins.id,INFO_OPERATIONS[name],outputs=(reg(a),),
                        operands=(O('destination','register',a),O('results','register_range',a,None if (not tail and results.count is None) else 1)),
                        targets=() if tail else ins.targets,
                        metadata={**metadata,'intrinsic_open':not tail and results.count is None}))
                    if not tail and results.count is not None and results.count>1:
                        last=instructions.pop()
                        instructions.append(replace(last,targets=()))
                        instructions.append(I(ins.id+':pad','LOAD_NIL',outputs=tuple(reg(r) for r in range(a+1,a+results.count)),
                            operands=(O('destination','register_range',a+1,results.count-1),),targets=ins.targets,metadata=metadata))
                    if tail:
                        instructions.append(I(ins.id+':return','RETURN',inputs=(reg(a),),operands=(O('values','register_range',a,1),),metadata=metadata))
                elif name=='KARITY_ASSERT':
                    count=0 if tail else results.count
                    span=O('results','register_range',a,count)
                    outputs=tuple(reg(r) for r in range(a,a+(count or 0)))
                    instructions.append(I(ins.id,'VM_ASSERT',inputs=(reg(arguments.value),),outputs=outputs,
                        operands=(O('condition','register',arguments.value),span),targets=() if tail else ins.targets,metadata=metadata))
                    if tail:instructions.append(I(ins.id+':return','RETURN',operands=(O('values','register_range',a,0),),metadata=metadata))
                else:
                    instructions.append(I(ins.id,'VM_PANIC' if name=='KARITY_PANIC' else 'VM_ABORT',metadata=metadata))
                    successors=()
            terminal=next((n for n,i in enumerate(instructions) if i.operation in ('VM_ABORT','VM_PANIC')),None)
            if terminal is not None:
                instructions=instructions[:terminal+1]
                successors=()
            blocks.append(replace(block,instructions=tuple(instructions),successors=successors))
        if used!=refs.keys():
            raise ValueError('KES intrinsic reference was not resolved to a direct VM instruction')
        return replace(function,blocks=tuple(blocks),children=tuple(resolve(c) for c in function.children))
    result=replace(ir,root=resolve(ir.root))
    validate_semantic_ir(result)
    return result


def prepare_info_runtime(source, ir):
    instructions=[i for f in ir.functions() for b in f.blocks for i in b.instructions]
    ids={'GET_SCRIPT_HASH':48,'GET_VM_COUNT':49,'GET_LAYOUT':50,'GET_VM_ID':52,'GET_CODE_LENGTH':53}
    info={i.operation for i in instructions if i.operation in ids and i.metadata.get('intrinsic') in INFO_OPERATIONS}
    for operation in info:
        # B is otherwise unused by these existing physical operations. Integrity
        # streams use B=0; only a user's open-result call requests top=A.
        source=re.sub(r'(elseif op=='+str(ids[operation])+r' then rset\(A,[^\n]+)',r'\1; if B==1 then top=A end',source)
    return source


def prepare_intrinsic_runtime(source, ir):
    """Add per-instance poison checks only to outputs that can execute Panic."""
    source=prepare_info_runtime(source,ir)
    instructions=[i for f in ir.functions() for b in f.blocks for i in b.instructions]
    if any(i.operation in ('VM_ABORT','VM_PANIC','VM_ASSERT') for i in instructions):
        anchor='local _IT={seed=0,layout=0,vmc=1,script=0,line=0}'
        if source.count(anchor)!=1:raise ValueError('VM intrinsic failure-state anchor is missing')
        source=source.replace(anchor,anchor[:-1]+',fail=error}')
    if any(i.operation=='VM_PANIC' for i in instructions):
        check='if _IT.invalid then _IT.fail("VM execution failed",0) end; '
        # Interpreter entry and every dispatched step, including MOV microcode.
        # Catching a panic in a native pcall cannot continue the caller VM.
        source=source.replace('while true do','while true do '+check)
        source=source.replace('local function run(blob,self_func,_root_args)',
                              'local function run(blob,self_func,_root_args) '+check)
        source=source.replace('local function _leave(r,n,av,tag)',
                              'local function _leave(r,n,av,tag) '+check)
        # A fused/synthesized handler may perform another operation before the
        # next dispatch. Refuse a subsequent metamethod or native call too.
        source=re.sub(r'(local function (?:_call_packet|_invoke_closure|_sem|_arith[12]\w*|_t(?:get|set|len))\([^)]*\))',
                      lambda match:match[0]+' '+check,source)
        for boundary in ('return {r=res, n=res.n}', 'return table.unpack(w.',
                         'return _unpack_values(w.', 'return table.unpack(_root_values,',
                         'return _unpack_values(_root_values,'):
            source=source.replace(boundary,check+'\n'+boundary)
    return source
