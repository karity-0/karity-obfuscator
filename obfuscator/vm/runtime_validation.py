"""Compile private runtime verdicts into existing semantic/backend execution."""
from dataclasses import replace
import time

from .runtime_probes import verifier_source


def mark_validation(function):
    if (function.params!=2 or function.vararg or function.children or function.upvalue_bindings
            or any(v.kind=='upvalue' for v in function.values)):
        raise ValueError('runtime validator must be a closed two-argument observation consumer')
    if any(i.operation in ('GLOBAL_GET','GLOBAL_SET','GET_UPVALUE','SET_UPVALUE',
                           'GET_UPVALUE_TABLE','SET_UPVALUE_TABLE','CLOSURE') or i.metadata.get('guard_event')
           for b in function.blocks for i in b.instructions):
        raise ValueError('runtime validator cannot capture bootstrap state or guard scheduling')
    return replace(function,
        debug_metadata={**function.debug_metadata,'security_owned':True,
                        'security_subsystem':'runtime_validation','security_optimization_safe':True},
        blocks=tuple(replace(block,instructions=tuple(replace(instruction,
            metadata={**instruction.metadata,'protection_origin':'runtime_integrity'})
            for instruction in block.instructions)) for block in function.blocks),
        children=tuple(mark_validation(child) for child in function.children))


def attach(ir, context):
    """Append only; guest prototype indexes/captures and the file format stay valid."""
    from .source_protection import _namespace
    from .ir import validate_semantic_ir
    started=time.perf_counter()
    plan=context.runtime_probe_plan
    if plan is None:raise ValueError('protected runtime probe plan is missing')
    source='return '+verifier_source(plan)
    compiled=context.target.build_ir(context.target.compile(source,context.toolchain))
    function=compiled.root.children[0]
    if function.upvalue_bindings or any(v.kind=='upvalue' for v in function.values):
        raise ValueError('runtime validator must not capture the guest environment')
    private=_namespace(replace(compiled,root=mark_validation(function)),'runtime-security:').root
    result=replace(ir,root=replace(ir.root,children=(*ir.root.children,private)))
    validate_semantic_ir(result)
    context.profile.append({'phase':'runtime_validation_ir','elapsed':round(time.perf_counter()-started,6),
                            'function':private.id,'instructions':sum(len(b.instructions) for b in private.blocks),
                            'verdict_in_ir':True,'new_blob_format':False})
    return result,private.id


def entry_source(backend, target, layout, function_id):
    """Reuse the backend/target's actual root-entry ABI for the private child."""
    indices=[i for i,f in enumerate(layout.functions.children,1) if f.source.id==function_id]
    if len(indices)!=1:raise ValueError('runtime validator private prototype is missing or ambiguous')
    index=indices[0]
    if backend=='karity':
        prefix='ctx.' if target.lua_version=='5.1' else '_'
        environment='self_func' if target.lua_version=='5.1' else 'env_box.v'
        entry=(f'{prefix}CG[__VM_ROUTE_ENTER__]({prefix}NX[_rv_proto.vm_id+1],'
            '{[__VM_Q_KIND__]=__VM_CALL_ENTER__,[__VM_Q_PROTO__]=_rv_proto,'
            '[__VM_Q_UPVALS__]={env_box,environment='+environment+'},'
            f'[__VM_Q_ARGS__]={prefix}apack(_rv_args,2,crc)'+'})')
        values,count='[__VM_RES_VALUES__]','[__VM_RES_COUNT__]'
    else:
        entry=target.direct_runtime_entry(proto='_rv_proto',args='_rv_args')
        values,count='.r','.n'
    return f'''local _rv_proto=proto.protos[{index}]
local _rv_o,_rv_kind,_rv_call=_PS.evidence()
local _rv_args={{n=2,_rv_o,_rv_kind}}
local _rv_ok,_rv_result=_rv_call(function()return {entry} end)
_PS.complete(_rv_ok and _rv_kind(_rv_result)=='table' and _rv_result{count}==1
 and _rv_result{values}[1]==true)
'''
