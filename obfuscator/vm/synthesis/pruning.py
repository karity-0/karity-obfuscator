"""Retire execution bodies, retaining the complete logical event vocabulary."""
from ..backends.runtime_layout import iter_functions


def handler_inventory(lowered,vm):
    layout=lowered.backend_data['layout']
    functions=[f for f in iter_functions(layout.functions) if f.vm_id==vm]
    entries=[e for f in functions for e in f.synthesis]
    if not entries:return None
    aliases,splits,fuses,defers=layout.vm_maps[vm]
    dispatched=set()
    for function in functions:
        owned={i for e in function.synthesis for i in range(e.start+1,e.start+len(e.recipe.steps))}
        # The second word of an ordinary fused handler is an operand/event
        # record too. Split parts, however, each execute their own handler.
        owned.update(i+1 for i,s in enumerate(function.code) if s.vop in fuses.values())
        dispatched.update(s.vop for i,s in enumerate(function.code) if i not in owned)
    if lowered.backend=='mov':
        # Number-only MOV regions still enter the ordinary HOST EXEC bodies
        # through representation guards. Only proven integer continuations
        # eliminate that indirect execution dependency.
        dispatched.update(v for e in entries if e.occurrence.numeric_domain!='integer' for v in e.original_vops)
    numeric={step.operation for e in entries for step in e.recipe.steps}
    from ..backends.handler_ir import OPERATION_IDS
    candidates={OPERATION_IDS[op] for op in numeric}
    retired={op for op in candidates if not set(aliases[op])&dispatched}
    removed={v for op in retired for v in aliases[op]}
    split_keep={op:forms for op,forms in splits.items()
                if op not in retired or any(v in dispatched for values in forms.values() for v in values)}
    fuse_keep={pair:v for pair,v in fuses.items() if not retired.intersection(pair) or v in dispatched}
    defer_keep={op:v for op,v in defers.items() if op not in retired or v in dispatched}
    reserved={v for values in aliases.values() for v in values}
    reserved.update(v for forms in splits.values() for values in forms.values() for v in values)
    reserved.update(fuses.values());reserved.update(defers.values());reserved.update(e.opcode for e in entries)
    if removed&dispatched:raise ValueError('synthesis pruning would remove an executable alias')
    return {'used':layout.used_ops[vm]-removed,'splits':split_keep,'fuses':fuse_keep,'defers':defer_keep,
        'reserved':reserved,'retired_aliases':sorted(removed),
        'retired_composite_handlers':sum(len(values) for op,forms in splits.items() if op not in split_keep for values in forms.values())
            +len(fuses)-len(fuse_keep)+len(defers)-len(defer_keep)}
