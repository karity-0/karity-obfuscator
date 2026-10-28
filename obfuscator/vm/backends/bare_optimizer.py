"""Bare emission views preserve protected IR identities and reachable events."""
from dataclasses import replace

from ..ir import validate_semantic_ir
from ..ir.facts import analyze_function, literal_fact
from ..ir.liveness import analyze_liveness


def prepare_emission(lowered, lua_version):
    statistics = {'unreachable_blocks': 0, 'unreachable_instructions': 0}
    events: list[dict] = []

    def prune(function):
        blocks = {block.id: block for block in function.blocks}
        pending = [function.blocks[0].id]
        reachable = set()
        while pending:
            key = pending.pop()
            if key in reachable:
                continue
            reachable.add(key)
            pending.extend(blocks[key].successors)
        removed = [block for block in function.blocks if block.id not in reachable]
        statistics['unreachable_blocks'] += len(removed)
        statistics['unreachable_instructions'] += sum(len(block.instructions) for block in removed)
        events.extend({'function': function.id, 'kind': 'unreachable-block',
                       'outcome': 'elided', 'block': block.id} for block in removed)
        return replace(function, blocks=tuple(block for block in function.blocks if block.id in reachable),
                       children=tuple(prune(child) for child in function.children))

    view = replace(lowered.semantic_ir, root=prune(lowered.semantic_ir.root))
    validate_semantic_ir(view)
    lowered.backend_data['bare_emission_ir'] = view
    lowered.backend_data['liveness'] = {f.id: analyze_liveness(f) for f in view.functions()}
    security = lowered.backend_data['source_protection']
    constants = dict(zip(security.constant_slots, security.constants))
    hints: dict[str,dict] = {}
    for function in view.functions():
        literals = {v.index:v.literal for v in function.values if v.kind=='constant'}
        hints[function.id] = {}
        for block in function.blocks:
            for instruction in block.instructions:
                call = instruction.metadata.get('bare_call')
                if (call and call[0]=='method' and call[1]=='constant' and len(call[2])==1
                        and call[2][0][0]=='constant'):
                    slot = literals[call[2][0][1]]
                    hints[function.id][instruction.metadata['bare_call_end']] = literal_fact(constants[slot],lua_version)
    lowered.backend_data['bare_facts'] = {f.id: analyze_function(f, lua_version,
        liveness=lowered.backend_data['liveness'][f.id],result_hints=hints[f.id]) for f in view.functions()}
    from .bare_lifetimes import preserve_locals
    lowered.backend_data['bare_local_releases']={}
    lowered.backend_data['bare_edge_releases']={}
    for function in view.functions():
        info=lowered.backend_data['bare_facts'][function.id]
        releases={};edges={}
        lifetime=preserve_locals(function,info.liveness,info,hints[function.id],releases,edges)
        info.liveness=lifetime
        lowered.backend_data['liveness'][function.id]=lifetime
        lowered.backend_data['bare_local_releases'][function.id]=releases
        lowered.backend_data['bare_edge_releases'][function.id]=edges
    lowered.backend_data['optimization'] = statistics
    lowered.backend_data['optimization_events'] = tuple(events)
    return lowered
