"""Validate the dispatcher contract used by the handler-based backends."""
from .runtime_layout import iter_functions


def validate_handler_dispatch(lowered, *, delayed):
    layout = lowered.backend_data['layout']
    planned = {
        descriptor[0]: (tuple(descriptor), state.get('graph_family', 0))
        for state in lowered.protection_plan.instructions.values()
        for descriptor in state.get('occurrence_descriptors', ())
    }
    seen = set()
    for function in iter_functions(layout.functions):
        for item in function.code:
            for family, site, seed, state_key, policy in item.graph_sites:
                if site in seen:
                    raise ValueError('duplicate physical graph site')
                seen.add(site)
                expected = planned.get(site)
                if expected is None or expected[0] != (site, seed, state_key, policy):
                    raise ValueError('physical graph descriptor differs from protection plan')
                expected_family = expected[1] if lowered.policy['graph_execution_rate'] > 0 else 0
                if family != expected_family:
                    raise ValueError('physical graph family differs from backend policy')
    if seen != layout.graph_sites:
        raise ValueError('physical graph site inventory mismatch')
    if len(layout.vm_maps) != layout.vm_count or len(layout.used_ops) != layout.vm_count:
        raise ValueError('handler dispatcher VM count mismatch')
    for vm_id, (aliases, splits, fuses, defers) in enumerate(layout.vm_maps):
        if defers and not delayed:
            raise ValueError('direct backend cannot emit deferred handlers')
        targets = [vop for values in aliases.values() for vop in values]
        targets += [vop for forms in splits.values() for values in forms.values() for vop in values]
        targets += list(fuses.values()) + list(defers.values())
        if any(not isinstance(vop, int) or not 0 <= vop < 32768 for vop in targets):
            raise ValueError('handler opcode exceeds 15-bit dispatcher encoding')
        if len(targets) != len(set(targets)):
            raise ValueError('colliding handler dispatcher targets')
        alias_targets = {vop for values in aliases.values() for vop in values}
        operations = {vop: op for op, values in aliases.items() for vop in values}
        operations.update({vop: op for op, vop in defers.items()})
        split_targets = {}
        for op, forms in splits.items():
            for arity, values in forms.items():
                if arity not in ('2', '3') or len(values) != int(arity):
                    raise ValueError('invalid split handler arity')
                for part, vop in enumerate(values):
                    operations[vop] = op
                    split_targets[vop] = (part, values)
        fused_targets = {vop: pair for pair, vop in fuses.items()}
        operations.update({vop: pair[0] for vop, pair in fused_targets.items()})
        if not layout.used_ops[vm_id] <= alias_targets:
            raise ValueError('dispatcher pruning references an unknown alias')
        for function in iter_functions(layout.functions):
            if function.vm_id != vm_id:
                continue
            interior = set()
            for index, item in enumerate(function.code):
                if item.vop in alias_targets and item.vop not in layout.used_ops[vm_id]:
                    raise ValueError('physical instruction references a pruned handler')
                expected_op = operations.get(item.vop)
                # Non-stream integrity LOAD_CONST splits retain the integrity
                # tag while using the regular constant resolver's split body.
                integrity_split = (item.vop in split_targets and expected_op == 1
                                   and item.instruction.op == 47
                                   and item.instruction.bx in function.integrity_indices)
                if expected_op != item.instruction.op and not integrity_split:
                    raise ValueError('physical instruction operation differs from dispatcher')
                if item.vop in split_targets:
                    part, values = split_targets[item.vop]
                    if part:
                        interior.add(index)
                    start = index - part
                    group = function.code[start:start + len(values)] if start >= 0 else []
                    if (tuple(entry.vop for entry in group) != tuple(values)
                            or any(entry.instruction != item.instruction for entry in group)):
                        raise ValueError('invalid physical split handler sequence')
                if item.vop in fused_targets:
                    interior.add(index + 1)
                    pair = fused_targets[item.vop]
                    operand = function.code[index + 1] if index + 1 < len(function.code) else None
                    if (operand is None or operand.instruction.op != pair[1]
                            or operand.vop not in aliases.get(pair[1], ())):
                        raise ValueError('invalid physical fused operand slot')
            # Composite handlers own their interior slots. Only their first
            # instruction can be entered from another control-flow edge.
            def check_entry(target):
                if target in interior:
                    raise ValueError('control flow enters a composite handler interior')
            check_entry(0)
            for index, item in enumerate(function.code):
                instruction = item.instruction
                operation = instruction.operation
                if operation in {'JUMP', 'FOR_LOOP', 'FOR_PREP', 'ITER_LOOP'}:
                    check_entry(index + 1 + instruction.sbx)
                elif operation == 'BLOCK_GOTO':
                    check_entry(instruction.bx)
                elif operation in {'EQUAL', 'LESS_THAN', 'LESS_EQUAL', 'TEST', 'TEST_SET'}:
                    check_entry(index + 2)
                elif operation == 'LOAD_BOOL' and instruction.c:
                    check_entry(index + 2)
            for route in function.routes:
                for target in route:
                    check_entry(target - 1)
