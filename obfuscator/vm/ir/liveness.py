"""Register and captured-local lifetimes over explicit semantic control flow."""
from dataclasses import dataclass


@dataclass(frozen=True)
class FunctionLiveness:
    live_in: dict[str, frozenset[str]]
    live_out: dict[str, frozenset[str]]
    before: dict[str, frozenset[str]]
    after: dict[str, frozenset[str]]
    captured_before: dict[str, frozenset[str]]
    captured_after: dict[str, frozenset[str]]
    open_extents: frozenset[str]

    def dump(self, function_id):
        names=lambda values:",".join(sorted(values)) or "-"
        lines=["lifetimes " + function_id]
        for block in sorted(self.live_in):
            lines.append(f"  live-block {block} in={names(self.live_in[block])} out={names(self.live_out[block])}")
        for instruction in sorted(self.before):
            lines.append(f"  live-instruction {instruction} before={names(self.before[instruction])} "
                         f"after={names(self.after[instruction])} captures-before={names(self.captured_before[instruction])} "
                         f"captures-after={names(self.captured_after[instruction])} open={int(instruction in self.open_extents)}")
        return "\n".join(lines)+"\n"


def analyze_liveness(function):
    blocks={block.id:block for block in function.blocks}
    predecessors={key:set() for key in blocks}
    for block in blocks.values():
        for target in block.successors:
            predecessors[target].add(block.id)
    captured_in={key:set() for key in blocks}
    captured_out={key:set() for key in blocks}
    captured_before={}
    captured_after={}

    def captures(instruction, current):
        current=set(current)
        if instruction.operation=="CLOSURE":
            current.update(f"{function.id}:r{value.value}" for value in instruction.operands
                           if value.role=="capture" and value.kind=="register")
        if instruction.operation=="JUMP":
            first=next(value.value for value in instruction.operands if value.role=="close_from")
            if first is not None:
                current={value for value in current if int(value.rsplit(":r",1)[1])<first}
        if instruction.operation in ("RETURN","TAIL_CALL"):
            current.clear()
        return current

    changed=True
    while changed:
        changed=False
        for block in blocks.values():
            incoming=set().union(*(captured_out[key] for key in predecessors[block.id]))
            current=set(incoming)
            for instruction in block.instructions:
                captured_before[instruction.id]=frozenset(current)
                current=captures(instruction,current)
                captured_after[instruction.id]=frozenset(current)
            if incoming!=captured_in[block.id] or current!=captured_out[block.id]:
                captured_in[block.id],captured_out[block.id]=incoming,current
                changed=True

    live_in={key:set() for key in blocks}
    live_out={key:set() for key in blocks}
    before,after={},{}
    # Open ranges include runtime top and may extend beyond the static frame.
    # The marker prevents a future allocator from treating that tail as free.
    top=function.id+":runtime_top"
    open_extents=set()
    for block in blocks.values():
        for instruction in block.instructions:
            if any(value.kind=="register_range" and value.count is None for value in instruction.operands):
                open_extents.add(instruction.id)
    changed=True
    while changed:
        changed=False
        for block in reversed(tuple(blocks.values())):
            outgoing=set().union(*(live_in[key] for key in block.successors))
            current=set(outgoing)
            for instruction in reversed(block.instructions):
                current.update(captured_after[instruction.id])
                after[instruction.id]=frozenset(current)
                # These destinations are assigned on only one outgoing edge.
                # Keeping the old value live on both edges is conservative.
                if instruction.operation not in ("TEST_SET","FOR_LOOP","ITER_LOOP"):
                    current.difference_update(instruction.outputs)
                current.update(instruction.inputs)
                current.update(captured_before[instruction.id])
                if instruction.id in open_extents:
                    current.add(top)
                before[instruction.id]=frozenset(current)
            if current!=live_in[block.id] or outgoing!=live_out[block.id]:
                live_in[block.id],live_out[block.id]=current,outgoing
                changed=True
    freeze=lambda values:{key:frozenset(value) for key,value in values.items()}
    return FunctionLiveness(freeze(live_in),freeze(live_out),before,after,
                            captured_before,captured_after,frozenset(open_extents))
