"""Microcode folding and per-VM recipe sharing before storage emission."""
from dataclasses import replace
from .ir import Instruction, Op, Program
from .validate import validate_program


def _relocate(code: list[Instruction], address) -> list[Instruction]:
    return [replace(i, b=address(i.b), c=address(i.c))
            if i.op == Op.SELECT and i.mode == 0 else i for i in code]


def link_programs(programs: list[Program], count: int):
    """Link each VM into a shared tape; frames retain private scratch storage.

    Recipes only read scratch slots and return through frame continuations, so
    an integer/multiply/compare recipe can safely serve every prototype in a VM.
    """
    tapes: list[list[Instruction]] = [[] for _ in range(count)]
    recipe_bases: list[dict[str, int]] = [{} for _ in range(count)]
    for program in programs:
        tape, bases = tapes[program.vm_id], recipe_bases[program.vm_id]
        offsets = sorted(program.recipe_offsets.items(), key=lambda item: item[1])
        for index, (kind, start) in enumerate(offsets):
            if kind in bases:
                continue
            stop = offsets[index + 1][1] if index + 1 < len(offsets) else len(program.code) + 1
            bases[kind] = len(tape) + 1
            delta = bases[kind] - start
            tape.extend(_relocate(program.code[start - 1:stop - 1], lambda a: a + delta))

    entries = []
    for program in programs:
        tape, bases = tapes[program.vm_id], recipe_bases[program.vm_id]
        offsets = sorted(program.recipe_offsets.items(), key=lambda item: item[1])
        prefix_end = offsets[0][1] if offsets else len(program.code) + 1
        prefix_base = len(tape) + 1

        def address(old: int) -> int:
            if old < prefix_end:
                return prefix_base + old - 1
            for kind, start in reversed(offsets):
                if old >= start:
                    return bases[kind] + old - start
            raise ValueError(f"invalid MOV link address {old}")

        entries.append([address(a) for a in program.entries])
        tape.extend(_relocate(program.code[:prefix_end - 1], address))
    return tapes, entries, sum(len(b) for b in recipe_bases)



def optimize_program(program: Program) -> Program:
    validate_program(program)
    targets = set(program.entries) | set(program.recipe_offsets.values())
    for instruction in program.code:
        if instruction.op == Op.SELECT and not instruction.mode:
            targets.update((instruction.b, instruction.c))
    kept = []
    addresses = {}
    for index, instruction in enumerate(program.code, 1):
        addresses[index] = len(kept) + 1
        # Restrict folding to an untargeted interior instruction. Shared table
        # mutation and HOST boundaries cannot be crossed by this local rule.
        redundant = (instruction.op == Op.MOVE and instruction.mode == 0
                     and instruction.a == instruction.b)
        if kept and instruction.op == Op.LOOKUP and instruction.a not in (instruction.b, instruction.c):
            redundant |= instruction == kept[-1]
        if index in targets or index == len(program.code) or not redundant:
            kept.append(instruction)
    result = Program([addresses[entry] for entry in program.entries],
                     _relocate(kept, addresses.__getitem__), program.lowered_sites,
                     program.vm_id, {key: addresses[value] for key, value in program.recipe_offsets.items()})
    validate_program(result)
    return result
