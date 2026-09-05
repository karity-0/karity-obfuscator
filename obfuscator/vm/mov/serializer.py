"""Versioned MOV extension appended to the shared encrypted prototype blob."""
import struct
from dataclasses import replace

from .ir import Instruction, Op, Program
from .layout import VMKit
from .tables import banks, STATE_COUNTS


def _relocate(code: list[Instruction], address) -> list[Instruction]:
    return [replace(i, b=address(i.b), c=address(i.c))
            if i.op == Op.SELECT and i.mode == 0 else i for i in code]


def _uint(out: bytearray, value: int) -> None:
    if not 0 <= value <= 0xFFFFFFFF:
        raise ValueError(f"MOV field outside uint32: {value}")
    while value >= 128:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)


def _link(programs: list[Program], count: int):
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


def serialize(programs: list[Program], kits: list[VMKit], stats: dict | None = None) -> bytes:
    tapes, entries, recipe_count = _link(programs, len(kits))
    if stats is not None:
        stats.update(stored_micro_instructions=sum(len(t) for t in tapes),
                     shared_recipes=recipe_count)
    out = bytearray(b"MOV\x04")
    out.extend(struct.pack("<H", len(kits)))
    for kit, tape in zip(kits, tapes):
        out.extend(kit.encode)
        out.append(len(STATE_COUNTS))
        for state_count, bank in zip(STATE_COUNTS, banks(kit.encode)):
            out.append(state_count)
            for ys in bank:
                for states in ys:
                    for pair in states:
                        out.extend(pair)
        out.extend(struct.pack("<I", len(tape)))
        for ins in tape:
            out.extend(struct.pack("<H", kit.opcodes[ins.op]))
            for value in (ins.a, ins.b, ins.c, ins.d, ins.mode):
                _uint(out, value)
    out.extend(struct.pack("<I", len(programs)))
    for program, linked_entries in zip(programs, entries):
        out.extend(struct.pack("<HI", program.vm_id, len(linked_entries)))
        for address in linked_entries:
            _uint(out, address)
    return bytes(out)
