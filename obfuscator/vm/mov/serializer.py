"""Versioned MOV extension appended to the shared encrypted prototype blob."""
import struct
from dataclasses import replace

from .ir import Instruction, Op, Program
from .layout import VMKit
from .tables import banks, STATE_COUNTS


def _uint(out: bytearray, value: int) -> None:
    if not 0 <= value <= 0xFFFFFFFF:
        raise ValueError(f"MOV field outside uint32: {value}")
    while value >= 128:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)


def serialize(programs: list[Program], kits: list[VMKit], stats: dict | None = None, *, linked=None) -> bytes:
    if linked is None:
        from .optimizer import link_programs
        linked = link_programs(programs, len(kits))
    from .validate import validate_linked
    validate_linked(programs, kits, linked)
    tapes, entries, recipe_count = linked
    if stats is not None:
        stats.update(stored_micro_instructions=sum(len(t) for t in tapes),
                     shared_recipes=recipe_count)
    out = bytearray(b"MOV\x0b")
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
