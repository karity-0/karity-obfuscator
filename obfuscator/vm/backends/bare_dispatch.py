"""Compile program blocks into a randomized position dispatcher.

Leaves contain the program's Lua operations. No opcode stream is interpreted.
IDs and the decision tree exist only in generated source, not a runtime blob.
"""
from dataclasses import dataclass
import random
from typing import TYPE_CHECKING
from ..ir.model import IRBlock, IRFunction, IRInstruction

if TYPE_CHECKING:
    from .bare_emitter import Function


@dataclass
class Segment:
    block: IRBlock
    instructions: tuple[IRInstruction, ...]
    following: int | None
    position: int = 0


def emit(function: IRFunction, emitter: 'Function') -> str:
    # Keep each function's layout draws independent of its optimized shape.
    rng = random.Random(random.getrandbits(64))
    segments: list[Segment] = []
    entries: dict[str, int] = {}
    for block in function.blocks:
        entries[block.id] = len(segments)
        units=[]
        offset = 0
        while offset < len(block.instructions):
            width=block.instructions[offset].metadata.get('bare_call_length',1)
            units.append(block.instructions[offset:offset+width])
            offset+=width
        offset=0
        while offset<len(units):
            # Keep short straight-line blocks together. Dispatching every few
            # bytecode instructions magnifies source pre-pass expansion.
            width=rng.randint(16,32)
            items=tuple(i for unit in units[offset:offset+width] for i in unit)
            offset += width
            following = len(segments) + 1 if offset < len(units) else None
            segments.append(Segment(block, items, following))
    ids = rng.sample(range(1, 2**24), len(segments))
    for segment, position in zip(segments, ids):
        segment.position = position

    from .bare_flow import emit as emit_flow
    return emit_flow(function,emitter,segments,entries,rng)
