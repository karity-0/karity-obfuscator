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
            width=random.randint(16,32)
            items=tuple(i for unit in units[offset:offset+width] for i in unit)
            offset += width
            following = len(segments) + 1 if offset < len(units) else None
            segments.append(Segment(block, items, following))
    ids = random.sample(range(1, 2**24), len(segments))
    for segment, position in zip(segments, ids):
        segment.position = position

    def advance(index: int) -> str:
        return '_Bposition=' + str(segments[index].position) + '\n'

    leaves = []
    for segment in segments:
        code = ''.join(emitter.instruction(i, segment.block) for i in segment.instructions)
        if segment.following is not None:
            code += advance(segment.following)
        elif len(segment.block.successors) == 2:
            left, right = segment.block.successors
            code += ('if ' + emitter.condition(segment.block) + ' then\n' + advance(entries[left])
                     + 'else\n' + advance(entries[right]) + 'end\n')
        elif segment.block.successors:
            code += advance(entries[segment.block.successors[0]])
        else:
            code += '_Bposition=nil\n'
        leaves.append((segment.position, code))
    leaves.sort()

    def tree(items: list[tuple[int, str]]) -> str:
        if len(items) == 1:
            return items[0][1]
        middle = len(items) // 2
        bound = random.randint(items[middle - 1][0] + 1, items[middle][0])
        left, right = tree(items[:middle]), tree(items[middle:])
        if random.getrandbits(1):
            condition = '_Bposition<' + str(bound)
        else:
            condition = str(bound) + '<=_Bposition'
            left, right = right, left
        return 'if ' + condition + ' then\n' + left + 'else\n' + right + 'end\n'

    return '--[[VM_DISPATCH_ENTRY]]\nlocal _Bposition=' + str(ids[entries[function.blocks[0].id]]) + '\nwhile _Bposition do\n' + tree(leaves) + 'end\n'
