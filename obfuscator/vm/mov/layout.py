"""Independent instruction IDs and digit alphabets for each MOV interpreter."""
from dataclasses import dataclass
import random

from .ir import Op


@dataclass(frozen=True)
class VMKit:
    opcodes: dict[Op, int]
    encode: tuple[int, ...]


def make_kits(count: int) -> list[VMKit]:
    if not 1 <= count <= 256:
        raise ValueError("MOV supports between 1 and 256 effective VMs")
    ids = iter(random.sample(range(0x100, 0x10000), count * len(Op)))
    alphabets: set[tuple[int, ...]] = set()
    kits = []
    for _ in range(count):
        while True:
            encode = tuple(random.sample(range(16), 16))
            if encode not in alphabets and encode != tuple(range(16)):
                break
        alphabets.add(encode)
        kits.append(VMKit({op: next(ids) for op in Op}, encode))
    return kits
