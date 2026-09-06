"""Small, fixed-width IR. Addresses are one-based, like the Lua executor.

LOOKUP indexes an internal table using a scratch-slot key. SELECT chooses
immediate addresses (mode=0) or addresses held in scratch slots (mode=1).
MOVE mode=1 stores a scratch value into an internal table through a slot key.
HOST is an explicit boundary for Lua values, effects and representation changes.
"""
from dataclasses import dataclass, field
from enum import IntEnum


class Op(IntEnum):
    MOVE = 1
    LOOKUP = 2
    SELECT = 3
    HOST = 4


class Host(IntEnum):
    EXEC = 0
    PREPARE = 1
    COMMIT = 2
    COPY = 3
    READ_TRUTH = 4
    CLOSE = 5
    DIVZERO = 6
    COMMIT_TRUTH = 7
    COMMIT_STRING = 8
    COMMIT_FLOAT = 9


@dataclass(frozen=True)
class Instruction:
    op: Op
    a: int = 0
    b: int = 0
    c: int = 0
    d: int = 0
    mode: int = 0


@dataclass
class Program:
    entries: list[int]
    code: list[Instruction]
    lowered_sites: int
    vm_id: int = 0
    recipe_offsets: dict[str, int] = field(default_factory=dict)
