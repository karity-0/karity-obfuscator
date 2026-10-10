"""Generate per-literal statement programs, shared by source and VM emitters.

All working words are unsigned 24-bit integers. Multiplication stays below
2**32, and rotations mask before shifting, so no float or signed-overflow
assumptions leak into the Lua program. Longer literals reuse a generated
schedule over shuffled records instead of growing the statement graph.
"""
from __future__ import annotations

import random
from dataclasses import dataclass

from ..names import NameAllocator


_BITS = 24
_MODULUS = 1 << _BITS
_MASK = _MODULUS - 1
_UNROLL_LIMIT = 16
_UNROLL_CHUNKS = 8
_OPERATIONS = ("add", "sub", "mul", "xor", "rol", "ror", "mba_add", "mba_xor")


def _constant(value: int) -> str:
    """Hide seed/constants modestly; NumberObf can layer the numeric leaves."""
    key = random.randint(1, _MASK)
    style = random.randrange(4)
    if style == 0:
        return f"({value ^ key} ~ {key})"
    if style == 1:
        return f"({value + key} - {key})"
    if style == 2:
        return f"({value - key} + {key})"
    # x + y = (x XOR y) + 2 * (x AND y), with nonnegative operands.
    left = random.randint(0, value)
    right = value - left
    return f"(({left} ~ {right}) + (({left} & {right}) << 1))"


@dataclass(frozen=True)
class _Step:
    slot: int
    operation: str
    salt: int
    delta: int
    shift: int

    def key(self, shared: int) -> int:
        key = (shared ^ self.salt) & _MASK
        return (key & 255) | 1 if self.operation == "mul" else key

    def inverse(self, value: int, key: int) -> int:
        if self.operation in {"add", "mba_add"}:
            return (value - key) & _MASK
        if self.operation == "sub":
            return (value + key) & _MASK
        if self.operation == "mul":
            return (value * pow(key, -1, _MODULUS)) & _MASK
        if self.operation in {"xor", "mba_xor"}:
            return value ^ key
        shift = self.shift if self.operation == "rol" else _BITS - self.shift
        return ((value >> shift) | (value << (_BITS - shift))) & _MASK

    def emit(self, value: str, key: str, shared: str, scratch: str) -> list[str]:
        lines = [f"{key}=({shared} ~ {_constant(self.salt)}) & {_MASK}"]
        if self.operation == "mul":
            lines.append(f"{key}=({key} & 255) | 1")
        if self.operation in {"add", "sub", "mul", "xor"}:
            operator = {"add": "+", "sub": "-", "mul": "*", "xor": "~"}[self.operation]
            lines.append(f"{value}=({value} {operator} {key}) & {_MASK}")
        elif self.operation == "mba_add":
            lines.extend((
                f"{scratch}=({value} & {key}) << 1",
                f"{value}=(({value} ~ {key}) + {scratch}) & {_MASK}",
            ))
        elif self.operation == "mba_xor":
            lines.extend((
                f"{scratch}={value} & {key}",
                f"{value}=({value} | {key}) - {scratch}",
            ))
        else:
            left = self.shift if self.operation == "rol" else _BITS - self.shift
            lines.extend((
                f"{scratch}={value} >> {_BITS - left}",
                f"{value}=(({value} << {left}) | {scratch}) & {_MASK}",
            ))
        lines.append(f"{shared}=({shared} + {key} + {_constant(self.delta)}) & {_MASK}")
        return lines


def _schedule(slots: int, steps: tuple[int, int]) -> list[_Step]:
    pending = [random.randint(*steps) for _ in range(slots)]
    plan = []
    while any(pending):
        slot = random.choice([i for i, count in enumerate(pending) if count])
        pending[slot] -= 1
        plan.append(_Step(slot, random.choice(_OPERATIONS), random.randint(1, _MASK),
                          random.randint(1, 255), random.randint(1, _BITS - 1)))
    return plan


def _seeds(targets: list[int], plan: list[_Step], shared: int) -> tuple[list[int], int]:
    initial = shared
    keys = []
    for step in plan:
        key = step.key(shared)
        keys.append(key)
        shared = (shared + key + step.delta) & _MASK
    values = targets.copy()
    for step, key in reversed(list(zip(plan, keys))):
        values[step.slot] = step.inverse(values[step.slot], key)
    # Later groups depend on an actual reconstructed word, not just keys.
    return [value ^ initial for value in values], shared ^ targets[-1]


def reconstruct(data: bytes, allocator: NameAllocator | None = None) -> str:
    """Return a single-valued Lua expression containing a fresh local program."""
    if not data:
        return "(string.char())"
    allocator = allocator or NameAllocator(seed=random.getrandbits(64))
    allocator.used.update({"string", "table"})
    fresh = allocator.allocate
    shared, key, scratch = fresh(), fresh(), fresh()
    pieces, numbers, lengths = fresh(), fresh(), fresh()
    slots = min(random.randint(2, 4), len(data))
    states = [fresh() for _ in range(slots)]
    strategy = random.choice(("numeric", "partial", "mixed"))
    early = [strategy == "partial" or (strategy == "mixed" and bool(random.getrandbits(1)))
             for _ in states]
    # Random lengths and shuffled calculation order are independent of the
    # final byte order. Three-byte packing keeps all operations comfortably
    # within the exact integer domain, including NumberObf's float backing.
    chunks = []
    offset = 0
    while offset < len(data):
        size = random.randint(1, min(3, len(data) - offset))
        chunks.append(data[offset:offset + size])
        offset += size
    jobs = list(enumerate(chunks, 1))
    random.shuffle(jobs)
    groups = [jobs[i:i + slots] for i in range(0, len(jobs), slots)]
    shared_value = random.randint(1, _MASK)
    declarations = [f"local {pieces}={{}}", f"local {shared}={_constant(shared_value)}",
                    f"local {','.join([key, scratch, *states])}"]
    if not all(early):
        declarations.extend((f"local {numbers}={{}}",
                             f"local {lengths}={{{','.join(str(len(chunk)) for chunk in chunks)}}}"))
    lines = declarations

    def store(slot: int, index: str, size: str) -> list[str]:
        value = states[slot]
        if not early[slot]:
            return [f"{numbers}[{index}]={value}"]
        return [f"{pieces}[{index}]=string.char({value} & 255,"
                f"({value} >> 8) & 255,({value} >> 16) & 255):sub(1,{size})"]

    if len(data) <= _UNROLL_LIMIT and len(chunks) <= _UNROLL_CHUNKS:
        for group in groups:
            plan = _schedule(len(group), (2, 3))
            targets = [int.from_bytes(chunk, "little") for _, chunk in group]
            seeds, next_shared = _seeds(targets, plan, shared_value)
            lines.extend(f"{states[i]}={_constant(seed)} ~ {shared}"
                         for i, seed in enumerate(seeds))
            pending = [sum(step.slot == slot for step in plan) for slot in range(len(group))]
            for step in plan:
                lines.extend(step.emit(states[step.slot], key, shared, scratch))
                pending[step.slot] -= 1
                if not pending[step.slot]:
                    index, chunk = group[step.slot]
                    lines.extend(store(step.slot, str(index), str(len(chunk))))
                elif random.random() < 0.08:
                    # One bounded dead store into a reused scratch register;
                    # all state/key assignments above participate in the result.
                    lines.append(f"{scratch}=({key} ~ {states[step.slot]}) & 255")
            lines.append(f"{shared}={shared} ~ {states[len(group) - 1]}")
            shared_value = next_shared
    else:
        # A new schedule and record layout per literal, reused only within that
        # literal. Control-flow/VM expansion is bounded independently of length.
        plan = _schedule(slots, (2, 3))
        fields = list(range(slots * 3))
        random.shuffle(fields)
        seed_fields, index_fields, size_fields = fields[:slots], fields[slots:2 * slots], fields[2 * slots:]
        records = []
        for group in groups:
            padded = group + [(0, b"")] * (slots - len(group))
            seeds, next_shared = _seeds([int.from_bytes(chunk, "little") for _, chunk in padded],
                                        plan, shared_value)
            record = [0] * len(fields)
            for slot, (index, chunk) in enumerate(padded):
                record[seed_fields[slot]] = seeds[slot]
                record[index_fields[slot]] = index
                record[size_fields[slot]] = len(chunk)
            records.append("{" + ",".join(str(value) for value in record) + "}")
            shared_value = next_shared
        rows, row, cursor = fresh(), fresh(), fresh()
        lines.append(f"local {rows}={{{','.join(records)}}}")
        lines.extend((f"for {cursor}=1,#{rows} do", f"local {row}={rows}[{cursor}]"))
        lines.extend(f"{state}={row}[{seed_fields[slot] + 1}] ~ {shared}"
                     for slot, state in enumerate(states))
        for step in plan:
            lines.extend(step.emit(states[step.slot], key, shared, scratch))
        for slot in range(slots):
            index, size = f"{row}[{index_fields[slot] + 1}]", f"{row}[{size_fields[slot] + 1}]"
            lines.append(f"if {size}>0 then")
            lines.extend(store(slot, index, size))
            lines.append("end")
        lines.extend((f"{shared}={shared} ~ {states[-1]}", "end"))

    if not all(early):
        index, value = fresh(), fresh()
        lines.extend((f"for {index}=1,{len(chunks)} do", f"local {value}={numbers}[{index}]",
                      f"if {value} then",
                      f"{pieces}[{index}]=string.char({value} & 255,"
                      f"({value} >> 8) & 255,({value} >> 16) & 255):sub(1,{lengths}[{index}])",
                      "end", "end"))
    lines.append(f"return table.concat({pieces})")
    # Outer parentheses suppress multiple results even after helper transforms.
    # Nothing is hoisted across source statements, short circuiting or loops.
    return "((function()\n" + ";\n".join(lines) + "\nend)())"
