"""Version-independent semantic data model."""
from __future__ import annotations
from hashlib import sha256
from dataclasses import dataclass, field
from typing import Any, Iterable

@dataclass(frozen=True)
class IROperand:
    """An ordered semantic operand; open ranges preserve runtime top and nils."""
    role: str
    kind: str
    value: Any
    count: int | None = None


@dataclass(frozen=True)
class IRValue:
    id: str
    kind: str
    index: int
    name: str = ""
    literal: Any = None


@dataclass(frozen=True)
class IRInstruction:
    id: str
    operation: str
    inputs: tuple[str, ...] = ()
    outputs: tuple[str, ...] = ()
    constants: tuple[str, ...] = ()
    targets: tuple[str, ...] = ()
    operands: tuple[IROperand, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict, compare=False)


@dataclass(frozen=True)
class IRBlock:
    id: str
    instructions: tuple[IRInstruction, ...]
    successors: tuple[str, ...] = ()


@dataclass(frozen=True)
class IRFunction:
    id: str
    params: int
    vararg: bool
    max_stack_size: int
    values: tuple[IRValue, ...]
    blocks: tuple[IRBlock, ...]
    children: tuple["IRFunction", ...] = ()
    source: str = ""
    upvalue_bindings: tuple[tuple[str, int], ...] = ()
    debug_metadata: dict[str, Any] = field(default_factory=dict, compare=False)


@dataclass(frozen=True)
class SemanticIR:
    version: str
    root: IRFunction
    def functions(self) -> Iterable[IRFunction]:
        def walk(function: IRFunction) -> Iterable[IRFunction]:
            yield function
            for child in function.children:
                yield from walk(child)

        return walk(self.root)

    @property
    def generation(self) -> str:
        return sha256(self.dump().encode("utf-8")).hexdigest()[:24]

    def dump(self) -> str:
        lines = [f"semantic-ir {self.version}"]
        for function in self.functions():
            lines.append(
                f"function {function.id} params={function.params} "
                f"vararg={int(function.vararg)} stack={function.max_stack_size} "
                f"captures={function.upvalue_bindings!r}"
            )
            for value in function.values:
                suffix = f" name={value.name!r}" if value.name else ""
                if value.kind == "constant":
                    suffix += f" literal={value.literal!r}"
                lines.append(
                    f"  value {value.id} kind={value.kind} index={value.index}{suffix}"
                )
            for block in function.blocks:
                successors = ",".join(block.successors) or "-"
                lines.append(f"  block {block.id} successors={successors}")
                for instruction in block.instructions:
                    inputs = ",".join(instruction.inputs) or "-"
                    outputs = ",".join(instruction.outputs) or "-"
                    constants = ",".join(instruction.constants) or "-"
                    targets = ",".join(instruction.targets) or "-"
                    lines.append(
                        f"    {instruction.id} {instruction.operation} "
                        f"in={inputs} out={outputs} const={constants} "
                        f"targets={targets} operands={instruction.operands!r}"
                    )
        return "\n".join(lines) + "\n"


