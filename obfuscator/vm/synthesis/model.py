"""Backend-independent ordered dataflow recipes and occurrence bindings."""
from dataclasses import dataclass
import json


@dataclass(frozen=True)
class Ref:
    kind: str
    index: int


@dataclass(frozen=True)
class Step:
    operation: str
    inputs: tuple[Ref, ...]


@dataclass(frozen=True)
class Binding:
    kind: str
    index: int


@dataclass(frozen=True)
class Recipe:
    id: str
    domain: str
    input_kinds: tuple[str, ...]
    steps: tuple[Step, ...]
    outputs: tuple[int, ...]
    edges: tuple[tuple[int, int], ...]
    ordered: bool = False


@dataclass(frozen=True)
class Cost:
    dispatch_before: int
    fusion_dispatch_estimate: int
    dispatch_after: int
    reads_before: int
    reads_after: int
    writes_before: int
    writes_after: int
    binding_bytes_estimate: int
    loop_region: bool = False
    logical_events_after: int = 0
    operand_slot_bytes: int = 0


@dataclass(frozen=True)
class Occurrence:
    function: str
    block: str
    source_ids: tuple[str, ...]
    recipe: str
    inputs: tuple[Binding, ...]
    output_registers: tuple[int, ...]
    cost: Cost
    scope: str
    materialize: bool = False
    numeric_domain: str = 'number'
    local_values: tuple[int, ...] = ()


@dataclass(frozen=True)
class SynthesisPlan:
    generation: str
    version: str
    recipes: tuple[Recipe, ...]
    occurrences: tuple[Occurrence, ...]
    rejected: tuple[tuple[str, int], ...]
    backend: str = 'prototype'
    protection_signature: str = ''
    decisions: tuple[dict, ...] = ()

    def dump(self):
        from dataclasses import asdict
        return json.dumps(asdict(self), indent=2, sort_keys=True)+'\n'
