"""Classic's immutable dispatcher and source-to-physical placement contract."""
from __future__ import annotations

from dataclasses import dataclass

from .runtime_layout import iter_functions
from .runtime_variants import resolve_runtime_variants


@dataclass(frozen=True)
class ClassicVariant:
    dispatcher: str
    decoy_body_variants: tuple[int, ...]
    mutate_handlers: bool
    mutation_seed: int
    semantic_alias_modes: tuple[tuple[int, tuple[bool, ...]], ...]
    alias_transition_indices: tuple[tuple[int, tuple[int, ...]], ...]

    @classmethod
    def from_plan(cls, variant: dict) -> "ClassicVariant":
        return cls(
            variant["dispatcher"], tuple(variant["decoy_body_variants"]),
            variant["mutate_handlers"], variant["mutation_seed"],
            tuple(sorted(variant["semantic_alias_modes"].items())),
            tuple(sorted(variant["alias_transition_indices"].items())),
        )

    def as_dict(self) -> dict:
        return {
            "dispatcher": self.dispatcher,
            "decoy_body_variants": self.decoy_body_variants,
            "mutate_handlers": self.mutate_handlers,
            "mutation_seed": self.mutation_seed,
            "semantic_alias_modes": dict(self.semantic_alias_modes),
            "alias_transition_indices": dict(self.alias_transition_indices),
        }


@dataclass(frozen=True)
class ClassicVMState:
    vm_id: int
    aliases: tuple[tuple[int, tuple[int, ...]], ...]
    splits: tuple[tuple[int, tuple[tuple[str, tuple[int, ...]], ...]], ...]
    fuses: tuple[tuple[tuple[int, int], int], ...]
    used_aliases: frozenset[int]
    variant: ClassicVariant

    def handler_map(self):
        return (
            {operation: list(vops) for operation, vops in self.aliases},
            {operation: dict(forms) for operation, forms in self.splits},
            dict(self.fuses),
            {},  # Classic never has deferred handlers.
        )


@dataclass(frozen=True)
class ClassicFunctionState:
    function: str
    vm_id: int
    source_positions: tuple[tuple[str, tuple[int, ...]], ...]


@dataclass(frozen=True)
class ClassicState:
    vms: tuple[ClassicVMState, ...]
    functions: tuple[ClassicFunctionState, ...]

    def dump(self) -> str:
        lines = [
            f"classic-vm {vm.vm_id} aliases={sum(len(vops) for _, vops in vm.aliases)} "
            f"used={len(vm.used_aliases)} splits={len(vm.splits)} "
            f"fuses={len(vm.fuses)} decoys={len(vm.variant.decoy_body_variants)} "
            f"mutate={vm.variant.mutate_handlers} dispatcher={vm.variant.dispatcher}"
            for vm in self.vms
        ]
        for function in self.functions:
            lines.append(f"classic-placement {function.function} vm={function.vm_id}")
            for source_id, positions in function.source_positions:
                lines.append(
                    f"  classic-source {source_id} pcs={','.join(map(str, positions))}"
                )
        return "\n".join(lines) + ("\n" if lines else "")


def lower_state(layout, variants: tuple[dict, ...]) -> ClassicState:
    if (len(variants) != layout.vm_count or len(layout.vm_maps) != layout.vm_count
            or len(layout.used_ops) != layout.vm_count):
        raise ValueError("Classic runtime variant count differs from VM layout")
    vms = []
    for vm_id, ((aliases, splits, fuses, defers), used, variant) in enumerate(
            zip(layout.vm_maps, layout.used_ops, variants)):
        if defers:
            raise ValueError("Classic lowered state cannot contain deferred handlers")
        vms.append(ClassicVMState(
            vm_id,
            tuple((operation, tuple(vops)) for operation, vops in sorted(aliases.items())),
            tuple((operation, tuple(sorted(forms.items())))
                  for operation, forms in sorted(splits.items())),
            tuple(sorted(fuses.items())),
            frozenset(used),
            ClassicVariant.from_plan(variant),
        ))
    functions = []
    for function in iter_functions(layout.functions):
        positions: dict[str, list[int]] = {}
        for pc, item in enumerate(function.code):
            positions.setdefault(item.instruction.source_id, []).append(pc)
        functions.append(ClassicFunctionState(
            function.source.id, function.vm_id,
            tuple((source_id, tuple(pcs)) for source_id, pcs in positions.items()),
        ))
    return ClassicState(tuple(vms), tuple(functions))


def validate_state(lowered) -> None:
    actual = lowered.backend_data.get("classic_state")
    if not isinstance(actual, ClassicState):
        raise ValueError("Classic lowered dispatcher state is missing")
    expected = lower_state(
        lowered.backend_data["layout"], resolve_runtime_variants(lowered),
    )
    if actual != expected:
        raise ValueError("Classic lowered dispatcher state differs from layout or plan")
