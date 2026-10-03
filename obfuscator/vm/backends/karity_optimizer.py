"""Karity-only dead producer and local materialization optimization.

Deferred handlers are allocated for every eligible operation present in a VM,
but the protection plan may choose no deferred form for a particular operation.
Only physical vops prove whether a producer can execute.  Prune the unreferenced
handler mapping without touching instruction PCs, graph descriptors, or epoch
transitions; the emitter then never generates those dead producer bodies.
Comparison handlers also reuse one rget result when both operands name the
same register.  The first read resolves any pending value; no write, call,
graph evaluation, or epoch rotation occurs before the second operand read.
"""
from __future__ import annotations

from .handler_ir import OPERATIONS
from .runtime_layout import iter_functions


_COMPARISONS = frozenset(("EQUAL", "LESS_THAN", "LESS_EQUAL"))


def deferred_signature(layout) -> tuple[tuple[tuple[int, int], ...], ...]:
    """Stable snapshot used to reject mutation after the optimizer has run."""
    return tuple(tuple(sorted(defers.items())) for _, _, _, defers in layout.vm_maps)


def optimize_layout(layout) -> tuple[dict[str, int | str], tuple[dict[str, object], ...]]:
    referenced = [set() for _ in layout.vm_maps]
    coalesced = []
    for function in iter_functions(layout.functions):
        referenced[function.vm_id].update(item.vop for item in function.code)
        aliases = layout.vm_maps[function.vm_id][0]
        for pc, item in enumerate(function.code):
            instruction = item.instruction
            if (instruction.operation in _COMPARISONS
                    and instruction.b == instruction.c
                    and item.vop in aliases.get(instruction.op, ())):
                coalesced.append((function.source.id, pc, instruction.source_id))

    events: list[dict[str, object]] = []
    before = 0
    after = 0
    for vm_id, (aliases, splits, fuses, defers) in enumerate(layout.vm_maps):
        before += len(defers)
        retained = {}
        for operation, vop in sorted(defers.items()):
            used = vop in referenced[vm_id]
            if used:
                retained[operation] = vop
                after += 1
            events.append({
                "vm": vm_id,
                "kind": "deferred-producer",
                "operation": OPERATIONS[operation],
                "outcome": "retained" if used else "elided",
                "reason": "physical-producer" if used else "no-physical-producer",
            })
        layout.vm_maps[vm_id] = aliases, splits, fuses, retained
    events.extend({
        "function": function, "pc": pc, "source": source,
        "kind": "comparison-materialization", "outcome": "coalesced",
        "reason": "same-register-within-instruction",
    } for function, pc, source in coalesced)
    return ({
        "backend": "karity",
        "deferred_handlers_before": before,
        "deferred_handlers_after": after,
        "dead_deferred_handlers": before - after,
        "comparison_reads_coalesced": len(coalesced),
    }, tuple(events))
