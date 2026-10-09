"""Resolve backend-neutral runtime-plan names to the handler ABI once."""
from __future__ import annotations

import random

from .handler_ir import OPERATIONS
from ..vm_mutation import planned_mutation_seeds


def resolve_runtime_variants(lowered) -> tuple[dict, ...]:
    root = lowered.protection_plan.functions[lowered.semantic_ir.root.id]
    semantic_active = lowered.resolution.is_active("semantic_variants")
    helper_active = lowered.resolution.is_active("helper_variants")
    decoys_active = lowered.resolution.is_active("decoy_handlers")
    mutation_active = lowered.resolution.is_active("handler_mutation")
    resolved = []
    for variant, aliases in zip(root["runtime_variants"], root["alias_requirements"]):
        concrete = dict(variant)
        named_modes = dict(variant["semantic_alias_modes"])
        named_transitions = dict(variant["alias_transition_indices"])
        counts = dict(aliases["operations"])
        auxiliary_seeds = planned_mutation_seeds(
            variant["mutation_seed"],
            {opcode: f"aux-transition:{name}"
             for opcode, name in enumerate(OPERATIONS)
             if name not in named_transitions},
        )
        concrete["semantic_alias_modes"] = {
            opcode: (named_modes.get(
                name, (False,) * counts.get(name, aliases["auxiliary_count"])
            ) if semantic_active else
                (False,) * counts.get(name, aliases["auxiliary_count"]))
            for opcode, name in enumerate(OPERATIONS)
        }
        concrete["alias_transition_indices"] = {
            opcode: (named_transitions[name] if name in named_transitions
                     else tuple(random.Random(auxiliary_seeds[opcode]).sample(
                         range(8), counts.get(name, aliases["auxiliary_count"]))))
            for opcode, name in enumerate(OPERATIONS)
        }
        if not helper_active:
            concrete["helper_variant_count"] = 1
            concrete["helper_route_cycles"] = tuple(
                (name, (0,)) for name in ("rget", "rset", "_flow", "_sem")
            )
        if not decoys_active:
            concrete["decoy_body_variants"] = ()
        if not mutation_active:
            concrete["mutate_handlers"] = False
        resolved.append(concrete)
    return tuple(resolved)
