from typing import Any

from .base import KARITY_OPTIONS, VMBackend
from ..protection import BackendCapabilities, option_feature


class KarityBackend(VMBackend):
    name = "karity"
    description = 'hardened graph and encoded-register runtime'
    lowered_kind = "karity-handler-graph"
    capabilities = BackendCapabilities(
        name,
        frozenset(filter(None, (option_feature(option) for option in KARITY_OPTIONS)))
        | frozenset({"handler_aliases"}),
        KARITY_OPTIONS,
    )

    def compose_runtime(self, source, lowered):
        # The shared loader template already contains the continuation executor.
        return source

    def _policy(self, options: dict[str, Any]) -> dict[str, Any]:
        policy = super()._policy(options)
        policy.update({
            "graph_execution_rate": float(options.get("graph_execution_rate", 0.1)),
            "cross_instruction_rate": float(options.get("cross_instruction_rate", 0.2)),
            "runtime_polymorphism_rate": float(
                options.get("runtime_polymorphism_rate", 0.2)
            ),
            "block_variant_rate": float(options.get("block_variant_rate", 0.08)),
            "semantic_diversity_rate": float(
                options.get("semantic_diversity_rate", 0.35)
            ),
        })
        return policy
