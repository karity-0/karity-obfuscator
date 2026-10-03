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

    def compose_runtime(self, source, lowered, *, target=None):
        # The shared loader template already contains the continuation executor.
        return source

    def validate_lowered(self, lowered):
        from .handler_validation import validate_handler_dispatch
        validate_handler_dispatch(lowered, delayed=True)

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

    def emit_handlers(self, source, lowered, variants):
        from .handler_emission import single_handlers
        from ..vm_obfuscation import (apply_execution_kit, apply_dispatch_target_hiding,
                                      wire_exec_router, build_next_router_kit, build_exec_variants)
        count = lowered.backend_data['layout'].vm_count
        def render(template, index):
            variant = variants[index]
            result = single_handlers(template, lowered, variant, vm_index=index,
                                     executor_name=f'_ex{index}' if count > 1 else None)
            result = apply_execution_kit(result, variant['helper_variant_count'], 0.0, variant)
            if lowered.policy.get('dispatcher_target_hiding', False):
                result = apply_dispatch_target_hiding(result)
            return result.replace('_NX', f'_NX[{index + 1}]') if count > 1 else result
        if count > 1:
            source = build_exec_variants(source, count, render)
        else:
            source = wire_exec_router(render(source, 0), 0)
        return build_next_router_kit(source, count)
