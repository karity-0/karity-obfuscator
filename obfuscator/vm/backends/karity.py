from typing import Any

from .base import KARITY_OPTIONS, RuntimeBody, VMBackend
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

    def lower(self, protected_ir, context):
        lowered = super().lower(protected_ir, context)
        from .karity_state import lower_state
        lowered.backend_data["karity_state"] = lower_state(
            lowered.backend_data["layout"]
        )
        return lowered

    def optimize(self, lowered, context):
        # Layout validators run before this backend-local projection so they
        # retain their precise dispatcher errors for malformed test layouts.
        # Refreshing the projection afterwards makes it an exact snapshot of
        # the validated physical layout, not a second source of lowering data.
        super().optimize(lowered, context)
        from .karity_state import lower_state, validate_state
        lowered.backend_data["karity_state"] = lower_state(
            lowered.backend_data["layout"]
        )
        validate_state(lowered)
        return lowered

    def emit(self, lowered, context):
        # ``VMBuildPipeline`` always optimizes before emission, but retaining
        # this gate also protects direct backend callers from emitting a stale
        # pending/epoch projection.
        from .karity_state import validate_state
        validate_state(lowered)
        return super().emit(lowered, context)

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
            native_state = '--<<TARGET_KARITY_EXEC_STATE>>' in template
            result = single_handlers(template, lowered, variant, vm_index=index,
                                     executor_name=f'_ex{index}' if count > 1 else None)
            result = apply_execution_kit(result, variant['helper_variant_count'], 0.0, variant)
            if lowered.policy.get('dispatcher_target_hiding', False):
                result = apply_dispatch_target_hiding(result, native_state=native_state)
            return result.replace('_NX', f'_NX[{index + 1}]') if count > 1 else result
        if count > 1:
            source = build_exec_variants(source, count, render)
        else:
            source = wire_exec_router(render(source, 0), 0)
        return build_next_router_kit(source, count)

    def emit_runtime_body(self, source, lowered, *, target):
        # Graph and representation-route construction belongs to Karity.  The
        # common emitter only owns the target-finalization/output-pass stages
        # that must run after this late-generated code exists.
        from .runtime_emitter import _apply_handler_graphs
        prepared = lowered.backend_data["layout"]
        root = lowered.protection_plan.functions[lowered.semantic_ir.root.id]
        graph_family_count = 8
        return RuntimeBody(
            source=_apply_handler_graphs(
                source,
                prepared.graph_sites,
                graph_family_count,
                runtime_polymorphism_rate=lowered.policy[
                    "runtime_polymorphism_rate"
                ],
                semantic_state_threading=bool(
                    lowered.policy.get("semantic_state_threading", False)
                ),
                argument_virtualization=bool(
                    lowered.policy.get("argument_virtualization", False)
                ),
                upvalue_virtualization=bool(
                    lowered.policy.get("upvalue_virtualization", False)
                ),
                table_virtualization=bool(
                    lowered.policy.get("table_virtualization", False)
                ),
                branch_virtualization=bool(
                    lowered.policy.get("branch_virtualization", False)
                ),
                representation_routes=root["representation_routes"],
                preserve_native_numbers=target.user_number_model == "binary64",
                private_state_native=target.lua_version == "5.1",
                native_graph_control=getattr(target, "native_graph_control", False),
            ),
            phase="vm_output:handler_graphs",
            implementation="_apply_handler_graphs",
            backend="pre_output_pipeline",
            graph_sites=len(prepared.graph_sites),
            graph_families=graph_family_count,
        )
