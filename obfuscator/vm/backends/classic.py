from .base import CLASSIC_OPTIONS, RuntimeBody, VMBackend
from ..protection import BackendCapabilities, option_feature


class ClassicBackend(VMBackend):
    name = "classic"
    description = 'direct-register and direct-handler runtime on the current VM pipeline'
    lowered_kind = "classic-handler-ir"
    capabilities = BackendCapabilities(
        name,
        frozenset(filter(None, (option_feature(option) for option in CLASSIC_OPTIONS)))
        | frozenset({"handler_aliases"}),
        CLASSIC_OPTIONS,
    )

    def compose_runtime(self, source, lowered, *, target=None):
        from .runtime_templates import classic_executor, direct_executor
        return direct_executor(source, target.runtime_template('classic_exec.lua') if target else classic_executor())

    def validate_lowered(self, lowered):
        from .handler_validation import validate_handler_dispatch
        validate_handler_dispatch(lowered, delayed=False)

    def optimize(self, lowered, context):
        # Validate the shared physical layout first, then apply only Classic's
        # metadata-free control-flow rewrite and validate the result again.
        super().optimize(lowered, context)
        from .classic_optimizer import optimize_layout
        from .handler_layout import validate_layout

        statistics, events = optimize_layout(lowered.backend_data["layout"])
        lowered.backend_data["optimization"] = {
            "backend": "classic",
            **statistics,
        }
        lowered.backend_data["optimization_events"] = events
        validate_layout(
            lowered.backend_data["layout"].functions,
            lowered.backend_data["layout"].vm_maps,
        )
        self.validate_lowered(lowered)
        return lowered

    def emit_handlers(self, source, lowered, variants):
        from .handler_emission import single_handlers
        from ..vm_obfuscation import apply_dispatch_target_hiding, build_exec_variants
        count = lowered.backend_data['layout'].vm_count
        def render(template, index):
            result = single_handlers(template, lowered, variants[index], vm_index=index,
                                     executor_name=f'_ex{index}' if count > 1 else None)
            if lowered.policy.get('dispatcher_target_hiding', False):
                result = apply_dispatch_target_hiding(result, native_state=True)
            return result
        return build_exec_variants(source, count, render) if count > 1 else render(source, 0)

    def emit_runtime_body(self, source, lowered, *, target):
        # Token selection is a Classic representation decision.  Keep it
        # before target finalization so the result takes part in the same
        # output-pass and integrity pipeline as every other backend.
        from .runtime_emitter import _apply_classic_runtime_tokens
        return RuntimeBody(
            source=_apply_classic_runtime_tokens(source),
            phase="vm_output:classic_runtime",
            implementation="_apply_classic_runtime_tokens",
            backend="classic_runtime",
        )
