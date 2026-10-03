from .base import CLASSIC_OPTIONS, VMBackend
from ..protection import BackendCapabilities, option_feature


class ClassicBackend(VMBackend):
    name = "classic"
    description = 'direct-register and direct-handler runtime on the current VM pipeline'
    lowered_kind = "classic-handler-ir"
    direct_runtime = True
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

    def emit_handlers(self, source, lowered, variants):
        from .handler_emission import single_handlers
        from ..vm_obfuscation import apply_dispatch_target_hiding, build_exec_variants
        count = lowered.backend_data['layout'].vm_count
        def render(template, index):
            result = single_handlers(template, lowered, variants[index], vm_index=index,
                                     executor_name=f'_ex{index}' if count > 1 else None)
            if lowered.policy.get('dispatcher_target_hiding', False):
                result = apply_dispatch_target_hiding(result)
            return result
        return build_exec_variants(source, count, render) if count > 1 else render(source, 0)
