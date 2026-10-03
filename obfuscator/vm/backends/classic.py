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

    def compose_runtime(self, source, lowered):
        from .runtime_templates import classic_executor, direct_executor
        return direct_executor(source, classic_executor())
