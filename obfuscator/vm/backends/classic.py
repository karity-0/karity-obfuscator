from .base import CLASSIC_OPTIONS, VMBackend
from ..protection import BackendCapabilities, option_feature


class ClassicBackend(VMBackend):
    name = "classic"
    lowered_kind = "lua53-direct-handler"
    direct_runtime = True
    capabilities = BackendCapabilities(
        name,
        frozenset(filter(None, (option_feature(option) for option in CLASSIC_OPTIONS))),
        CLASSIC_OPTIONS,
    )
