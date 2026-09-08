from typing import Any

from .base import SHARED_OPTIONS, LoweredIR, VMBackend
from ..protection import BackendCapabilities, option_feature


class MovBackend(VMBackend):
    name = "mov"
    lowered_kind = "mov-micro-ir"
    direct_runtime = True
    mov_microcode = True
    capabilities = BackendCapabilities(
        name,
        frozenset(filter(None, (option_feature(option) for option in SHARED_OPTIONS)))
        | frozenset(("mov_microcode",)),
        SHARED_OPTIONS,
    )

    def attach_programs(self, lowered: LoweredIR, programs: list[Any]) -> None:
        lowered.backend_data["programs"] = tuple(programs)
