from typing import Any

from .base import SHARED_OPTIONS, LoweredIR, VMBackend
from ..protection import BackendCapabilities, option_feature


class MovBackend(VMBackend):
    name = "mov"
    description = 'supported multi-VM lookup microcode; encoded integer arithmetic, bitwise and comparisons; Lua host fallback'
    lowered_kind = "mov-micro-ir"
    direct_runtime = True
    mov_microcode = True
    capabilities = BackendCapabilities(
        name,
        frozenset(filter(None, (option_feature(option) for option in SHARED_OPTIONS)))
        | frozenset(("mov_microcode",)),
        SHARED_OPTIONS,
    )

    def compose_runtime(self, source, lowered):
        from .runtime_templates import classic_executor, direct_executor
        from ..mov.builder import build_runtime
        executor = build_runtime(classic_executor(), lowered.backend_data['kits'])
        source = direct_executor(source, executor)
        return source.replace('local proto=read_proto(r,acc_state)',
                              'local proto=read_proto(r,acc_state); _mov_read(r,proto)')

    def build_vm_map(self, program, assignments, vm_id, used_vops, alias_requirements):
        from .handler_ir import OPERATIONS
        return {op: [op] for op in range(len(OPERATIONS))}, {}, {}, {}

    def lower(self, protected_ir, context):
        lowered = super().lower(protected_ir, context)
        from .runtime_layout import iter_functions
        from ..mov.lower import lower
        lowered.backend_data["programs"] = tuple(
            lower([item.instruction for item in function.code], function.vm_id)
            for function in iter_functions(lowered.backend_data["layout"].functions))
        return lowered

    def optimize(self, lowered, context):
        super().optimize(lowered, context)
        from ..mov.optimizer import optimize_program, link_programs
        from ..mov.layout import make_kits
        before = sum(len(program.code) for program in lowered.backend_data["programs"])
        programs = tuple(optimize_program(program) for program in lowered.backend_data["programs"])
        lowered.backend_data["programs"] = programs
        count = lowered.backend_data["layout"].vm_count
        lowered.backend_data["kits"] = make_kits(count)
        linked = link_programs(programs, count)
        lowered.backend_data["linked"] = linked
        lowered.backend_data["optimization"] = {
            "before": before, "after": sum(len(program.code) for program in programs),
            "stored": sum(len(tape) for tape in linked[0]), "shared_recipes": linked[2],
        }
        return lowered

