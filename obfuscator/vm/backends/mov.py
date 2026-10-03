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

    def compose_runtime(self, source, lowered, *, target=None):
        from .runtime_templates import classic_executor, direct_executor
        from ..mov.builder import build_runtime
        executor = build_runtime(target.runtime_template('classic_exec.lua') if target else classic_executor(),
                                 lowered.backend_data['kits'],
                                 template=target.runtime_template('mov_exec.lua') if target else None)
        source = direct_executor(source, executor)
        return source.replace('local proto=read_proto(r,acc_state)',
                              'local proto=read_proto(r,acc_state); _mov_read(r,proto)')

    def build_vm_map(self, program, assignments, vm_id, used_vops, alias_requirements):
        from .handler_ir import OPERATIONS
        return {op: [op] for op in range(len(OPERATIONS))}, {}, {}, {}

    def emit_handlers(self, source, lowered, variants):
        # Microcode dispatch and HOST handlers are composed by the MOV builder.
        return source

    def serialize_program(self, lowered, context):
        from ..mov.serializer import serialize
        from ..backend import unsupported_vm_options
        blob = super().serialize_program(lowered, context)
        programs = lowered.backend_data['programs']
        count = lowered.backend_data['layout'].vm_count
        storage_stats = {}
        extension = serialize(programs, lowered.backend_data['kits'], storage_stats,
                              linked=lowered.backend_data['linked'])
        context.profile.append({
            'phase': 'mov_lowering', 'elapsed': 0.0,
            'prototypes': len(programs), 'effective_vms': count,
            'vm_prototypes': [sum(p.vm_id == i for p in programs) for i in range(count)],
            'digit_encoding': 'per_vm_permutation',
            'lowered_sites': sum(p.lowered_sites for p in programs),
            'micro_instructions': sum(len(p.code) for p in programs),
            'extension_bytes': len(extension), **storage_stats,
            'dispatcher': 'mov_microcode',
            'unsupported_options': sorted(unsupported_vm_options(self.name)),
        })
        return blob + extension

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

