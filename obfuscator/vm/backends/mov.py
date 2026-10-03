from typing import Any

from .base import SHARED_OPTIONS, LoweredIR, RuntimeBody, VMBackend
from ..protection import BackendCapabilities, option_feature


class MovBackend(VMBackend):
    name = "mov"
    description = 'supported multi-VM lookup microcode; encoded integer arithmetic, bitwise and comparisons; Lua host fallback'
    lowered_kind = "mov-micro-ir"
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
        executor_template = target.runtime_template('classic_exec.lua') if target else classic_executor()
        # MOV reuses Classic's host-handler template, then injects its own
        # microcode expressions.  Those expressions still use the target
        # lowering markers, so only Classic itself may retain this native
        # executor boundary.
        executor_template = executor_template.replace('--<<TARGET_CLASSIC_EXEC_NATIVE>>', '')
        executor_template = executor_template.replace('--<<ENDTARGET_CLASSIC_EXEC_NATIVE>>', '')
        executor = build_runtime(executor_template, lowered.backend_data['kits'],
                                 template=target.runtime_template('mov_exec.lua') if target else None,
                                 target=target)
        source = direct_executor(source, executor, target=target)
        source = source.replace('local proto=read_proto(r,acc_state)',
                                'local proto=read_proto(r,acc_state); _mov_read(r,proto)')
        return source.replace('local proto=ctx.read_proto(r,acc_state)',
                              'local proto=ctx.read_proto(r,acc_state); _mov_read(r,proto)')

    def build_vm_map(self, program, assignments, vm_id, used_vops, alias_requirements):
        from .handler_ir import OPERATIONS
        return {op: [op] for op in range(len(OPERATIONS))}, {}, {}, {}

    def emit_handlers(self, source, lowered, variants):
        # Microcode dispatch and HOST handlers are composed by the MOV builder.
        return source

    def validate_lowered(self, lowered):
        from .runtime_layout import iter_functions
        from ..mov.adapter import bind_slots
        from ..mov.validate import validate_host_bindings, validate_linked
        programs = lowered.backend_data.get("programs")
        if programs is None:
            raise ValueError("MOV lowered microprograms are missing")
        functions = tuple(iter_functions(lowered.backend_data["layout"].functions))
        if len(programs) != len(functions):
            raise ValueError("MOV microprogram count differs from physical functions")
        slots = lowered.backend_data.get("mov_slots")
        if slots != bind_slots(lowered.protected_ir, lowered.backend_data["layout"]):
            raise ValueError("MOV semantic/control slots differ from protected IR or layout")
        for program, function, bound in zip(programs, functions, slots):
            if program.vm_id != function.vm_id:
                raise ValueError("MOV microprogram VM differs from physical function")
            if len(bound.slots) != len(function.code):
                raise ValueError("MOV HOST slot count differs from physical function")
            validate_host_bindings(
                program, bound.slots,
            )
        kits = lowered.backend_data.get("kits")
        linked = lowered.backend_data.get("linked")
        if kits is not None or linked is not None:
            if kits is None or linked is None:
                raise ValueError("MOV optimized codebook or linked tape is missing")
            validate_linked(programs, kits, linked)

    def emit_runtime_body(self, source, lowered, *, target):
        # MOV owns its microcode/host runtime above.  The remaining VM tokens
        # are direct-runtime tokens, but their resolution is still a MOV
        # backend decision rather than a shared-emitter backend branch.
        from .runtime_emitter import _apply_classic_runtime_tokens
        return RuntimeBody(
            source=_apply_classic_runtime_tokens(source),
            phase="vm_output:mov_runtime",
            implementation="_apply_classic_runtime_tokens",
            backend="mov_runtime",
        )

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
        from ..mov.adapter import bind_slots
        from ..mov.lower import lower
        lowered.backend_data["mov_slots"] = bind_slots(
            protected_ir, lowered.backend_data["layout"],
        )
        lowered.backend_data["programs"] = tuple(
            lower(bound.slots, bound.vm_id)
            for bound in lowered.backend_data["mov_slots"])
        self.validate_lowered(lowered)
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
        self.validate_lowered(lowered)
        return lowered

    def emit(self, lowered, context):
        self.validate_lowered(lowered)
        return super().emit(lowered, context)

