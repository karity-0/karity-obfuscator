from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .handler_ir import (HandlerFunction, lower_handler_ir, serialization_targets,
                         validate_handler_ir)
from ..protection import (
    BackendCapabilities, CapabilityResolution, ProtectionPlan,
    ProtectedIR, protect, resolve_capabilities,
)
from ..semantic_ir import SemanticIR, validate_semantic_ir
from .domains import ExecutionDomain


@dataclass(frozen=True)
class BackendContext:
    options: dict[str, Any]
    toolchain: Any = None
    output_passes: tuple[str, ...] = ()
    output_prefix: str = ""
    profile: list[dict] = field(default_factory=list, compare=False)
    output_transform: Any = None
    target: Any = None
    constant_provider: Any = None


@dataclass
class LoweredIR:
    backend: str
    kind: str
    semantic_ir: SemanticIR
    protection_plan: ProtectionPlan
    resolution: CapabilityResolution
    program: HandlerFunction
    policy: dict[str, Any]
    protected_ir: ProtectedIR
    backend_data: dict[str, Any] = field(default_factory=dict)

    def dump(self) -> str:
        lines = [f"backend-ir v1 backend={self.backend} kind={self.kind}"]
        lines.append(f"generation={self.semantic_ir.generation}")
        materialization = self.backend_data.get("materialization")
        if materialization is not None:
            lines.extend(materialization.dump().splitlines())
        classic_state = self.backend_data.get("classic_state")
        if classic_state is not None:
            lines.extend(classic_state.dump().splitlines())
        karity_state = self.backend_data.get("karity_state")
        if karity_state is not None:
            lines.extend(karity_state.dump().splitlines())
        for request in self.resolution.active:
            lines.append(f"active {request.feature}")
        for request in self.resolution.disabled:
            lines.append(f"fallback-disable {request.feature}")
        for key in sorted(self.policy):
            lines.append(f"policy {key}={self.policy[key]!r}")
        for function in self.semantic_ir.functions():
            instruction_count = sum(len(block.instructions) for block in function.blocks)
            lines.append(
                f"lowered-function {function.id} blocks={len(function.blocks)} "
                f"instructions={instruction_count}"
            )
        for function_id, lifetimes in sorted(self.backend_data.get("liveness", {}).items()):
            lines.extend(lifetimes.dump(function_id).splitlines())
        def dump_function(function):
            lines.append(f"handler-function {function.id}")
            for index, instruction in enumerate(function.code):
                target = ""
                if instruction.operation in {"JUMP", "FOR_LOOP", "FOR_PREP", "ITER_LOOP"}:
                    target = f" target={index + 1 + instruction.sbx}"
                lines.append(
                    f"  h{index} {instruction.operation} source={instruction.source_id} "
                    f"a={instruction.a} b={instruction.b} c={instruction.c}{target}"
                )
            for child in function.protos:
                dump_function(child)
        dump_function(self.program)
        layout = self.backend_data.get("layout")
        if layout is not None:
            from .runtime_layout import iter_functions
            for function in iter_functions(layout.functions):
                lines.append(f"physical-function {function.source.id} vm={function.vm_id} instructions={len(function.code)}")
                for index, item in enumerate(function.code):
                    instruction = item.instruction
                    lines.append(f"  p{index} {instruction.operation} vop={item.vop} source={instruction.source_id} "
                                 f"a={instruction.a} b={instruction.b} c={instruction.c} "
                                 f"scratch={item.avalanche!r} graphs={item.graph_sites!r}")
                for index, targets in enumerate(function.routes):
                    lines.append(f"  route {index} targets={','.join(map(str, targets))}")
        for key, value in sorted(self.backend_data.get("optimization", {}).items()):
            lines.append(f"optimization {key}={value}")
        for event in self.backend_data.get("optimization_events", ()):
            detail = " ".join(
                f"{key}={event[key]}" for key in sorted(event)
            )
            lines.append(f"optimization-event {detail}")
        for bound in self.backend_data.get("mov_slots", ()):
            lines.extend(bound.dump().splitlines())
        programs = self.backend_data.get("programs", ())
        for program_index, program in enumerate(programs):
            recipes = ",".join(sorted(program.recipe_offsets)) or "-"
            lines.append(
                f"micro-program {program_index} vm={program.vm_id} "
                f"entries={len(program.entries)} instructions={len(program.code)} "
                f"lowered-sites={program.lowered_sites} recipes={recipes}"
            )
            for address, instruction in enumerate(program.code, 1):
                lines.append(
                    f"  m{address} {instruction.op.name} a={instruction.a} "
                    f"b={instruction.b} c={instruction.c} d={instruction.d} "
                    f"mode={instruction.mode}"
                )
        return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class RuntimeBody:
    """Backend-owned transformation of the completed VM function source.

    The shared emitter deliberately knows nothing about whether a backend
    resolves direct tokens, emits graphs, or supplies another representation.
    Backends return the profiling metadata with the transformed body so the
    common output-pass/finalization sequence remains identical for every
    runtime.
    """

    source: str
    phase: str
    implementation: str
    backend: str
    graph_sites: int = 0
    graph_families: int = 0


class VMBackend:
    domain = ExecutionDomain.VM
    name = ""
    description = ""
    lowered_kind = ""
    mov_microcode = False
    capabilities = BackendCapabilities("", frozenset(), frozenset())

    def lower(
        self,
        protected_ir: ProtectedIR,
        context: BackendContext,
    ) -> LoweredIR:
        if not isinstance(protected_ir, ProtectedIR):
            raise TypeError("backend lowering requires ProtectedIR")
        ir, protection_plan = protected_ir.semantic_ir, protected_ir.plan
        validate_semantic_ir(ir)
        protect(ir, protection_plan)
        resolution = resolve_capabilities(protection_plan, self.capabilities)
        policy = self._policy(context.options)
        lowered = LoweredIR(
            backend=self.name,
            kind=self.lowered_kind,
            semantic_ir=ir,
            protection_plan=protection_plan,
            resolution=resolution,
            program=lower_handler_ir(ir),
            policy=policy,
            protected_ir=protected_ir,
        )
        from ..ir.liveness import analyze_liveness
        lowered.backend_data["liveness"]={function.id:analyze_liveness(function) for function in ir.functions()}
        from .runtime_layout import prepare_layout
        lowered.backend_data["layout"] = prepare_layout(self, lowered, context)
        if context.constant_provider is not None:
            from ..targets.materialization import plan_materialization
            lowered.backend_data["materialization"] = plan_materialization(
                lowered.backend_data["layout"].functions, context.constant_provider)
        return lowered

    def build_vm_map(self, program, assignments, vm_id, used_vops, alias_requirements):
        from .runtime_layout import build_handler_map
        return build_handler_map(program, assignments, vm_id, used_vops, alias_requirements,
                                 delayed=self.capabilities.supports("delayed_materialization"))

    def serialization_targets(self, lowered: LoweredIR) -> dict[int, dict[str, Any]]:
        return serialization_targets(lowered.program, lowered.protection_plan)

    def optimize(self, lowered: LoweredIR, context: BackendContext) -> LoweredIR:
        """Validate the typed runtime representation before emission."""
        validate_handler_ir(lowered.program)
        from .handler_layout import validate_layout
        layout = lowered.backend_data["layout"]
        validate_layout(layout.functions, layout.vm_maps)
        self.validate_lowered(lowered)
        return lowered

    def validate_lowered(self, lowered: LoweredIR) -> None:
        """Validate additional invariants owned by the backend representation."""

    def compose_runtime(self, source: str, lowered: LoweredIR, *, target=None) -> str:
        raise NotImplementedError('a VM backend must select its runtime executor')

    def emit_handlers(self, source: str, lowered: LoweredIR, variants) -> str:
        raise NotImplementedError('a VM backend must own its handler emission')

    def runtime_variants(self, lowered: LoweredIR) -> tuple[dict, ...]:
        """Consume the stable per-VM plan through this backend's ABI."""
        from .runtime_variants import resolve_runtime_variants
        return resolve_runtime_variants(lowered)

    def emit_runtime_body(
        self,
        source: str,
        lowered: LoweredIR,
        *,
        target,
    ) -> RuntimeBody:
        """Apply backend-specific runtime representation after handler emission.

        ``source`` is the complete VM closure, immediately before shared
        target finalization and VM output passes.  A backend must not run those
        later stages itself: they include integrity-sensitive target lowering
        and must cover every late-generated helper.
        """
        raise NotImplementedError(
            'a VM backend must own its runtime-body emission'
        )

    def serialize_program(self, lowered: LoweredIR, context: BackendContext) -> bytes:
        """Serialize the backend's physical program, including host constants."""
        import time
        from .handler_codec import serialize
        layout = lowered.backend_data['layout']
        materialization = lowered.backend_data.get('materialization')
        started = time.perf_counter()
        blob = serialize(materialization.functions if materialization else layout.functions,
                         layout=layout.instruction_layout, constant_tags=layout.constant_tags,
                         vm_count=layout.vm_count,
                         integrity_options={'enabled': lowered.policy.get('integrity_constants', False)})
        context.profile.append({'phase': 'serialize_blob',
                                'elapsed': round(time.perf_counter() - started, 6)})
        return blob

    def emit(self, lowered: LoweredIR, context: BackendContext) -> str:
        if lowered.backend != self.name:
            raise ValueError(f"backend={self.name} cannot emit {lowered.backend}")
        from .runtime_emitter import emit_runtime
        return emit_runtime(self, lowered, context)

    def _policy(self, options: dict[str, Any]) -> dict[str, Any]:
        policy = {
            option: options[option]
            for option in sorted(self.capabilities.supported_options)
            if option != "backend" and option in options
        }
        policy.update({
            "graph_execution_rate": 0.0,
            "cross_instruction_rate": 0.0,
            "runtime_polymorphism_rate": 0.0,
            "block_variant_rate": 0.0,
            "semantic_diversity_rate": 0.0,
        })
        return policy



SHARED_OPTIONS = frozenset((
    "backend", "requirements", "blob_form", "vm_count", "junk_instructions", "junk_rate",
    "integrity_constants", "integrity_constant_rate",
))

CLASSIC_OPTIONS = SHARED_OPTIONS | frozenset((
    "dispatcher_type", "dispatcher_target_hiding", "fake_handlers",
    "mutate_handlers",
))

KARITY_ONLY_OPTIONS = frozenset((
    "graph_execution_rate", "cross_instruction_rate", "runtime_polymorphism_rate",
    "runtime_trace", "block_variant_rate", "block_variant_count",
    "block_variant_max_instructions", "helper_variant_count",
    "helper_diversity_rate", "semantic_diversity_rate",
    "semantic_state_threading", "argument_virtualization",
    "upvalue_virtualization", "table_virtualization", "branch_virtualization",
))

KARITY_OPTIONS = CLASSIC_OPTIONS | KARITY_ONLY_OPTIONS
