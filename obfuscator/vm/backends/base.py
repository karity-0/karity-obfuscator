from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ...parser import Proto
from ..protection import (
    BackendCapabilities, CapabilityResolution, ProtectionPlan,
    ProtectedIR, protect, resolve_capabilities,
)
from ..semantic_ir import SemanticIR, validate_semantic_ir


@dataclass(frozen=True)
class BackendContext:
    options: dict[str, Any]


@dataclass
class LoweredIR:
    backend: str
    kind: str
    semantic_ir: SemanticIR
    protection_plan: ProtectionPlan
    resolution: CapabilityResolution
    source_proto: Proto
    policy: dict[str, Any]
    protected_ir: ProtectedIR
    backend_data: dict[str, Any] = field(default_factory=dict)

    def dump(self) -> str:
        lines = [f"backend-ir v1 backend={self.backend} kind={self.kind}"]
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


class VMBackend:
    name = ""
    lowered_kind = ""
    direct_runtime = False
    mov_microcode = False
    capabilities = BackendCapabilities("", frozenset(), frozenset())

    def lower(
        self,
        ir: SemanticIR,
        protection_plan: ProtectionPlan,
        context: BackendContext,
    ) -> LoweredIR:
        validate_semantic_ir(ir)
        protected_ir = protect(ir, protection_plan)
        resolution = resolve_capabilities(protection_plan, self.capabilities)
        policy = self._policy(context.options)
        return LoweredIR(
            backend=self.name,
            kind=self.lowered_kind,
            semantic_ir=ir,
            protection_plan=protection_plan,
            resolution=resolution,
            source_proto=ir.source_proto,
            policy=policy,
            protected_ir=protected_ir,
        )

    def optimize(self, lowered: LoweredIR, context: BackendContext) -> LoweredIR:
        """Optimization boundary; compatibility adapters currently preserve IR."""
        return lowered

    def emit(
        self,
        lowered: LoweredIR,
        emitted_source: str,
        context: BackendContext,
    ) -> str:
        """Emission boundary around the retained runtime/code generator."""
        if lowered.backend != self.name:
            raise ValueError(
                f"backend={self.name} cannot emit lowered IR for {lowered.backend}"
            )
        return emitted_source

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

    def attach_programs(self, lowered: LoweredIR, programs: list[Any]) -> None:
        if programs:
            raise ValueError(f"backend={self.name} does not accept micro programs")


SHARED_OPTIONS = frozenset((
    "backend", "blob_form", "vm_count", "junk_instructions", "junk_rate",
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
