"""Program-specialized Lua emission, without a serialized instruction runtime."""
from __future__ import annotations
from typing import TYPE_CHECKING
from .base import BackendContext, LoweredIR, VMBackend, SHARED_OPTIONS
from ..protection import BackendCapabilities, ProtectedIR, option_feature, protect, resolve_capabilities
from ..targets.capabilities import TargetRequirements

if TYPE_CHECKING:
    from ..targets.profile import TargetProfile


_OPTIONS = frozenset({'backend', 'requirements', 'junk_instructions', 'junk_rate',
    'environment_policy','integrity_constants','integrity_constant_rate'}) | frozenset(
    name for name in SHARED_OPTIONS if name.startswith('ir_'))


class BareBackend(VMBackend):
    name = 'bare'
    display_name = 'Bare'
    description = 'program-specific Lua blocks with randomized position dispatch; no instruction blob'
    lowered_kind = 'bare-lua-blocks'
    capabilities = BackendCapabilities(name, frozenset(filter(None, map(option_feature, _OPTIONS))), _OPTIONS)

    def target_requirements(self, profile: TargetProfile) -> TargetRequirements:
        from ..targets.capabilities import Capability, CompatibilityPolicy
        return TargetRequirements(profile.adapter().requirements.capabilities |
            {Capability.DEBUG_LIBRARY,Capability.FUNCTION_DUMP},CompatibilityPolicy.RUNTIME_SPECIFIC)

    def lower(self, protected_ir: ProtectedIR, context: BackendContext) -> LoweredIR:
        from ..ir import validate_semantic_ir
        from ..ir.liveness import analyze_liveness
        from .handler_ir import lower_handler_ir
        from ..source_protection import prepare
        from ..protection import ProtectionPlanner
        ir, plan = protected_ir.semantic_ir, protected_ir.plan
        if context.constant_provider is not None:
            raise ValueError('Bare does not support CE image-backed constant materialization')
        validate_semantic_ir(ir)
        protect(ir, plan)
        ir,source_protection=prepare(ir,plan,context)
        plan=ProtectionPlanner(context.options).build(ir)
        protected_ir=protect(ir,plan)
        return LoweredIR(self.name, self.lowered_kind, ir, plan,
                         resolve_capabilities(plan, self.capabilities), lower_handler_ir(ir),
                         self._policy(context.options), protected_ir,
                         {'liveness': {f.id: analyze_liveness(f) for f in ir.functions()},
                          'source_protection':source_protection})

    def optimize(self, lowered: LoweredIR, context: BackendContext) -> LoweredIR:
        from ..ir import validate_semantic_ir
        validate_semantic_ir(lowered.semantic_ir)
        return lowered

    def emit(self, lowered: LoweredIR, context: BackendContext) -> str:
        from .bare_emitter import emit
        if lowered.backend != self.name:
            raise ValueError('Bare cannot emit another backend representation')
        return emit(lowered, context)
