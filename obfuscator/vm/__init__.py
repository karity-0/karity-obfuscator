# Python 3.15 defers these exports until first use; older versions import normally.
__lazy_modules__ = {
    'obfuscator.vm.vm_pass',
    'obfuscator.vm.protection',
    'obfuscator.vm.semantic_ir',
}

from .vm_pass import VMPass
from .protection import ProtectedIR, ProtectionPlan, ProtectionPlanner, protect
from .semantic_ir import (
    IRBlock, IRFunction, IRInstruction, IROperand, IRValue, SemanticIR,
    build_semantic_ir, normalize_semantic_ir, validate_semantic_ir,
)

__all__ = (
    "VMPass", "SemanticIR", "IRFunction", "IRBlock", "IRInstruction",
    "IRValue", "IROperand", "ProtectedIR", "ProtectionPlan", "ProtectionPlanner", "protect",
    "build_semantic_ir",
    "normalize_semantic_ir", "validate_semantic_ir",
)
