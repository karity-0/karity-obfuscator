from .vm_pass import VMPass
from .protection import ProtectedIR, ProtectionPlan, ProtectionPlanner, protect
from .semantic_ir import (
    IRBlock, IRFunction, IRInstruction, IRValue, SemanticIR,
    build_semantic_ir, normalize_semantic_ir, validate_semantic_ir,
)

__all__ = (
    "VMPass", "SemanticIR", "IRFunction", "IRBlock", "IRInstruction",
    "IRValue", "ProtectedIR", "ProtectionPlan", "ProtectionPlanner", "protect",
    "build_semantic_ir",
    "normalize_semantic_ir", "validate_semantic_ir",
)
