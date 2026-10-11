"""Public semantic IR API; bytecode decoding lives in frontends."""

# Load processing dependencies only when the corresponding feature is used.
__lazy_modules__ = {
    "obfuscator.vm.frontends.lua53",
}

from .ir import (IRValue, IROperand, IRInstruction, IRBlock, IRFunction, SemanticIR,
                 IRValidationError, validate_semantic_ir, normalize_semantic_ir)
from .frontends.lua53 import build_semantic_ir
