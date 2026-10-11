# Python 3.15 defers these exports until first use; older versions import normally.
__lazy_modules__ = {
    'obfuscator.vm.ir.model',
    'obfuscator.vm.ir.validate',
    'obfuscator.vm.ir.normalize',
}

from .model import IRValue, IROperand, IRInstruction, IRBlock, IRFunction, SemanticIR
from .validate import IRValidationError, validate_semantic_ir
from .normalize import normalize_semantic_ir
