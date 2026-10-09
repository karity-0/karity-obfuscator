"""A bounded common-IR lowering into the Windows x64 native domain."""
from dataclasses import dataclass, replace
import struct

from ..protection import ProtectedIR, protect
from ..ir.validate import validate_semantic_ir
from ..targets.capabilities import Capability as C, CompatibilityPolicy as P, TargetRequirements
from ..targets.profile import TargetProfile
from .domains import ExecutionDomain


@dataclass(frozen=True)
class NativeBackendContext:
    target: TargetProfile


class UnsupportedNativeRegion(ValueError):
    pass


@dataclass(frozen=True)
class NativeOperand:
    kind: str
    value: int


@dataclass(frozen=True)
class NativeInstruction:
    operation: str
    destination: int
    inputs: tuple[NativeOperand, ...]
    source_id: str


@dataclass(frozen=True)
class NativeFunction:
    id: str
    params: int
    instructions: tuple[NativeInstruction, ...]
    result: int


@dataclass(frozen=True)
class NativeProgram:
    generation: str
    functions: tuple[NativeFunction, ...]
    rejected: tuple[tuple[str, str], ...]
    domain: ExecutionDomain = ExecutionDomain.NATIVE

    def dump(self):
        lines = [f'native-ir v1 domain={self.domain.value} abi=windows-x64 generation={self.generation}']
        for function in self.functions:
            lines.append(f'function {function.id} integer-parameters={function.params} result=r{function.result}')
            for instruction in function.instructions:
                lines.append(f'  {instruction.source_id} {instruction.operation} r{instruction.destination} {instruction.inputs!r}')
        for function_id, reason in self.rejected:
            lines.append(f'fallback {function_id}: {reason}')
        return '\n'.join(lines) + '\n'


_BINARY = {'ADD': b'\x48\x01\xc8', 'SUB': b'\x48\x29\xc8',
           'MUL': b'\x48\x0f\xaf\xc1', 'BIT_AND': b'\x48\x21\xc8',
           'BIT_OR': b'\x48\x09\xc8', 'BIT_XOR': b'\x48\x31\xc8'}
_UNARY = {'NEGATE': b'\x48\xf7\xd8', 'BIT_NOT': b'\x48\xf7\xd0', 'MOVE': b''}


def validate_native_function(function):
    if type(function.params) is not int or not 0 <= function.params <= 4:
        raise ValueError('native function exceeds four integer parameters')
    initialized = set(range(function.params))
    for instruction in function.instructions:
        arity = 2 if instruction.operation in _BINARY else 1 if instruction.operation in _UNARY else None
        if arity is None or len(instruction.inputs) != arity or type(instruction.destination) is not int or not 0 <= instruction.destination < 4:
            raise ValueError('invalid native instruction')
        for operand in instruction.inputs:
            if operand.kind == 'register':
                if type(operand.value) is not int or operand.value not in initialized:
                    raise ValueError('native read before integer definition')
            elif operand.kind != 'constant' or type(operand.value) is not int or not -(1 << 63) <= operand.value < (1 << 63):
                raise ValueError('native operand is not a signed 64-bit integer')
        initialized.add(instruction.destination)
    if type(function.result) is not int or function.result not in initialized:
        raise ValueError('native result is not initialized')


class CENativeBackend:
    """Leaf integer functions only; unsupported regions retain an explicit fallback."""
    name = 'ce_native'
    domain = ExecutionDomain.NATIVE
    requirements = TargetRequirements({C.AUTO_ASSEMBLER, C.NATIVE_ALLOCATION,
                                      C.NATIVE_EXECUTION, C.INTEGER_ARITHMETIC}, P.RUNTIME_SPECIFIC)

    def lower(self, protected: ProtectedIR, context: NativeBackendContext):
        if not isinstance(protected, ProtectedIR):
            raise TypeError('native lowering requires ProtectedIR')
        profile = context.target
        profile.require(self.requirements, 'CE native lowering')
        if profile.runtime_abi != 'windows-x64':
            raise ValueError('CE native lowering requires explicit runtime_abi=windows-x64')
        protect(protected.semantic_ir, protected.plan)
        validate_semantic_ir(protected.semantic_ir)
        functions, rejected = [], []
        for function in protected.semantic_ir.functions():
            try:
                functions.append(self._lower_function(function))
            except UnsupportedNativeRegion as error:
                rejected.append((function.id, str(error)))
        return NativeProgram(protected.semantic_ir.generation, tuple(functions), tuple(rejected))

    def _lower_function(self, function):
        if function.vararg or function.children or function.max_stack_size > 4 or function.params > 4:
            raise UnsupportedNativeRegion('requires a non-vararg leaf with at most four register slots')
        block = function.blocks[0]
        if block.successors:
            raise UnsupportedNativeRegion('control flow is outside the native subset')
        constants = {v.index: v.literal for v in function.values if v.kind == 'constant'}
        instructions = []
        result = None

        def operand(value):
            if value.kind == 'register':
                return NativeOperand('register', value.value)
            literal = constants.get(value.value) if value.kind == 'constant' else None
            if type(literal) is not int:
                raise UnsupportedNativeRegion('non-integer operand requires Lua execution')
            return NativeOperand('constant', literal)

        for index, instruction in enumerate(block.instructions):
            fields = {value.role: value for value in instruction.operands}
            operation = instruction.operation
            if operation == 'RETURN':
                values = fields['values']
                if values.count != 1 or index != len(block.instructions) - 1:
                    raise UnsupportedNativeRegion('requires one final scalar return')
                result = values.value
                continue
            if operation in _BINARY:
                inputs = (operand(fields['left']), operand(fields['right']))
            elif operation in _UNARY:
                inputs = (operand(fields['source']),)
            elif operation == 'LOAD_CONST':
                operation, inputs = 'MOVE', (operand(fields['value']),)
            else:
                raise UnsupportedNativeRegion(f'operation {operation} requires Lua execution')
            instructions.append(NativeInstruction(operation, fields['destination'].value, inputs, instruction.id))
        if result is None:
            raise UnsupportedNativeRegion('missing scalar return')
        native = NativeFunction(function.id, function.params, tuple(instructions), result)
        try:
            validate_native_function(native)
        except ValueError as error:
            raise UnsupportedNativeRegion(str(error)) from error
        return native

    def optimize(self, program, context=None):
        functions = []
        for function in program.functions:
            validate_native_function(function)
            live, kept = {function.result}, []
            for instruction in reversed(function.instructions):
                if instruction.destination not in live:
                    continue
                live.discard(instruction.destination)
                live.update(value.value for value in instruction.inputs if value.kind == 'register')
                kept.append(instruction)
            optimized = replace(function, instructions=tuple(reversed(kept)))
            validate_native_function(optimized)
            functions.append(optimized)
        return replace(program, functions=tuple(functions))

    def emit(self, program, context=None):
        from .native_runtime import emit_ce_module
        return emit_ce_module(program)


def encode_x64(function: NativeFunction) -> bytes:
    """Use only volatile registers and the caller-provided 32-byte home area.

    RSP and nonvolatile registers remain unchanged, so these are leaf functions
    requiring no stack-unwind registration. No native calls or memory inputs.
    """
    validate_native_function(function)
    code = bytearray()
    for index, (rex, modrm) in enumerate(((0x48, 0x4c), (0x48, 0x54), (0x4c, 0x44), (0x4c, 0x4c))):
        if index < function.params:
            code.extend((rex, 0x89, modrm, 0x24, 8 + index * 8))

    def load(operand, register=0):
        if operand.kind == 'constant':
            code.extend((0x48, 0xb8 + register))
            code.extend(struct.pack('<q', operand.value))
        else:
            code.extend((0x48, 0x8b, 0x44 + register * 8, 0x24, 8 + operand.value * 8))

    for instruction in function.instructions:
        load(instruction.inputs[0])
        if instruction.operation in _BINARY:
            load(instruction.inputs[1], 1)
            code.extend(_BINARY[instruction.operation])
        else:
            code.extend(_UNARY[instruction.operation])
        code.extend((0x48, 0x89, 0x44, 0x24, 8 + instruction.destination * 8))
    load(NativeOperand('register', function.result))
    code.append(0xc3)
    return bytes(code)
