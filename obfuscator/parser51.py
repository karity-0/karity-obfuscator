"""Strict parser for native Lua 5.1 binary chunks.

Lua 5.1 records closure bindings in the instruction stream immediately after
OP_CLOSURE.  The parser materializes those bindings as the shared ``Upvalue``
objects used by the VM serializers while retaining the original words (the
runtime skips them after constructing a closure).
"""
from __future__ import annotations

from builtins import bytes as ByteString

import math
import struct

from .data_types import LuaConstant, LuaNumber
from .parser import LocVar, Proto, Upvalue


LUA_SIGNATURE = b"\x1bLua"
LUAC_VERSION = 0x51
LUAC_FORMAT = 0


class Lua51Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.endian = "<"
        self.int_size = 0
        self.size_t_size = 0
        self.number_size = 0
        self.integral_numbers = False

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def bytes(self, size: int) -> bytes:
        if size < 0 or size > self.remaining():
            raise EOFError(
                f"Lua 5.1 chunk truncated at {self.pos}: wanted {size} bytes, "
                f"have {self.remaining()}"
            )
        result = self.data[self.pos:self.pos + size]
        self.pos += size
        return result

    def byte(self) -> int:
        return self.bytes(1)[0]

    def integer(self, size: int, *, signed: bool = True) -> int:
        if size not in (4, 8):
            raise ValueError(f"unsupported Lua 5.1 integer width: {size}")
        code = {4: "i" if signed else "I", 8: "q" if signed else "Q"}[size]
        return struct.unpack(self.endian + code, self.bytes(size))[0]

    def count(self) -> int:
        value = self.integer(self.int_size)
        if value < 0:
            raise ValueError(f"negative Lua 5.1 vector size: {value}")
        return value

    def size_t(self) -> int:
        return self.integer(self.size_t_size, signed=False)

    def instruction(self) -> int:
        return self.integer(4, signed=False)

    def number(self) -> LuaNumber:
        raw = self.bytes(self.number_size)
        if self.integral_numbers:
            code = {4: "i", 8: "q"}.get(self.number_size)
        else:
            code = {4: "f", 8: "d"}.get(self.number_size)
        if code is None:
            kind = "integral" if self.integral_numbers else "floating-point"
            raise ValueError(f"unsupported Lua 5.1 {kind} number width: {self.number_size}")
        value = struct.unpack(self.endian + code, raw)[0]
        if isinstance(value, float) and math.isnan(value):
            # NaN constants are legal values, but Python's serializer/runtime
            # path must preserve them rather than trying to use them as keys.
            return float("nan")
        return value

    def string(self) -> ByteString | None:
        size = self.size_t()
        if size == 0:
            return None
        raw = self.bytes(size)
        if raw[-1:] != b"\0":
            raise ValueError("Lua 5.1 string is missing its terminating NUL")
        return raw[:-1]


class Lua51Parser:
    """Parse a standard, non-vendor Lua 5.1 binary chunk."""

    def __init__(self, data: bytes):
        self.reader = Lua51Reader(data)

    def parse(self) -> Proto:
        self._header()
        proto = self._proto(None)
        if self.reader.remaining():
            raise ValueError(
                f"unexpected {self.reader.remaining()} trailing bytes in Lua 5.1 chunk"
            )
        return proto

    def _header(self) -> None:
        r = self.reader
        if r.bytes(4) != LUA_SIGNATURE:
            raise ValueError("invalid Lua bytecode signature")
        version = r.byte()
        if version != LUAC_VERSION:
            raise ValueError(f"expected Lua 5.1 bytecode (0x51), got {version:#x}")
        fmt = r.byte()
        if fmt != LUAC_FORMAT:
            raise ValueError(f"unsupported Lua 5.1 chunk format: {fmt}")
        endian = r.byte()
        if endian not in (0, 1):
            raise ValueError(f"invalid Lua 5.1 endian flag: {endian}")
        r.endian = "<" if endian else ">"
        r.int_size = r.byte()
        r.size_t_size = r.byte()
        instruction_size = r.byte()
        r.number_size = r.byte()
        integral = r.byte()
        if r.int_size not in (4, 8):
            raise ValueError(f"unsupported Lua 5.1 int width: {r.int_size}")
        if r.size_t_size not in (4, 8):
            raise ValueError(f"unsupported Lua 5.1 size_t width: {r.size_t_size}")
        if instruction_size != 4:
            raise ValueError(
                f"Lua 5.1 instruction width must be 4, got {instruction_size}"
            )
        if r.number_size not in (4, 8):
            raise ValueError(f"unsupported Lua 5.1 number width: {r.number_size}")
        if integral not in (0, 1):
            raise ValueError(f"invalid Lua 5.1 integral-number flag: {integral}")
        if integral:
            raise ValueError(
                "integral lua_Number Lua 5.1 chunks are not supported by the "
                "native-number VM runtime"
            )
        r.integral_numbers = bool(integral)

    @staticmethod
    def _text(value: bytes | None) -> str:
        return (value or b"").decode("utf-8", errors="surrogateescape")

    def _proto(self, parent_source: str | None) -> Proto:
        r = self.reader
        raw_source = r.string()
        source = self._text(raw_source) if raw_source is not None else (parent_source or "")
        line_defined = r.integer(r.int_size)
        last_line_defined = r.integer(r.int_size)
        nups = r.byte()
        num_params = r.byte()
        is_vararg = r.byte()
        max_stack_size = r.byte()

        code = [r.instruction() for _ in range(r.count())]
        constants: list[LuaConstant] = []
        for _ in range(r.count()):
            tag = r.byte()
            if tag == 0:
                constants.append(None)
            elif tag == 1:
                constants.append(bool(r.byte()))
            elif tag == 3:
                constants.append(r.number())
            elif tag == 4:
                constants.append(r.string() or b"")
            else:
                raise ValueError(f"unknown Lua 5.1 constant tag: {tag:#x}")

        protos = [self._proto(source) for _ in range(r.count())]
        lineinfo = [r.integer(r.int_size) for _ in range(r.count())]
        locvars = [
            LocVar(
                self._text(r.string()),
                r.integer(r.int_size),
                r.integer(r.int_size),
            )
            for _ in range(r.count())
        ]
        upvalue_names = [self._text(r.string()) for _ in range(r.count())]
        upvalues = [
            Upvalue(0, index, upvalue_names[index] if index < len(upvalue_names) else "")
            for index in range(nups)
        ]
        proto = Proto(
            source=source,
            line_defined=line_defined,
            last_line_defined=last_line_defined,
            num_params=num_params,
            is_vararg=is_vararg,
            max_stack_size=max_stack_size,
            code=code,
            constants=constants,
            upvalues=upvalues,
            protos=protos,
            lineinfo=lineinfo,
            locvars=locvars,
        )
        # Useful to serializers even when a prototype is never referenced by a
        # closure in malformed/dead bytecode.
        setattr(proto, "lua51_nups", nups)
        self._materialize_closure_bindings(proto)
        return proto

    @staticmethod
    def _materialize_closure_bindings(proto: Proto) -> None:
        pc = 0
        while pc < len(proto.code):
            word = proto.code[pc]
            op = word & 0x3F
            if op == 34 and ((word >> 14) & 0x1FF) == 0:  # SETLIST extension is data
                if pc + 1 >= len(proto.code):
                    raise ValueError("truncated Lua 5.1 SETLIST extension")
                pc += 2
                continue
            if op != 36:  # OP_CLOSURE
                pc += 1
                continue
            bx = (word >> 14) & 0x3FFFF
            if bx >= len(proto.protos):
                raise ValueError(f"Lua 5.1 CLOSURE references missing proto {bx}")
            child = proto.protos[bx]
            nups = getattr(child, "lua51_nups", len(child.upvalues))
            bindings: list[Upvalue] = []
            for offset in range(nups):
                bind_pc = pc + 1 + offset
                if bind_pc >= len(proto.code):
                    raise ValueError("truncated Lua 5.1 CLOSURE upvalue bindings")
                bind = proto.code[bind_pc]
                bind_op = bind & 0x3F
                b = (bind >> 23) & 0x1FF
                if bind_op == 0:       # OP_MOVE: capture parent register B
                    bindings.append(Upvalue(1, b, child.upvalues[offset].name))
                elif bind_op == 4:     # OP_GETUPVAL: capture parent upvalue B
                    bindings.append(Upvalue(0, b, child.upvalues[offset].name))
                else:
                    raise ValueError(
                        "Lua 5.1 CLOSURE binding must be MOVE or GETUPVAL, "
                        f"got opcode {bind_op}"
                    )
            previous = getattr(child, "lua51_bindings", None)
            signature = [(uv.instack, uv.idx) for uv in bindings]
            if previous is not None and previous != signature:
                raise ValueError("inconsistent bindings for reused Lua 5.1 prototype")
            setattr(child, "lua51_bindings", signature)
            child.upvalues = bindings
            pc += nups + 1


def parse_bytes(data: bytes) -> Proto:
    return Lua51Parser(data).parse()
