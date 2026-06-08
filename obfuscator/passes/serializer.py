from __future__ import annotations
import struct
from .parser import Proto, Upvalue, ConstTag


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------
class Writer:
    def __init__(self):
        self._buf = bytearray()

    def data(self) -> bytes:
        return bytes(self._buf)

    def u8(self, v: int):
        self._buf.append(v & 0xFF)

    def u32(self, v: int):
        self._buf += struct.pack('<I', v & 0xFFFFFFFF)

    def i64(self, v: int):
        self._buf += struct.pack('<q', v)

    def f64(self, v: float):
        self._buf += struct.pack('<d', v)

    def string(self, s: str | None):
        if s is None:
            self.u32(0)
            return
        encoded = s.encode('utf-8')
        self.u32(len(encoded))
        self._buf += encoded


# ---------------------------------------------------------------------------
# Reader
# ---------------------------------------------------------------------------
class BinReader:
    def __init__(self, data: bytes):
        self._data = data
        self._pos  = 0

    def u8(self) -> int:
        v = self._data[self._pos]
        self._pos += 1
        return v

    def u32(self) -> int:
        v = struct.unpack_from('<I', self._data, self._pos)[0]
        self._pos += 4
        return v

    def i64(self) -> int:
        v = struct.unpack_from('<q', self._data, self._pos)[0]
        self._pos += 8
        return v

    def f64(self) -> float:
        v = struct.unpack_from('<d', self._data, self._pos)[0]
        self._pos += 8
        return v

    def string(self) -> str | None:
        length = self.u32()
        if length == 0:
            return None
        raw = self._data[self._pos : self._pos + length]
        self._pos += length
        return raw.decode('utf-8', errors='replace')


# ---------------------------------------------------------------------------
CTAG_NIL   = 0
CTAG_BOOL  = 1
CTAG_INT   = 2
CTAG_FLOAT = 3
CTAG_STR   = 4


# ---------------------------------------------------------------------------
def serialize(proto: Proto) -> bytes:
    w = Writer()
    _write_proto(w, proto)
    return w.data()


def _write_proto(w: Writer, proto: Proto):
    w.u8(proto.num_params)
    w.u8(proto.is_vararg)
    w.u8(proto.max_stack_size)

    # 명령어
    w.u32(len(proto.code))
    for instr in proto.code:
        w.u32(instr)

    # 상수
    w.u32(len(proto.constants))
    for c in proto.constants:
        if c is None:
            w.u8(CTAG_NIL)
        elif isinstance(c, bool):
            w.u8(CTAG_BOOL)
            w.u8(1 if c else 0)
        elif isinstance(c, int):
            w.u8(CTAG_INT)
            w.i64(c)
        elif isinstance(c, float):
            w.u8(CTAG_FLOAT)
            w.f64(c)
        elif isinstance(c, str):
            w.u8(CTAG_STR)
            w.string(c)
        else:
            raise ValueError(f"unknown constant type: {type(c)}")

    # upvalue
    w.u32(len(proto.upvalues))
    for uv in proto.upvalues:
        w.u8(uv.instack)
        w.u8(uv.idx)

    # 중첩 proto
    w.u32(len(proto.protos))
    for sub in proto.protos:
        _write_proto(w, sub)


# ---------------------------------------------------------------------------
def deserialize(data: bytes) -> Proto:
    r = BinReader(data)
    return _read_proto(r)


def _read_proto(r: BinReader) -> Proto:
    num_params     = r.u8()
    is_vararg      = r.u8()
    max_stack_size = r.u8()

    code_count = r.u32()
    code = [r.u32() for _ in range(code_count)]

    const_count = r.u32()
    constants = []
    for _ in range(const_count):
        tag = r.u8()
        if tag == CTAG_NIL:
            constants.append(None)
        elif tag == CTAG_BOOL:
            constants.append(bool(r.u8()))
        elif tag == CTAG_INT:
            constants.append(r.i64())
        elif tag == CTAG_FLOAT:
            constants.append(r.f64())
        elif tag == CTAG_STR:
            constants.append(r.string())
        else:
            raise ValueError(f"unknown constant tag: {tag}")

    upvalue_count = r.u32()
    upvalues = [Upvalue(instack=r.u8(), idx=r.u8()) for _ in range(upvalue_count)]

    proto_count = r.u32()
    protos = [_read_proto(r) for _ in range(proto_count)]

    return Proto(
        source            = "",
        line_defined      = 0,
        last_line_defined = 0,
        num_params        = num_params,
        is_vararg         = is_vararg,
        max_stack_size    = max_stack_size,
        code              = code,
        constants         = constants,
        upvalues          = upvalues,
        protos            = protos,
        lineinfo          = [],
        locvars           = [],
    )


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    from parser import parse_file, dump_proto

    if len(sys.argv) < 2:
        print("usage: python serializer.py <file.luac>")
        sys.exit(1)

    original = parse_file(sys.argv[1])
    print("=== original ===")
    dump_proto(original)

    blob = serialize(original)
    print(f"\nserialized: {len(blob)} bytes")
    print(f"hex: {blob.hex()}")

    restored = deserialize(blob)
    print("\n=== restored ===")
    dump_proto(restored)

    # 검증
    assert original.code       == restored.code,      "code mismatch"
    assert original.constants  == restored.constants,  "constants mismatch"
    assert len(original.upvalues) == len(restored.upvalues), "upvalue count mismatch"
    assert len(original.protos)   == len(restored.protos),   "proto count mismatch"
    print("\nOK: serialize → deserialize 일치")