"""
Lua 5.3 bytecode parser
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import IntEnum
import struct


# ---------------------------------------------------------------------------
# Lua 5.3 헤더 상수
# ---------------------------------------------------------------------------
LUA_SIGNATURE   = b'\x1bLua'
LUAC_VERSION    = 0x53
LUAC_FORMAT     = 0
LUAC_DATA       = b'\x19\x93\r\n\x1a\n'
LUAC_INT        = 0x5678           # 헤더 검증용 int
LUAC_NUM        = 370.5            # 헤더 검증용 float


# ---------------------------------------------------------------------------
# 상수 타입 태그
# ---------------------------------------------------------------------------
class ConstTag(IntEnum):
    NIL         = 0x00
    BOOLEAN     = 0x01
    NUMBER_FLT  = 0x03   # LUA_TNUMBER | (0 << 4)  → float
    NUMBER_INT  = 0x13   # LUA_TNUMBER | (1 << 4)  → integer
    SHORT_STR   = 0x04   # LUA_TSTRING | (0 << 4)
    LONG_STR    = 0x14   # LUA_TSTRING | (1 << 4)


# ---------------------------------------------------------------------------
# 데이터 클래스
# ---------------------------------------------------------------------------
@dataclass
class Upvalue:
    instack: int    # 1 = 바로 위 스택, 0 = 상위 upvalue
    idx: int        # 스택 인덱스 or 상위 upvalue 인덱스
    name: str = ""


@dataclass
class LocVar:
    name: str
    startpc: int
    endpc: int


@dataclass
class Proto:
    """Function prototype — luaP_Proto 구조 대응."""
    source: str
    line_defined: int
    last_line_defined: int
    num_params: int
    is_vararg: int
    max_stack_size: int

    code: list[int]                    # 명령어 (32-bit int 목록)
    constants: list                    # None | bool | int | float | str
    upvalues: list[Upvalue]
    protos: list[Proto]                # 중첩 함수

    # debug info (나중에 제거 대상)
    lineinfo: list[int]
    locvars: list[LocVar]


# ---------------------------------------------------------------------------
# 파서
# ---------------------------------------------------------------------------
class Reader:
    def __init__(self, data: bytes):
        self._data = data
        self._pos  = 0

    # -- 기본 ---
    def remaining(self) -> int:
        return len(self._data) - self._pos

    def read_bytes(self, n: int) -> bytes:
        chunk = self._data[self._pos : self._pos + n]
        if len(chunk) != n:
            raise EOFError(f"expected {n} bytes at {self._pos}, got {len(chunk)}")
        self._pos += n
        return chunk

    def read_byte(self) -> int:
        return self.read_bytes(1)[0]

    def read_int(self) -> int:
        """4-byte little-endian int."""
        return struct.unpack_from('<i', self.read_bytes(4))[0]

    def read_size_t(self) -> int:
        """8-byte little-endian unsigned (64-bit 플랫폼 기본)."""
        return struct.unpack_from('<Q', self.read_bytes(8))[0]

    def read_lua_integer(self) -> int:
        """lua_Integer = int64."""
        return struct.unpack_from('<q', self.read_bytes(8))[0]

    def read_lua_number(self) -> float:
        """lua_Number = double."""
        return struct.unpack_from('<d', self.read_bytes(8))[0]

    # -- Lua 가변길이 문자열 ---
    def read_string(self) -> bytes | None:
        size = self.read_byte()
        if size == 0:
            return None
        if size == 0xFF:
            size = self.read_size_t()
        raw = self.read_bytes(size - 1)   # 끝 \0 미포함
        return raw


class Lua53Parser:
    def __init__(self, data: bytes):
        self._r = Reader(data)

    def parse(self) -> Proto:
        self._read_header()
        _upvalue_count = self._r.read_byte()  # top-level upvalue 개수 (보통 1)
        return self._read_proto()

    # -- 헤더 ---
    def _read_header(self):
        sig = self._r.read_bytes(4)
        if sig != LUA_SIGNATURE:
            raise ValueError(f"invalid signature: {sig!r}")

        ver = self._r.read_byte()
        if ver != LUAC_VERSION:
            raise ValueError(f"expected Lua 5.3 (0x53), got {ver:#x}")

        fmt = self._r.read_byte()
        if fmt != LUAC_FORMAT:
            raise ValueError(f"unexpected format: {fmt}")

        data = self._r.read_bytes(6)
        if data != LUAC_DATA:
            raise ValueError(f"LUAC_DATA mismatch: {data!r}")

        # 크기 필드들
        int_size         = self._r.read_byte()   # 4
        size_t_size      = self._r.read_byte()   # 8
        instr_size       = self._r.read_byte()   # 4
        lua_integer_size = self._r.read_byte()   # 8
        lua_number_size  = self._r.read_byte()   # 8

        # 검증용 샘플 값
        chk_int = self._r.read_lua_integer()
        if chk_int != LUAC_INT:
            raise ValueError(f"LUAC_INT check failed: {chk_int}")

        chk_num = self._r.read_lua_number()
        if chk_num != LUAC_NUM:
            raise ValueError(f"LUAC_NUM check failed: {chk_num}")

    # -- Prototype ---
    def _read_proto(self) -> Proto:
        source      = self._r.read_string() or ""
        line_def    = self._r.read_int()
        last_line   = self._r.read_int()
        num_params  = self._r.read_byte()
        is_vararg   = self._r.read_byte()
        max_stack   = self._r.read_byte()

        code        = self._read_code()
        constants   = self._read_constants()
        upvalues    = self._read_upvalues()
        protos      = self._read_protos()
        lineinfo    = self._read_lineinfo()
        locvars     = self._read_locvars()
        upv_names   = self._read_upvalue_names()

        for i, name in enumerate(upv_names):
            if i < len(upvalues):
                upvalues[i].name = name

        return Proto(
            source             = source,
            line_defined       = line_def,
            last_line_defined  = last_line,
            num_params         = num_params,
            is_vararg          = is_vararg,
            max_stack_size     = max_stack,
            code               = code,
            constants          = constants,
            upvalues           = upvalues,
            protos             = protos,
            lineinfo           = lineinfo,
            locvars            = locvars,
        )

    def _read_code(self) -> list[int]:
        n = self._r.read_int()
        return [
            struct.unpack_from('<I', self._r.read_bytes(4))[0]
            for _ in range(n)
        ]

    def _read_constants(self) -> list:
        n = self._r.read_int()
        consts = []
        for _ in range(n):
            tag = self._r.read_byte()
            if tag == ConstTag.NIL:
                consts.append(None)
            elif tag == ConstTag.BOOLEAN:
                consts.append(bool(self._r.read_byte()))
            elif tag == ConstTag.NUMBER_FLT:
                consts.append(self._r.read_lua_number())
            elif tag == ConstTag.NUMBER_INT:
                consts.append(self._r.read_lua_integer())
            elif tag in (ConstTag.SHORT_STR, ConstTag.LONG_STR):
                consts.append(self._r.read_string())
            else:
                raise ValueError(f"unknown constant tag: {tag:#x}")
        return consts

    def _read_upvalues(self) -> list[Upvalue]:
        n = self._r.read_int()
        return [
            Upvalue(instack=self._r.read_byte(), idx=self._r.read_byte())
            for _ in range(n)
        ]

    def _read_protos(self) -> list[Proto]:
        n = self._r.read_int()
        return [self._read_proto() for _ in range(n)]

    def _read_lineinfo(self) -> list[int]:
        n = self._r.read_int()
        return [self._r.read_int() for _ in range(n)]

    def _read_locvars(self) -> list[LocVar]:
        n = self._r.read_int()
        return [
            LocVar(
                name     = self._r.read_string() or "",
                startpc  = self._r.read_int(),
                endpc    = self._r.read_int(),
            )
            for _ in range(n)
        ]

    def _read_upvalue_names(self) -> list[str]:
        n = self._r.read_int()
        return [self._r.read_string() or "" for _ in range(n)]


# ---------------------------------------------------------------------------
# 편의 함수
# ---------------------------------------------------------------------------
def parse_file(path: str) -> Proto:
    with open(path, 'rb') as f:
        return Lua53Parser(f.read()).parse()

def parse_bytes(data: bytes) -> Proto:
    return Lua53Parser(data).parse()


# ---------------------------------------------------------------------------
# 디버그 출력
# ---------------------------------------------------------------------------
def dump_proto(proto: Proto, indent: int = 0):
    pad = "  " * indent
    print(f"{pad}Proto: {proto.source!r}  lines {proto.line_defined}-{proto.last_line_defined}")
    print(f"{pad}  params={proto.num_params}  vararg={proto.is_vararg}  stack={proto.max_stack_size}")
    print(f"{pad}  instructions ({len(proto.code)}):")
    for i, instr in enumerate(proto.code):
        op  = instr & 0x3F
        a   = (instr >> 6) & 0xFF
        b   = (instr >> 23) & 0x1FF
        c   = (instr >> 14) & 0x1FF
        bx  = (instr >> 14) & 0x3FFFF
        sbx = bx - (0x3FFFF >> 1)
        print(f"{pad}    [{i:3d}]  op={op:2d}  A={a}  B={b}  C={c}  Bx={bx}  sBx={sbx}")
    print(f"{pad}  constants ({len(proto.constants)}):")
    for i, c in enumerate(proto.constants):
        print(f"{pad}    [{i}] {type(c).__name__}: {c!r}")
    print(f"{pad}  upvalues ({len(proto.upvalues)}):")
    for i, u in enumerate(proto.upvalues):
        print(f"{pad}    [{i}] instack={u.instack}  idx={u.idx}  name={u.name!r}")
    for i, sub in enumerate(proto.protos):
        print(f"{pad}  sub-proto [{i}]:")
        dump_proto(sub, indent + 2)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: python parser.py <file.luac>")
        sys.exit(1)
    proto = parse_file(sys.argv[1])
    dump_proto(proto)