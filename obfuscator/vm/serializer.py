from __future__ import annotations
import random
import struct
from ..parser import Proto, Upvalue, ConstTag


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

    def u16(self, v: int):
        self._buf += struct.pack('<H', v & 0xFFFF)

    def u32(self, v: int):
        self._buf += struct.pack('<I', v & 0xFFFFFFFF)

    def u64(self, v: int):
        self._buf += struct.pack('<Q', v & 0xFFFFFFFFFFFFFFFF)

    def i64(self, v: int):
        self._buf += struct.pack('<q', v)

    def f64(self, v: float):
        self._buf += struct.pack('<d', v)

    def string(self, s: str | bytes | None):
        if s is None:
            self.u32(0)
            return
        encoded = s.encode('utf-8') if isinstance(s, str) else s
        self.u32(len(encoded))
        self._buf += encoded

    def instr(self, raw: int, enc_op: int, enc_variant: int):
        """
        커스텀 64비트 instruction 레이아웃:
          [63:48] reserved  (16비트, 랜덤 쓰레기)
          [47:40] variant   (8비트,  acc-인코딩된 vop >> 7)
          [39:32] A         (8비트)
          [31:23] B         (9비트)
          [22:14] C         (9비트)
          [13:7]  pad       (7비트, 랜덤 쓰레기)
          [6:0]   op        (7비트, acc-인코딩된 vop & 0x7F)
        """
        A        = (raw >> 6)  & 0xFF
        B        = (raw >> 23) & 0x1FF
        C        = (raw >> 14) & 0x1FF
        pad      = random.randint(0, 0x7F)
        reserved = random.randint(0, 0xFFFF)

        val = (
            (enc_op & 0x7F)
            | (pad              << 7)
            | (C                << 14)
            | (B                << 23)
            | (A                << 32)
            | ((enc_variant & 0xFF) << 40)
            | (reserved         << 48)
        )
        self.u64(val)


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

    def u16(self) -> int:
        v = struct.unpack_from('<H', self._data, self._pos)[0]
        self._pos += 2
        return v

    def u32(self) -> int:
        v = struct.unpack_from('<I', self._data, self._pos)[0]
        self._pos += 4
        return v

    def u64(self) -> int:
        v = struct.unpack_from('<Q', self._data, self._pos)[0]
        self._pos += 8
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
# 상수 태그 (커스텀)
# ---------------------------------------------------------------------------
CTAG_NIL   = 0
CTAG_BOOL  = 1
CTAG_INT   = 2
CTAG_FLOAT = 3
CTAG_STR   = 4



# ---------------------------------------------------------------------------
# 가짜 상수 풀
# ---------------------------------------------------------------------------
_FAKE_STRINGS = [
    "print", "tostring", "tonumber", "require", "load", "pcall", "xpcall",
    "io", "os", "math", "string", "table", "package", "debug",
    "open", "read", "write", "close", "format", "find", "match", "gsub",
    "insert", "remove", "concat", "sort", "exit", "time", "clock",
    "loadfile", "dofile", "type", "pairs", "ipairs", "next", "select",
    "rawget", "rawset", "rawlen", "rawequal", "setmetatable", "getmetatable",
]
_FAKE_NUMBERS_INT   = [0, 1, -1, 2, 10, 16, 32, 64, 100, 255, 256, 1000, 0xFF, 0x7F, 0x100]
_FAKE_NUMBERS_FLOAT = [0.0, 1.0, -1.0, 3.14, 2.718, 0.5, 100.0]


def _write_fake_pool(w: Writer) -> None:
    """가짜 상수 풀을 blob에 직렬화. 태그 구조는 진짜 풀과 동일."""
    entries = []
    # 문자열 랜덤 샘플
    n_str = random.randint(8, 20)
    for s in random.sample(_FAKE_STRINGS, min(n_str, len(_FAKE_STRINGS))):
        entries.append((CTAG_STR, s))
    # 정수 랜덤 샘플
    n_int = random.randint(3, 8)
    for v in random.sample(_FAKE_NUMBERS_INT, min(n_int, len(_FAKE_NUMBERS_INT))):
        entries.append((CTAG_INT, v))
    # 실수 랜덤 샘플
    n_flt = random.randint(1, 4)
    for v in random.sample(_FAKE_NUMBERS_FLOAT, min(n_flt, len(_FAKE_NUMBERS_FLOAT))):
        entries.append((CTAG_FLOAT, v))
    # bool/nil 약간
    for _ in range(random.randint(1, 3)):
        entries.append((CTAG_BOOL, random.choice([True, False])))
    entries.append((CTAG_NIL, None))

    random.shuffle(entries)
    w.u32(len(entries))
    for tag, val in entries:
        w.u8(tag)
        if tag == CTAG_NIL:
            pass
        elif tag == CTAG_BOOL:
            w.u8(1 if val else 0)
        elif tag == CTAG_INT:
            w.i64(val)
        elif tag == CTAG_FLOAT:
            w.f64(val)
        elif tag == CTAG_STR:
            w.string(val)


# ---------------------------------------------------------------------------
# Split / Fusion + jump offset 유틸리티
# ---------------------------------------------------------------------------
from .vm_obfuscation import FUSE_OPS

# sBx 필드를 가진 opcodes (Lua 5.3 원본 번호): JMP, FORLOOP, FORPREP, TFORLOOP
_SBXOPS: set[int] = {30, 39, 40, 42}
# 조건부로 다음 명령어를 건너뛰는 opcodes: EQ/LT/LE/TEST/TESTSET
_TESTOPS: set[int] = {31, 32, 33, 34, 35}


def _compute_protected(code: list[int]) -> set[int]:
    """독립적으로 dispatch 진입해야 하는(=fuse의 operand 슬롯이 되면 안 되는)
    명령어 인덱스 집합.

    - JMP/FORLOOP/FORPREP/TFORLOOP의 점프 목적지
    - test 명령(skip)의 착지 위치 i+2
    - LOADBOOL(op==3, C!=0)의 skip 착지 위치 i+2
    """
    n = len(code)
    protected: set[int] = set()
    for i, raw in enumerate(code):
        op = raw & 0x3F
        if op in _SBXOPS:
            sbx = ((raw >> 14) & 0x3FFFF) - 131071
            tgt = i + 1 + sbx
            if 0 <= tgt < n:
                protected.add(tgt)
        elif op in _TESTOPS:
            if i + 2 < n:
                protected.add(i + 2)
        elif op == 3:  # LOADBOOL
            C = (raw >> 14) & 0x1FF
            if C != 0 and i + 2 < n:
                protected.add(i + 2)
    return protected


def collect_fuseable_pairs(proto: Proto) -> set[tuple[int, int]]:
    """proto 트리에서 fuse 가능한 인접 (op1, op2) 쌍 집합을 반환."""
    pairs: set[tuple[int, int]] = set()
    _collect_pairs(proto, pairs)
    return pairs


def _collect_pairs(proto: Proto, pairs: set[tuple[int, int]]) -> None:
    code = proto.code
    protected = _compute_protected(code)
    for i in range(len(code) - 1):
        op1 = code[i]     & 0x3F
        op2 = code[i + 1] & 0x3F
        if op1 in FUSE_OPS and op2 in FUSE_OPS and (i + 1) not in protected:
            pairs.add((op1, op2))
    for sub in proto.protos:
        _collect_pairs(sub, pairs)


# plan unit 형식:
#   ("normal", i)         — 1 슬롯
#   ("split",  i, parts)  — parts 슬롯 (parts in {2,3})
#   ("fuse",   i, i+1)    — 2 슬롯 (fused vop + operand)
def _build_plan(code: list[int],
                split_map: dict[int, dict[str, tuple[int, ...]]] | None,
                fuse_map: dict[tuple[int, int], int] | None,
                protected: set[int]) -> list[tuple]:
    n = len(code)
    plan: list[tuple] = []
    i = 0
    while i < n:
        op = code[i] & 0x3F
        options: list[tuple] = [("normal", i)]

        if split_map and op in split_map:
            options.append(("split", i, 2))
            options.append(("split", i, 3))

        if (fuse_map and i + 1 < n and op in FUSE_OPS
                and (code[i + 1] & 0x3F) in FUSE_OPS
                and (i + 1) not in protected
                and (op, code[i + 1] & 0x3F) in fuse_map):
            options.append(("fuse", i, i + 1))

        choice = random.choice(options) if len(options) > 1 else options[0]
        plan.append(choice)
        i += 2 if choice[0] == "fuse" else 1
    return plan


def _plan_slots(unit: tuple) -> int:
    if unit[0] == "split":
        return unit[2]
    if unit[0] == "fuse":
        return 2
    return 1


def _plan_new_pos(plan: list[tuple], n: int) -> tuple[list[int], int]:
    """new_pos[원본 인덱스] = 새 배열에서의 시작 슬롯. (목록, 총 슬롯수) 반환."""
    new_pos = [0] * n
    slot = 0
    for unit in plan:
        i = unit[1]
        new_pos[i] = slot
        if unit[0] == "fuse":
            new_pos[unit[2]] = slot + 1  # operand 슬롯 (점프 타겟 아님, 안전용)
        slot += _plan_slots(unit)
    return new_pos, slot


def _adjust_jumps(code: list[int], new_pos: list[int], total: int) -> list[int]:
    """JMP/FORLOOP/FORPREP/TFORLOOP의 sBx를 split로 밀린 새 위치에 맞게 수정.

    (fusion은 2→2 슬롯이라 위치를 바꾸지 않지만, split이 섞이면 위치가
    밀리므로 new_pos 기준으로 일괄 재계산한다.)
    """
    result = list(code)
    for i, raw in enumerate(code):
        if (raw & 0x3F) not in _SBXOPS:
            continue
        old_sbx = ((raw >> 14) & 0x3FFFF) - 131071
        target  = i + 1 + old_sbx
        new_tgt = new_pos[target] if 0 <= target < len(code) else total
        new_sbx = new_tgt - new_pos[i] - 1
        new_bx  = (new_sbx + 131071) & 0x3FFFF
        result[i] = (raw & ~(0x3FFFF << 14)) | (new_bx << 14)
    return result


def _emit_instr(w: Writer, raw: int, vop: int, acc_state: list[int]) -> None:
    acc, idx = acc_state
    enc_op      = (vop & 0x7F)  ^ (acc & 0x7F)
    enc_variant = (vop >> 7)    ^ ((acc >> 7) & 0xFF)
    acc_state[0] = (acc + vop + idx) & 0xFFFF
    acc_state[1] = idx + 1
    w.instr(raw, enc_op, enc_variant)


def _rand_alias(vop_map: dict[int, list[int]] | None, op: int) -> int:
    if vop_map:
        aliases = vop_map[op]
        return aliases[random.randint(0, len(aliases) - 1)]
    return op


# ---------------------------------------------------------------------------
# 직렬화
# ---------------------------------------------------------------------------
def serialize(proto: Proto, vop_map: dict[int, list[int]] | None = None,
              split_map: dict[int, dict[str, tuple[int, ...]]] | None = None,
              fuse_map: dict[tuple[int, int], int] | None = None) -> bytes:
    w = Writer()
    seed = random.randint(0, 0xFFFF)
    w.u16(seed)
    _write_fake_pool(w)
    # acc 상태: [acc, instr_index] — 재귀 proto 간 전역 공유
    acc_state = [seed, 0]
    _write_proto(w, proto, vop_map, acc_state, split_map, fuse_map)
    return w.data()


def _write_proto(w: Writer, proto: Proto, vop_map: dict[int, list[int]] | None,
                 acc_state: list[int],
                 split_map: dict[int, dict[str, tuple[int, ...]]] | None = None,
                 fuse_map: dict[tuple[int, int], int] | None = None):
    w.u8(proto.num_params)
    w.u8(proto.is_vararg)
    w.u8(proto.max_stack_size)

    # --- split/fuse 결정 + jump offset 보정 ---
    protected     = _compute_protected(proto.code)
    plan          = _build_plan(proto.code, split_map, fuse_map, protected)
    new_pos, total = _plan_new_pos(plan, len(proto.code))
    code          = _adjust_jumps(proto.code, new_pos, total)

    # 명령어: u64 커스텀 포맷으로 emit (alias 중 랜덤 선택 + 롤링 acc 인코딩)
    w.u32(total)
    for unit in plan:
        i = unit[1]
        raw = code[i]
        orig_op = raw & 0x3F
        if unit[0] == "normal":
            _emit_instr(w, raw, _rand_alias(vop_map, orig_op), acc_state)
        elif unit[0] == "split":
            # 같은 raw 명령어를 각 part vop으로 반복 방출
            vops = split_map[orig_op][str(unit[2])]  # type: ignore[index]
            for vop in vops:
                _emit_instr(w, raw, vop, acc_state)
        else:  # fuse: fused vop 슬롯(instr1) + operand 슬롯(instr2)
            op2 = code[unit[2]] & 0x3F
            fuse_vop = fuse_map[(orig_op, op2)]  # type: ignore[index]
            _emit_instr(w, raw, fuse_vop, acc_state)
            # operand 슬롯: dispatch 안 되지만 acc 동기화 위해 정상 슬롯으로 방출
            _emit_instr(w, code[unit[2]], _rand_alias(vop_map, op2), acc_state)

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
        elif isinstance(c, (str, bytes)):
            w.u8(CTAG_STR)
            w.string(c)
        else:
            raise ValueError(f"unknown constant type: {type(c)}")

    # upvalue
    w.u32(len(proto.upvalues))
    for uv in proto.upvalues:
        w.u8(uv.instack)
        w.u8(uv.idx)

    # 중첩 proto (acc_state 전역 공유)
    w.u32(len(proto.protos))
    for sub in proto.protos:
        _write_proto(w, sub, vop_map, acc_state, split_map)


# ---------------------------------------------------------------------------
# 역직렬화
# ---------------------------------------------------------------------------
def deserialize(data: bytes) -> Proto:
    r = BinReader(data)
    seed = r.u16()
    acc_state = [seed, 0]
    return _read_proto(r, acc_state)


def _read_proto(r: BinReader, acc_state: list[int]) -> Proto:
    num_params     = r.u8()
    is_vararg      = r.u8()
    max_stack_size = r.u8()

    code_count = r.u32()
    code = []
    for _ in range(code_count):
        raw64 = r.u64()
        enc_op      =  raw64        & 0x7F
        enc_variant = (raw64 >> 40) & 0xFF
        acc, idx = acc_state
        actual_op      = enc_op      ^ (acc & 0x7F)
        actual_variant = enc_variant ^ ((acc >> 7) & 0xFF)
        actual_vop = actual_op | (actual_variant << 7)
        acc_state[0] = (acc + actual_vop + idx) & 0xFFFF
        acc_state[1] = idx + 1
        # vop를 다시 raw64에 반영 (op, variant 필드 교체)
        raw64 = (raw64 & ~0xFF000000007F) | actual_op | (actual_variant << 40)
        code.append(raw64)

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
    protos = [_read_proto(r, acc_state) for _ in range(proto_count)]

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
# 테스트
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