from __future__ import annotations
import random
import struct
from .handler_ir import HandlerFunction, HandlerInstruction


# instruction 워드 필드 시프트(기본 레이아웃). vm.lua의 _SH_A/_SH_B/_SH_C/_SH_V
# 기본값과 일치해야 한다. 파이프라인은 per-run 랜덤 레이아웃을 주입한다.
# 제약: op은 비트 0(7비트) 고정, B=C+9(연속, Bx=B|C), 모든 필드 ≤ 비트47(_ksm 48비트 마스크).
DEFAULT_INSTR_LAYOUT = {"A": 32, "B": 23, "C": 14, "V": 40}


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------
class Writer:
    def __init__(self, layout: dict | None = None):
        self._buf = bytearray()
        self.layout = layout or DEFAULT_INSTR_LAYOUT

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

    def instr(self, raw: HandlerInstruction, enc_op: int, enc_variant: int):
        """
        커스텀 64비트 instruction 레이아웃. op은 [6:0] 고정, A/B/C/variant 위치는
        self.layout(per-run 랜덤)에 따른다. B=C+9(연속) → Bx=B|C. 나머지 비트는 랜덤.
          op       (7비트, [6:0], acc-인코딩된 vop & 0x7F)
          C        (9비트, <<L["C"])
          B        (9비트, <<L["B"] = L["C"]+9)
          A        (8비트, <<L["A"])
          variant  (8비트, <<L["V"], acc-인코딩된 vop >> 7)
        """
        A = raw.a
        B = raw.b
        C = raw.c
        L = self.layout

        val = (
            (enc_op & 0x7F)
            | (C                    << L["C"])
            | (B                    << L["B"])   # B=C+9 이므로 B|C가 연속된 Bx 필드
            | (A                    << L["A"])
            | ((enc_variant & 0xFF) << L["V"])
        )
        # 사용된 필드 비트를 제외한 나머지 전 비트에 랜덤 쓰레기(pad/reserved 대체)
        used = 0x7F | (0x1FF << L["C"]) | (0x1FF << L["B"]) | (0xFF << L["A"]) | (0xFF << L["V"])
        garbage = random.getrandbits(64) & ~used
        self.u64((val | garbage) & 0xFFFFFFFFFFFFFFFF)


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
CTAG_IEXPR = 5

IOP_PUSH_U32   = 1
IOP_GET_SEED   = 2
IOP_GET_VMCOUNT = 3
IOP_GET_LAYOUT = 4
IOP_GET_VMID   = 5
IOP_GET_CODELEN = 6
IOP_XOR        = 7
IOP_ADD        = 8
IOP_MUL        = 9
IOP_GET_SCRIPT_HASH = 10
IOP_GET_LINE_STATE = 11




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


def _write_fake_pool(w: Writer, constant_tags: tuple[int, ...]) -> None:
    """가짜 상수 풀을 blob에 직렬화. 태그 구조는 진짜 풀과 동일."""
    c_nil, c_bool, c_int, c_float, c_str, _c_iexpr = constant_tags
    entries = []
    # 문자열 랜덤 샘플
    n_str = random.randint(8, 20)
    for s in random.sample(_FAKE_STRINGS, min(n_str, len(_FAKE_STRINGS))):
        entries.append((c_str, s))
    # 정수 랜덤 샘플
    n_int = random.randint(3, 8)
    for v in random.sample(_FAKE_NUMBERS_INT, min(n_int, len(_FAKE_NUMBERS_INT))):
        entries.append((c_int, v))
    # 실수 랜덤 샘플
    n_flt = random.randint(1, 4)
    for v in random.sample(_FAKE_NUMBERS_FLOAT, min(n_flt, len(_FAKE_NUMBERS_FLOAT))):
        entries.append((c_float, v))
    # bool/nil 약간
    for _ in range(random.randint(1, 3)):
        entries.append((c_bool, random.choice([True, False])))
    entries.append((c_nil, None))

    random.shuffle(entries)
    w.u32(len(entries))
    for tag, val in entries:
        w.u8(tag)
        if tag == c_nil:
            pass
        elif tag == c_bool:
            w.u8(1 if val else 0)
        elif tag == c_int:
            w.i64(val)
        elif tag == c_float:
            w.f64(val)
        elif tag == c_str:
            w.string(val)


def _emit_instr(w: Writer, raw: HandlerInstruction, vop: int, acc_state: list[int]) -> None:
    acc, idx = acc_state
    enc_op      = (vop & 0x7F)  ^ (acc & 0x7F)
    enc_variant = (vop >> 7)    ^ ((acc >> 7) & 0xFF)
    acc_state[0] = (acc + vop + idx) & 0xFFFF
    acc_state[1] = idx + 1
    w.instr(raw, enc_op, enc_variant)




def _layout_hash(layout: dict | None) -> int:
    layout = layout or DEFAULT_INSTR_LAYOUT
    return (
        (layout["A"] * 0x45D9F3B)
        ^ (layout["B"] * 0x119DE1F3)
        ^ (layout["C"] * 0x3449D)
        ^ (layout["V"] * 0x27D4EB2D)
    ) & 0xFFFFFFFF


def _integrity_mix(seed: int, integrity: dict, code_count: int, vm_id: int) -> int:
    return (
        seed
        ^ ((integrity.get("vm_count", 1) & 0xFFFF) << 11)
        ^ integrity.get("layout_hash", 0)
        ^ ((vm_id & 0xFF) << 23)
        ^ ((code_count & 0xFFFF) * 0x45D9F3B)
    ) & 0xFFFFFFFF


def _integrity_sources(seed: int, integrity: dict, code_count: int, vm_id: int) -> dict[int, int]:
    return {
        IOP_GET_SEED: seed & 0xFFFFFFFF,
        IOP_GET_VMCOUNT: integrity.get("vm_count", 1) & 0xFFFFFFFF,
        IOP_GET_LAYOUT: integrity.get("layout_hash", 0) & 0xFFFFFFFF,
        IOP_GET_VMID: vm_id & 0xFFFFFFFF,
        IOP_GET_CODELEN: code_count & 0xFFFFFFFF,
        IOP_GET_SCRIPT_HASH: integrity.get("script_hash", 0) & 0xFFFFFFFF,
        IOP_GET_LINE_STATE: integrity.get("line_state", 0) & 0xFFFFFFFF,
    }


def _eval_integrity_program(program: list[tuple[int, int | None]], sources: dict[int, int]) -> int:
    stack: list[int] = []
    for op, arg in program:
        if op == IOP_PUSH_U32:
            stack.append(int(arg or 0) & 0xFFFFFFFF)
        elif op in sources:
            stack.append(sources[op])
        else:
            b = stack.pop()
            a = stack.pop()
            if op == IOP_XOR:
                stack.append((a ^ b) & 0xFFFFFFFF)
            elif op == IOP_ADD:
                stack.append((a + b) & 0xFFFFFFFF)
            elif op == IOP_MUL:
                stack.append((a * (b | 1)) & 0xFFFFFFFF)
            else:
                raise ValueError(f"unknown integrity op: {op}")
    return stack[-1] & 0xFFFFFFFF


def _make_integrity_program() -> list[tuple[int, int | None]]:
    sources = [
        IOP_GET_SEED,
        IOP_GET_VMCOUNT,
        IOP_GET_LAYOUT,
        IOP_GET_VMID,
        IOP_GET_CODELEN,
        IOP_GET_SCRIPT_HASH,
        IOP_GET_LINE_STATE,
    ]
    random.shuffle(sources)

    program: list[tuple[int, int | None]] = [(sources[0], None)]
    stack_depth = 1
    for source in sources[1:]:
        if random.random() < 0.45:
            program.append((IOP_PUSH_U32, random.randint(0, 0xFFFFFFFF)))
            program.append((random.choice([IOP_XOR, IOP_ADD, IOP_MUL]), None))
        program.append((source, None))
        program.append((random.choice([IOP_XOR, IOP_ADD, IOP_MUL]), None))

    for _ in range(random.randint(1, 3)):
        program.append((IOP_PUSH_U32, random.randint(0, 0xFFFFFFFF)))
        program.append((random.choice([IOP_XOR, IOP_ADD, IOP_MUL]), None))
    return program


def _make_stream_integrity_program() -> list[tuple[int, int | None]]:
    return [
        (IOP_GET_SCRIPT_HASH, None),
        (IOP_GET_VMCOUNT, None),
        (IOP_XOR, None),
        (IOP_GET_LAYOUT, None),
        (IOP_ADD, None),
        (IOP_GET_SEED, None),
        (IOP_XOR, None),
        (IOP_GET_VMID, None),
        (IOP_ADD, None),
        (IOP_GET_CODELEN, None),
        (IOP_MUL, None),
    ]


def _write_integrity_program(w: Writer, program: list[tuple[int, int | None]]) -> None:
    if len(program) > 255:
        raise ValueError("integrity program too long")
    w.u8(len(program))
    for op, arg in program:
        w.u8(op)
        if op == IOP_PUSH_U32:
            w.u32(int(arg or 0))


def serialize(function, *, layout: dict | None = None,
              constant_tags: dict[str, int] | None = None,
              integrity_options: dict | None = None, vm_count: int = 1) -> bytes:
    from .handler_layout import PhysicalFunction
    if not isinstance(function, PhysicalFunction):
        raise ValueError("handler serialization requires physical layout with concrete protection targets")
    w = Writer(layout)
    constant_tag_values = tuple(
        (constant_tags or {}).get(name, default)
        for name, default in (
            ("nil", CTAG_NIL), ("bool", CTAG_BOOL),
            ("int", CTAG_INT), ("float", CTAG_FLOAT),
            ("str", CTAG_STR), ("iexpr", CTAG_IEXPR),
        )
    )
    if len(set(constant_tag_values)) != len(constant_tag_values):
        raise ValueError("constant tags must be distinct")
    if any(not 0 <= value <= 0xFF for value in constant_tag_values):
        raise ValueError("constant tags must fit in one byte")
    seed = random.randint(0, 0xFFFF)
    w.u16(seed)
    integrity = {
        "enabled": bool((integrity_options or {}).get("enabled", False)),
        "rate": float((integrity_options or {}).get("rate", 0.0)),
        "vm_count": vm_count,
        "layout_hash": _layout_hash(layout),
        "script_hash": int((integrity_options or {}).get("script_hash", 0)),
        "line_state": int((integrity_options or {}).get("line_state", 0)),
    }
    w.u32(integrity["layout_hash"])
    w.u16(integrity["vm_count"])
    _write_fake_pool(w, constant_tag_values)
    # acc 상태: [acc, instr_index] — 재귀 proto 간 전역 공유
    acc_state = [seed, 0]
    _write_proto(w, function, acc_state, seed, integrity, constant_tag_values)
    return w.data()


def _write_proto(w: Writer, function, acc_state: list[int], seed: int,
                 integrity: dict, constant_tags: tuple[int, ...]):
    proto = function.source
    vm_id = function.vm_id
    total = len(function.code)
    iexpr_indices = function.integrity_indices
    stream_enabled = function.stream_integrity
    w.u8(proto.num_params)
    w.u8(proto.is_vararg)
    w.u8(proto.max_stack_size)
    w.u8(vm_id)
    w.u32(total)
    for item in function.code:
        _emit_instr(w, item.instruction, item.vop, acc_state)
    emitted_av = [item.avalanche for item in function.code]
    emitted_sites = [item.graph_sites for item in function.code]
    block_routes = function.routes

    for slots in emitted_av:
        w.u8(len(slots))
        for slot in slots:
            w.u8(slot)

    for descriptors in emitted_sites:
        w.u8(len(descriptors))
        for family, site, selector_seed, state_key, policy in descriptors:
            w.u8(family)
            w.u8(policy)
            w.u16(state_key)
            w.u32(site)
            w.u32(selector_seed)

    w.u16(len(block_routes))
    for route in block_routes:
        w.u8(len(route))
        for target in route:
            w.u32(target)

    # 상수
    c_nil, c_bool, c_int, c_float, c_str, c_iexpr = constant_tags
    w.u32(len(proto.constants))
    for i, c in enumerate(proto.constants):
        if c is None:
            w.u8(c_nil)
        elif isinstance(c, bool):
            w.u8(c_bool)
            w.u8(1 if c else 0)
        elif isinstance(c, int):
            if i in iexpr_indices:
                program = _make_stream_integrity_program() if stream_enabled else _make_integrity_program()
                mix = _eval_integrity_program(
                    program,
                    _integrity_sources(seed, integrity, total, vm_id),
                )
                w.u8(c_iexpr)
                w.i64(c ^ mix)
                _write_integrity_program(w, program)
            else:
                w.u8(c_int)
                w.i64(c)
        elif isinstance(c, float):
            w.u8(c_float)
            w.f64(c)
        elif isinstance(c, (str, bytes)):
            w.u8(c_str)
            w.string(c)
        else:
            raise ValueError(f"unknown constant type: {type(c)}")

    # upvalue
    w.u32(len(proto.upvalues))
    for uv in proto.upvalues:
        w.u8(uv.instack)
        w.u8(uv.idx)

    # 중첩 proto (acc_state 전역 공유, vm_id별 맵은 sub마다 재선택)
    w.u32(len(proto.protos))
    for sub in function.children:
        _write_proto(w, sub, acc_state, seed, integrity, constant_tags)


# ---------------------------------------------------------------------------
# 역직렬화
# ---------------------------------------------------------------------------
def patch_integrity_sources(
    data: bytes,
    new_hash: int,
    new_line_state: int,
    constant_tags: dict[str, int] | None = None,
) -> bytes:
    patched = bytearray(data)
    r = BinReader(data)
    constant_tag_values = tuple(
        (constant_tags or {}).get(name, default)
        for name, default in (
            ("nil", CTAG_NIL), ("bool", CTAG_BOOL),
            ("int", CTAG_INT), ("float", CTAG_FLOAT),
            ("str", CTAG_STR), ("iexpr", CTAG_IEXPR),
        )
    )
    seed = r.u16()
    layout_hash = r.u32()
    vm_count = r.u16()
    _skip_fake_pool(r, constant_tag_values)
    _patch_proto_integrity(
        r, patched, seed, layout_hash, vm_count,
        0, new_hash & 0xFFFFFFFF,
        0, new_line_state & 0xFFFFFFFF,
        constant_tag_values,
    )
    return bytes(patched)


def patch_integrity_script_hash(data: bytes, new_hash: int) -> bytes:
    """Backward-compatible wrapper for callers without source-line state."""
    return patch_integrity_sources(data, new_hash, 0)


def _skip_fake_pool(r: BinReader, constant_tags: tuple[int, ...]) -> None:
    _c_nil, c_bool, c_int, c_float, c_str, c_iexpr = constant_tags
    count = r.u32()
    for _ in range(count):
        tag = r.u8()
        if tag == c_bool:
            r.u8()
        elif tag == c_int:
            r.i64()
        elif tag == c_float:
            r.f64()
        elif tag == c_str:
            r.string()
        elif tag == c_iexpr:
            r.i64()
            _skip_integrity_program(r)


def _read_integrity_program(r: BinReader) -> list[tuple[int, int | None]]:
    program = []
    prog_len = r.u8()
    for _ in range(prog_len):
        op = r.u8()
        arg = r.u32() if op == IOP_PUSH_U32 else None
        program.append((op, arg))
    return program


def _skip_integrity_program(r: BinReader) -> None:
    prog_len = r.u8()
    for _ in range(prog_len):
        op = r.u8()
        if op == IOP_PUSH_U32:
            r.u32()


def _to_signed_i64(value: int) -> int:
    value &= 0xFFFFFFFFFFFFFFFF
    if value >= 0x8000000000000000:
        value -= 0x10000000000000000
    return value


def _patch_i64(buf: bytearray, pos: int, value: int) -> None:
    struct.pack_into("<q", buf, pos, _to_signed_i64(value))


def _patch_proto_integrity(
    r: BinReader,
    buf: bytearray,
    seed: int,
    layout_hash: int,
    vm_count: int,
    old_hash: int,
    new_hash: int,
    old_line_state: int,
    new_line_state: int,
    constant_tags: tuple[int, ...],
) -> None:
    c_nil, c_bool, c_int, c_float, c_str, c_iexpr = constant_tags
    r.u8(); r.u8(); r.u8()
    vm_id = r.u8()
    code_count = r.u32()
    for _ in range(code_count):
        r.u64()
    for _ in range(code_count):
        for _ in range(r.u8()):
            r.u8()
    for _ in range(code_count):
        for _ in range(r.u8()):
            r.u8(); r.u8(); r.u16(); r.u32(); r.u32()
    for _ in range(r.u16()):
        for _ in range(r.u8()):
            r.u32()

    sources_base = {
        "vm_count": vm_count,
        "layout_hash": layout_hash,
    }
    const_count = r.u32()
    for _ in range(const_count):
        tag = r.u8()
        if tag == c_nil:
            continue
        if tag == c_bool:
            r.u8()
        elif tag == c_int:
            r.i64()
        elif tag == c_float:
            r.f64()
        elif tag == c_str:
            r.string()
        elif tag == c_iexpr:
            encoded_pos = r._pos
            encoded = r.i64()
            program = _read_integrity_program(r)
            old_sources = {
                **sources_base,
                "script_hash": old_hash,
                "line_state": old_line_state,
            }
            new_sources = {
                **sources_base,
                "script_hash": new_hash,
                "line_state": new_line_state,
            }
            old_mix = _eval_integrity_program(
                program, _integrity_sources(seed, old_sources, code_count, vm_id)
            )
            new_mix = _eval_integrity_program(
                program, _integrity_sources(seed, new_sources, code_count, vm_id)
            )
            _patch_i64(buf, encoded_pos, encoded ^ old_mix ^ new_mix)
        else:
            raise ValueError(f"unknown constant tag: {tag}")

    upvalue_count = r.u32()
    for _ in range(upvalue_count):
        r.u8(); r.u8()

    proto_count = r.u32()
    for _ in range(proto_count):
        _patch_proto_integrity(
            r, buf, seed, layout_hash, vm_count,
            old_hash, new_hash, old_line_state, new_line_state,
            constant_tags,
        )
