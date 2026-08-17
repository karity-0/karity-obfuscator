from __future__ import annotations
import random
import struct
from ..parser import Proto, Upvalue, ConstTag


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

    def instr(self, raw: int, enc_op: int, enc_variant: int):
        """
        커스텀 64비트 instruction 레이아웃. op은 [6:0] 고정, A/B/C/variant 위치는
        self.layout(per-run 랜덤)에 따른다. B=C+9(연속) → Bx=B|C. 나머지 비트는 랜덤.
          op       (7비트, [6:0], acc-인코딩된 vop & 0x7F)
          C        (9비트, <<L["C"])
          B        (9비트, <<L["B"] = L["C"]+9)
          A        (8비트, <<L["A"])
          variant  (8비트, <<L["V"], acc-인코딩된 vop >> 7)
        """
        A = (raw >> 6)  & 0xFF
        B = (raw >> 23) & 0x1FF
        C = (raw >> 14) & 0x1FF
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


def _abc(raw: int) -> tuple[int, int, int, int]:
    a = (raw >> 6) & 0xFF
    b = (raw >> 23) & 0x1FF
    c = (raw >> 14) & 0x1FF
    return a, b, c, (raw >> 14) & 0x3FFFF


def _reg(value: int, max_stack: int) -> set[int]:
    return {value} if value < max_stack else set()


def _reg_range(lo: int, hi: int, max_stack: int) -> set[int]:
    if hi < lo:
        return set()
    return set(range(max(0, lo), min(max_stack - 1, hi) + 1))


def _instruction_rw(proto: Proto, index: int) -> tuple[set[int], set[int]]:
    """Conservative Lua 5.3 register read/write sets for one instruction."""
    raw = proto.code[index]
    op = raw & 0x3F
    a, b, c, _ = _abc(raw)
    m = proto.max_stack_size
    reads: set[int] = set()
    writes: set[int] = set()

    if op == 0:
        reads |= _reg(b, m); writes |= _reg(a, m)
    elif op in {1, 2, 3, 5, 11}:
        writes |= _reg(a, m)
    elif op == 4:
        writes |= _reg_range(a, a + b, m)
    elif op == 6:
        reads |= _reg(c, m); writes |= _reg(a, m)
    elif op == 7:
        reads |= _reg(b, m) | _reg(c, m); writes |= _reg(a, m)
    elif op == 8:
        reads |= _reg(b, m) | _reg(c, m)
    elif op == 9:
        reads |= _reg(a, m)
    elif op == 10:
        reads |= _reg(a, m) | _reg(b, m) | _reg(c, m)
    elif op == 12:
        reads |= _reg(b, m) | _reg(c, m)
        writes |= _reg(a, m) | _reg(a + 1, m)
    elif 13 <= op <= 24:
        reads |= _reg(b, m) | _reg(c, m); writes |= _reg(a, m)
    elif 25 <= op <= 28:
        reads |= _reg(b, m); writes |= _reg(a, m)
    elif op == 29:
        reads |= _reg_range(b, c, m); writes |= _reg(a, m)
    elif 31 <= op <= 33:
        reads |= _reg(b, m) | _reg(c, m)
    elif op == 34:
        reads |= _reg(a, m)
    elif op == 35:
        reads |= _reg(a, m) | _reg(b, m); writes |= _reg(a, m)
    elif op == 36:
        reads |= _reg(a, m)
        reads |= _reg_range(a + 1, m - 1 if b == 0 else a + b - 1, m)
        writes |= _reg_range(a, m - 1 if c == 0 else a + c - 2, m)
    elif op == 37:
        reads |= _reg_range(a, m - 1 if b == 0 else a + b - 1, m)
    elif op == 38:
        reads |= _reg_range(a, m - 1 if b == 0 else a + b - 2, m)
    elif op == 39:
        reads |= _reg_range(a, a + 3, m)
        writes |= _reg(a, m) | _reg(a + 3, m)
    elif op == 40:
        reads |= _reg(a, m) | _reg(a + 2, m); writes |= _reg(a, m)
    elif op == 41:
        reads |= _reg_range(a, a + 2, m)
        writes |= _reg_range(a + 3, a + 2 + c, m)
    elif op == 42:
        reads |= _reg(a, m) | _reg(a + 1, m); writes |= _reg(a, m)
    elif op == 43:
        reads |= _reg_range(a, m - 1 if b == 0 else a + b, m)
    elif op == 44:
        writes |= _reg(a, m)
        bx = (raw >> 14) & 0x3FFFF
        if bx < len(proto.protos):
            reads |= {uv.idx for uv in proto.protos[bx].upvalues
                      if uv.instack == 1 and uv.idx < m}
    elif op == 45:
        writes |= _reg_range(a, m - 1 if b == 0 else a + b - 2, m)
    return reads, writes


def _successors(code: list[int], index: int) -> set[int]:
    raw = code[index]
    op = raw & 0x3F
    n = len(code)
    nxt = index + 1
    if op in {37, 38}:
        return set()
    if op in _SBXOPS:
        sbx = ((raw >> 14) & 0x3FFFF) - 131071
        target = nxt + sbx
        if op in {30, 40}:
            return {target} if 0 <= target < n else set()
        result = {target} if 0 <= target < n else set()
        if op in {39, 42} and nxt < n:
            result.add(nxt)
        return result
    if op in _TESTOPS:
        return {i for i in (nxt, index + 2) if i < n}
    if op == 3 and ((raw >> 14) & 0x1FF) != 0:
        return {index + 2} if index + 2 < n else set()
    return {nxt} if nxt < n else set()


def _live_out_sets(proto: Proto) -> list[set[int]]:
    """Compute backward liveness to a fixed point over the bytecode CFG."""
    n = len(proto.code)
    rw = [_instruction_rw(proto, i) for i in range(n)]
    succ = [_successors(proto.code, i) for i in range(n)]
    live_in = [set() for _ in range(n)]
    live_out = [set() for _ in range(n)]
    changed = True
    while changed:
        changed = False
        for i in range(n - 1, -1, -1):
            out = set().union(*(live_in[j] for j in succ[i])) if succ[i] else set()
            reads, writes = rw[i]
            incoming = reads | (out - writes)
            if out != live_out[i] or incoming != live_in[i]:
                live_out[i] = out
                live_in[i] = incoming
                changed = True
    return live_out


_AVALANCHE_OPS = (
    set(range(0, 30))
    | {30, 31, 32, 33, 34, 35, 36, 39, 40, 41, 42, 43, 44, 45}
)
_AVALANCHE_RATE = {
    **{op: 0.12 for op in range(0, 13)},
    **{op: 1.0 for op in range(13, 27)},
    **{op: 0.25 for op in range(27, 30)},
    **{op: 0.45 for op in range(31, 36)},
    30: 0.12,
    36: 0.25,
    39: 0.12,
    40: 0.12,
    41: 0.12,
    42: 0.12,
    43: 0.35,
    44: 0.35,
    45: 0.12,
}


def _instruction_avalanche_slots(proto: Proto) -> dict[int, tuple[int, ...]]:
    """Pick owned scratch registers, using dead stack slots only for straight-line code."""
    result: dict[int, tuple[int, ...]] = {}
    live_out = _live_out_sets(proto)
    all_regs = set(range(proto.max_stack_size))
    reserved_regs = set(range(proto.max_stack_size, min(255, proto.max_stack_size + 12)))
    straight_line = not proto.protos and all(
        (raw & 0x3F) < 30 for raw in proto.code
    )
    captured = {
        uv.idx for child in proto.protos for uv in child.upvalues
        if uv.instack == 1 and uv.idx < proto.max_stack_size
    }
    for i, raw in enumerate(proto.code):
        if (raw & 0x3F) not in _AVALANCHE_OPS:
            continue
        op = raw & 0x3F
        if random.random() >= _AVALANCHE_RATE.get(op, 0.25):
            continue
        reads, writes = _instruction_rw(proto, i)
        blocked = live_out[i] | reads | writes | captured
        candidates = list(reserved_regs)
        if straight_line:
            candidates.extend(all_regs - blocked)
        random.shuffle(candidates)
        if candidates:
            result[i] = tuple(candidates[:random.randint(1, min(3, len(candidates)))])
    return result


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


def collect_fuseable_pairs_for_vm(proto: Proto, vm_assign: dict[int, int],
                                  vm_id: int) -> set[tuple[int, int]]:
    """vm_id로 배정된 proto들만의 fuse 가능 쌍."""
    pairs: set[tuple[int, int]] = set()
    for p in iter_protos(proto):
        if vm_assign.get(id(p), 0) == vm_id:
            _collect_pairs_single(p, pairs)
    return pairs


def _collect_pairs_single(proto: Proto, pairs: set[tuple[int, int]]) -> None:
    """단일 proto의 fuse 가능 쌍만 수집(재귀 안 함)."""
    code = proto.code
    protected = _compute_protected(code)
    for i in range(len(code) - 1):
        op1 = code[i]     & 0x3F
        op2 = code[i + 1] & 0x3F
        if op1 in FUSE_OPS and op2 in FUSE_OPS and (i + 1) not in protected:
            pairs.add((op1, op2))


def _collect_pairs(proto: Proto, pairs: set[tuple[int, int]]) -> None:
    _collect_pairs_single(proto, pairs)
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
VMMaps = tuple  # (vop_map, split_map, fuse_map)
_GRAPH_SITE_OPS = {13, 14, 15, 20, 21, 22, 23, 24, 25, 26}


def _new_graph_site(site_registry: set[int]) -> int:
    while True:
        site = random.randint(0x10000, 0x7FFFFFFF)
        if site not in site_registry:
            site_registry.add(site)
            return site


def iter_protos(proto: Proto):
    """proto 트리를 pre-order로 순회(직렬화 순서와 동일)."""
    yield proto
    for sub in proto.protos:
        yield from iter_protos(sub)


def assign_vm_ids(proto: Proto, n: int) -> tuple[dict[int, int], int]:
    """각 proto에 vm_id 배정. (assign, effective_n) 반환.

    n을 proto 수로 clamp하고, 0..n-1이 모두 최소 1회 등장하도록 보장해
    죽은(빈) 인터프리터가 생기지 않게 한다. key=id(proto)."""
    protos = list(iter_protos(proto))
    n = max(1, min(n, len(protos)))
    ids = list(range(n)) + [random.randint(0, n - 1) for _ in range(len(protos) - n)]
    random.shuffle(ids)
    return {id(p): ids[i] for i, p in enumerate(protos)}, n


def serialize(proto: Proto,
              vm_assign: dict[int, int] | None = None,
              vm_maps: list | None = None,
              layout: dict | None = None,
              graph_sites: set[int] | None = None) -> bytes:
    """vm_maps[vm_id] = (vop_map, split_map, fuse_map). vm_assign = {id(proto): vm_id}.
    기본값(둘 다 None)은 단일 VM(vm_id=0, 맵 없음)으로 동작.
    layout: instruction 워드 필드 시프트(None이면 DEFAULT_INSTR_LAYOUT). vm.lua의
    _SH_*와 반드시 동일해야 한다(deserialize는 기본 레이아웃만 지원)."""
    if vm_maps is None:
        vm_maps = [(None, None, None)]
    if vm_assign is None:
        vm_assign = {}
    w = Writer(layout)
    seed = random.randint(0, 0xFFFF)
    w.u16(seed)
    _write_fake_pool(w)
    # acc 상태: [acc, instr_index] — 재귀 proto 간 전역 공유
    acc_state = [seed, 0]
    _write_proto(w, proto, vm_assign, vm_maps, acc_state,
                 graph_sites if graph_sites is not None else set())
    return w.data()


def _write_proto(w: Writer, proto: Proto, vm_assign: dict[int, int],
                 vm_maps: list, acc_state: list[int],
                 graph_sites: set[int]):
    vm_id = vm_assign.get(id(proto), 0)
    vop_map, split_map, fuse_map = vm_maps[vm_id]

    w.u8(proto.num_params)
    w.u8(proto.is_vararg)
    w.u8(proto.max_stack_size)
    w.u8(vm_id)

    # --- split/fuse 결정 + jump offset 보정 ---
    protected     = _compute_protected(proto.code)
    plan          = _build_plan(proto.code, split_map, fuse_map, protected)
    new_pos, total = _plan_new_pos(plan, len(proto.code))
    code          = _adjust_jumps(proto.code, new_pos, total)
    add_slots     = _instruction_avalanche_slots(proto)
    emitted_av: list[tuple[int, ...]] = []
    emitted_sites: list[tuple[int, ...]] = []

    # 명령어: u64 커스텀 포맷으로 emit (alias 중 랜덤 선택 + 롤링 acc 인코딩)
    w.u32(total)
    for unit in plan:
        i = unit[1]
        raw = code[i]
        orig_op = raw & 0x3F
        if unit[0] == "normal":
            _emit_instr(w, raw, _rand_alias(vop_map, orig_op), acc_state)
            emitted_av.append(add_slots.get(i, ()))
            emitted_sites.append(
                (_new_graph_site(graph_sites),) if orig_op in _GRAPH_SITE_OPS else ()
            )
        elif unit[0] == "split":
            # 같은 raw 명령어를 각 part vop으로 반복 방출
            vops = split_map[orig_op][str(unit[2])]  # type: ignore[index]
            for vop in vops:
                _emit_instr(w, raw, vop, acc_state)
                emitted_av.append(add_slots.get(i, ()))
                emitted_sites.append(
                    (_new_graph_site(graph_sites),) if orig_op in _GRAPH_SITE_OPS else ()
                )
        else:  # fuse: fused vop 슬롯(instr1) + operand 슬롯(instr2)
            op2 = code[unit[2]] & 0x3F
            fuse_vop = fuse_map[(orig_op, op2)]  # type: ignore[index]
            _emit_instr(w, raw, fuse_vop, acc_state)
            emitted_av.append(add_slots.get(i, ()))
            sites = []
            if orig_op in _GRAPH_SITE_OPS:
                sites.append(_new_graph_site(graph_sites))
            if op2 in _GRAPH_SITE_OPS:
                sites.append(_new_graph_site(graph_sites))
            emitted_sites.append(tuple(sites))
            # operand 슬롯: dispatch 안 되지만 acc 동기화 위해 정상 슬롯으로 방출
            _emit_instr(w, code[unit[2]], _rand_alias(vop_map, op2), acc_state)
            emitted_av.append(add_slots.get(unit[2], ()))
            emitted_sites.append(())

    for slots in emitted_av:
        w.u8(len(slots))
        for slot in slots:
            w.u8(slot)

    for sites in emitted_sites:
        w.u8(len(sites))
        for site in sites:
            w.u32(site)

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

    # 중첩 proto (acc_state 전역 공유, vm_id별 맵은 sub마다 재선택)
    w.u32(len(proto.protos))
    for sub in proto.protos:
        _write_proto(w, sub, vm_assign, vm_maps, acc_state, graph_sites)


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
    _vm_id         = r.u8()  # 직렬화 포맷 정렬용(Proto에는 보관 안 함)

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

    for _ in range(code_count):
        for _ in range(r.u8()):
            r.u8()

    for _ in range(code_count):
        for _ in range(r.u8()):
            r.u32()

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
