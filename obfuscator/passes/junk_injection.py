"""
Bytecode-level junk instruction injection.

파싱된 Proto.code (raw 32-bit Lua 5.3 instruction 목록)에
무해한 junk instruction을 끼워넣고, JMP 계열 opcode의 점프
타겟(sBx)을 새 인덱스 기준으로 재계산한다.

raw instruction 레이아웃 (parser.dump_proto 기준):
    op  = ins & 0x3F
    A   = (ins >> 6)  & 0xFF
    B   = (ins >> 23) & 0x1FF
    C   = (ins >> 14) & 0x1FF
    Bx  = (ins >> 14) & 0x3FFFF
    sBx = Bx - 131071   (OFFSET = 0x3FFFF >> 1 = 131071)

junk 다양성 전략
────────────────
[전략 A] MOVE self-junk
    MOVE A, A  — 어떤 타입에도 안전, 레지스터 다양성으로 노이즈 생성.

[전략 B] dead-write junk
    다음 instruction이 reg를 덮어쓰는 경우 MOVE reg, reg 선삽입.
    역시 타입 무관 안전.

[전략 C] junk 전용 레지스터 combination
    max_stack을 JUNK_REG_COUNT개 확장해 원본 로직이 절대 건드리지 않는
    전용 구간을 확보한다. 함수 진입부에 LOADK 초기화 시퀀스를 삽입하고,
    이후 gap에서 BAND/BOR/BXOR/BNOT/UNM 조합을 자유롭게 사용.

[전략 D] 숫자 보장 instruction 후 combination junk
    직전 instruction이 "결과가 반드시 숫자"인 opcode이면 해당 레지스터에
    net-zero combination을 삽입: 여러 연산을 연쇄해 최종 값이 원래 값과
    동일하게 복원되도록 설계됨.
    숫자 보장 opcode: ADD, SUB, MUL, DIV, MOD, POW, IDIV,
                      BAND, BOR, BXOR, BNOT, SHL, SHR, UNM, LEN,
                      LOADK(숫자 상수), FORLOOP/FORPREP(A 레지스터)
"""
from __future__ import annotations
import random
from .parser import Proto

SBX_OFFSET = 0x3FFFF >> 1  # 131071

# 다음 instruction과 의미적으로 결합되는 opcode들 (사이에 junk 삽입 금지)
# EQ/LT/LE/TEST/TESTSET (31~35): "조건 불일치 시 다음 instruction(JMP) skip" 구조
_SKIP_NEXT_OPS = {31, 32, 33, 34, 35}

# jump 계열 opcode: target = i + 1 + sBx
_JUMP_OPS = {30, 39, 40, 42}  # JMP, FORLOOP, FORPREP, TFORLOOP

# A를 input으로 읽는 opcode들 (junk가 직전에 A를 건드리면 위험)
_A_IS_INPUT_OPS = {
    36, 37, 38,   # CALL, TAILCALL, RETURN
    41, 42, 43,   # TFORCALL, TFORLOOP, SETLIST
    39, 40,       # FORLOOP, FORPREP
    9,            # SETUPVAL
    8, 10,        # SETTABUP, SETTABLE
    29,           # CONCAT
}

# 결과 레지스터 A가 반드시 숫자인 opcode들
_NUMERIC_DEST_OPS = {
    13, 14, 15, 16, 17, 18, 19,   # ADD, SUB, MUL, MOD, POW, DIV, IDIV
    20, 21, 22, 23, 24,            # BAND, BOR, BXOR, SHL, SHR
    25, 26,                        # UNM, BNOT
    28,                            # LEN
}

# FORLOOP/FORPREP: A 레지스터가 숫자 (루프 인덱스)
_FORLOOP_OPS = {39, 40}

OP_MOVE  = 0
OP_LOADK = 1
OP_ADD   = 13
OP_SUB   = 14
OP_BAND  = 20
OP_BOR   = 21
OP_BXOR  = 22
OP_UNM   = 25
OP_BNOT  = 26

# rk(x) 에서 상수 참조: B/C 필드에 256+kidx 를 넣으면 consts[kidx] 를 읽음
# (vm.lua: if x>=256 then return kval(consts[x-255]) end → kidx=0 이면 x=256)
_RK_CONST_OFFSET = 256

# junk 전용 레지스터 확장 개수
JUNK_REG_COUNT = 3


# ---------------------------------------------------------------------------
# 인코딩 헬퍼
# ---------------------------------------------------------------------------

def _encode(op: int, a: int, b: int, c: int) -> int:
    return (op & 0x3F) | ((a & 0xFF) << 6) | ((c & 0x1FF) << 14) | ((b & 0x1FF) << 23)


def _encode_bx(op: int, a: int, bx: int) -> int:
    return (op & 0x3F) | ((a & 0xFF) << 6) | ((bx & 0x3FFFF) << 14)


def _decode(ins: int) -> tuple[int, int, int, int]:
    op = ins & 0x3F
    a  = (ins >> 6)  & 0xFF
    b  = (ins >> 23) & 0x1FF
    c  = (ins >> 14) & 0x1FF
    return op, a, b, c


def _sbx(ins: int) -> int:
    bx = (ins >> 14) & 0x3FFFF
    return bx - SBX_OFFSET


def _set_sbx(ins: int, new_sbx: int) -> int:
    op = ins & 0x3F
    a  = (ins >> 6) & 0xFF
    bx = new_sbx + SBX_OFFSET
    return (op & 0x3F) | ((a & 0xFF) << 6) | ((bx & 0x3FFFF) << 14)


def _is_numeric_const(c) -> bool:
    return isinstance(c, (int, float)) and not isinstance(c, bool)


# ---------------------------------------------------------------------------
# 전략 C: junk 전용 레지스터 초기화 시퀀스
# ---------------------------------------------------------------------------

def _gen_junk_reg_init(junk_base: int, constants: list) -> list[int]:
    """
    junk 전용 레지스터 junk_base..junk_base+JUNK_REG_COUNT-1 에
    숫자 상수를 LOADK로 초기화하는 instruction 시퀀스.

    constants 풀에서 숫자 상수 인덱스를 찾아 사용.
    숫자 상수가 없으면 MOVE self로 fallback (값 = nil이지만 combination에서
    BNOT/UNM 만 쓰면 에러, BXOR/BOR/BAND nil은 에러 → 이 경우 전략 C 회피를
    _pick_junks_for_gap 에서 처리).
    """
    numeric_kidxs = [i for i, c in enumerate(constants) if _is_numeric_const(c)]
    instrs = []
    for slot in range(junk_base, junk_base + JUNK_REG_COUNT):
        if numeric_kidxs:
            kidx = random.choice(numeric_kidxs)
            instrs.append(_encode_bx(OP_LOADK, slot, kidx))
        else:
            # 숫자 상수 없음: MOVE self (nil → nil, 전략 C는 이 함수에서 비활성화됨)
            instrs.append(_encode(OP_MOVE, slot, slot, 0))
    return instrs


# ---------------------------------------------------------------------------
# 전략 C/D: 숫자 보장 레지스터 combination junk
# ---------------------------------------------------------------------------

def _add_junk_const(constants: list, value: int | float) -> int:
    """
    junk용 상수를 constants 리스트에 추가하고 0-based 인덱스를 반환.
    같은 값이 이미 있으면 재사용.
    """
    for i, c in enumerate(constants):
        if type(c) is type(value) and c == value:
            return i
    constants.append(value)
    return len(constants) - 1


def _rk(kidx: int) -> int:
    """상수 인덱스(0-based) → B/C 필드 인코딩 값."""
    return _RK_CONST_OFFSET + kidx


def _gen_numeric_combination(reg: int, constants: list) -> list[int]:
    """
    reg가 숫자임이 보장될 때, net-zero combination 연산 시퀀스를 반환.
    각 패턴은 최종 값이 입력 값과 동일하게 복원된다.

    K 기반 패턴: 랜덤 정수 K를 constants에 추가해 B/C 필드 상수 참조로 인코딩.

    패턴 목록:
      ── K 없는 패턴 (self-op 기반) ──
      P0:  BNOT×2                              (~~r = r)
      P1:  UNM×2                               (--r = r)
      P2:  BOR self → BAND self                (r|r=r, r&r=r)
      P3:  BOR self × 3                        (r|r=r, 3회)
      P4:  BNOT×2 → BOR → BAND                (4단)
      P5:  UNM×2 → BOR → BAND                 (4단)
      P6:  BNOT×4                              (~~~~r = r)
      P7:  UNM×4                               (----r = r)
      P8:  BOR → BNOT×2 → BAND                (4단)
      P9:  BAND → BNOT×2 → BOR                (4단)
      ── K 기반 패턴 ──
      P10: BXOR r,r,K → BXOR r,r,K            (r^K^K = r)
      P11: ADD r,r,K  → SUB r,r,K             (r+K-K = r)
      P12: BNOT → BXOR r,r,K → BXOR r,r,K → BNOT   (4단 조합)
      P13: UNM  → ADD r,r,K  → SUB r,r,K  → UNM     (4단 조합)
      P14: BXOR r,r,K1 → BXOR r,r,K1 → BNOT×2       (4단 조합)
      P15: ADD r,r,K  → BXOR r,r,K2 → BXOR r,r,K2 → SUB r,r,K  (4단 조합)
    (SHL/SHR 패턴 제외: Lua >> 는 logical shift라 음수 정수에서 net-zero 불성립)
    """
    r = reg

    def bxor_k(k_val: int):
        ki = _rk(_add_junk_const(constants, k_val))
        return _encode(OP_BXOR, r, r, ki)

    def add_k(k_val: int):
        ki = _rk(_add_junk_const(constants, k_val))
        return _encode(OP_ADD, r, r, ki)

    def sub_k(k_val: int):
        ki = _rk(_add_junk_const(constants, k_val))
        return _encode(OP_SUB, r, r, ki)

    bnot = _encode(OP_BNOT, r, r, 0)
    unm  = _encode(OP_UNM,  r, r, 0)
    bor  = _encode(OP_BOR,  r, r, r)
    band = _encode(OP_BAND, r, r, r)

    # 난수 K 생성
    K  = random.randint(1, 0x7FFFFFFF)
    K2 = random.randint(1, 0x7FFFFFFF)

    patterns = [
        # P0~P9: K 없는 패턴
        [bnot, bnot],
        [unm,  unm],
        [bor,  band],
        [bor,  bor,  bor],
        [bnot, bnot, bor,  band],
        [unm,  unm,  bor,  band],
        [bnot, bnot, bnot, bnot],
        [unm,  unm,  unm,  unm],
        [bor,  bnot, bnot, band],
        [band, bnot, bnot, bor],
        # P10: BXOR r,K x2
        [bxor_k(K), bxor_k(K)],
        # P11: ADD K → SUB K
        [add_k(K),  sub_k(K)],
        # P12: BNOT → BXOR K×2 → BNOT
        [bnot, bxor_k(K), bxor_k(K), bnot],
        # P13: UNM → ADD K → SUB K → UNM
        [unm,  add_k(K),  sub_k(K),  unm],
        # P14: BXOR K1×2 → BNOT×2
        [bxor_k(K), bxor_k(K), bnot, bnot],
        # P15: ADD K → BXOR K2×2 → SUB K
        [add_k(K), bxor_k(K2), bxor_k(K2), sub_k(K)],
    ]
    return random.choice(patterns)


# ---------------------------------------------------------------------------
# 전략 D: 직전 instruction 기반 숫자 보장 레지스터 탐색
# ---------------------------------------------------------------------------

def _numeric_dest_from_prev(prev_ins: int, constants: list) -> int | None:
    """
    prev_ins (직전 instruction)이 숫자를 dest A에 쓰는 opcode인지 확인.
    맞으면 A를 반환, 아니면 None.
    """
    op, a, _, _ = _decode(prev_ins)

    if op in _NUMERIC_DEST_OPS:
        return a

    if op == OP_LOADK:
        bx = (prev_ins >> 14) & 0x3FFFF
        if bx < len(constants) and _is_numeric_const(constants[bx]):
            return a

    if op in _FORLOOP_OPS:
        return a

    return None


# ---------------------------------------------------------------------------
# 통합 junk 선택기
# ---------------------------------------------------------------------------

def _pick_junks_for_gap(
    code: list[int],
    idx: int,
    orig_stack: int,
    junk_base: int,
    has_numeric_junk_regs: bool,
    constants: list,
) -> list[int]:
    """
    gap idx에 삽입할 junk instruction 목록을 반환.
    빈 리스트 = 삽입 안 함.

    전략 우선순위 (확률 기반 가중치):
      D (직전 숫자 combination) > C (전용 레지스터 combination) >
      B (dead-write MOVE) > A (self MOVE fallback)
    """
    prev_ins = code[idx - 1] if idx > 0 else None
    next_ins = code[idx]     if idx < len(code) else None

    # 전략 D: 직전 instruction이 숫자 dest → combination junk
    if prev_ins is not None and random.random() < 0.55:
        num_reg = _numeric_dest_from_prev(prev_ins, constants)
        if num_reg is not None:
            return _gen_numeric_combination(num_reg, constants)

    # 전략 C: junk 전용 레지스터 combination
    if has_numeric_junk_regs and random.random() < 0.45:
        jreg = random.randint(junk_base, junk_base + JUNK_REG_COUNT - 1)
        return _gen_numeric_combination(jreg, constants)

    # 전략 B: dead-write MOVE (다음 instruction이 reg를 덮어쓸 때)
    if next_ins is not None and random.random() < 0.4:
        nop, na, _, _ = _decode(next_ins)
        if nop not in _A_IS_INPUT_OPS and 0 <= na < orig_stack:
            return [_encode(OP_MOVE, na, na, 0)]

    # 전략 A: fallback MOVE self
    if orig_stack > 0:
        reg = random.randint(0, orig_stack - 1)
        return [_encode(OP_MOVE, reg, reg, 0)]

    return []


# ---------------------------------------------------------------------------
# 메인 삽입 로직
# ---------------------------------------------------------------------------

def _inject_code(
    code: list[int],
    max_stack: int,
    num_params: int,
    constants: list,
    rate: float,
) -> tuple[list[int], int, list]:
    """
    junk를 삽입한 새 code, 새 max_stack_size, 새 constants 를 반환.
    junk 전용 레지스터 JUNK_REG_COUNT개를 max_stack에 추가한다.
    """
    n = len(code)
    if n == 0:
        return code, max_stack, constants

    # constants는 junk K 추가로 변형되므로 복사본 사용
    constants = list(constants)

    junk_base = max_stack
    new_max_stack = max_stack + JUNK_REG_COUNT
    has_numeric_junk_regs = any(_is_numeric_const(c) for c in constants)

    # 삽입 금지 gap 계산
    forbidden_before: set[int] = set()
    i = 0
    while i < n:
        op = code[i] & 0x3F
        if op == 2:  # OP_LOADKX → 다음은 EXTRAARG
            forbidden_before.add(i + 1)
            i += 2
            continue
        if op in _SKIP_NEXT_OPS:
            forbidden_before.add(i + 1)
        if op == 41:  # TFORCALL → 다음은 TFORLOOP
            forbidden_before.add(i + 1)
        i += 1

    # gap별 junk 목록 결정
    insertions: dict[int, list[int]] = {}
    for gap in range(0, n + 1):
        if gap in forbidden_before:
            continue
        if random.random() < rate:
            junks = _pick_junks_for_gap(
                code, gap, max_stack, junk_base, has_numeric_junk_regs, constants
            )
            if junks:
                insertions[gap] = list(junks)

    # junk 전용 레지스터 초기화 시퀀스를 맨 앞(gap 0)에 prepend
    init_seq = _gen_junk_reg_init(junk_base, constants)
    insertions[0] = init_seq + insertions.get(0, [])

    if not any(insertions.values()):
        return code, new_max_stack

    # old index -> new index 매핑 구성
    old_to_new = [0] * n
    new_code: list[int] = []
    for gap in range(0, n + 1):
        if gap in insertions:
            new_code.extend(insertions[gap])
        if gap < n:
            old_to_new[gap] = len(new_code)
            new_code.append(code[gap])

    # 역매핑: new index -> old index
    new_to_old: dict[int, int] = {v: k for k, v in enumerate(old_to_new)}

    # jump target 재계산
    for new_i, ins in enumerate(new_code):
        op = ins & 0x3F
        if op not in _JUMP_OPS:
            continue
        if new_i not in new_to_old:
            continue

        old_i = new_to_old[new_i]
        old_sbx = _sbx(ins)
        old_target = old_i + 1 + old_sbx

        if old_target == n:
            new_target = len(new_code)
        elif 0 <= old_target < n:
            new_target = old_to_new[old_target]
        else:
            continue

        new_sbx = new_target - new_i - 1
        new_code[new_i] = _set_sbx(ins, new_sbx)

    return new_code, new_max_stack, constants


def inject_junk(proto: Proto, rate: float = 0.15) -> Proto:
    """
    proto.code에 junk instruction을 삽입하고, jump target을 재계산한
    새 Proto를 반환한다 (재귀적으로 모든 sub-proto에도 적용).

    rate: 각 gap(instruction 사이)마다 junk가 삽입될 확률.
    """
    new_code, new_max_stack, new_constants = _inject_code(
        proto.code, proto.max_stack_size, proto.num_params, proto.constants, rate
    )
    new_protos = [inject_junk(sub, rate) for sub in proto.protos]

    return Proto(
        source            = proto.source,
        line_defined      = proto.line_defined,
        last_line_defined = proto.last_line_defined,
        num_params        = proto.num_params,
        is_vararg         = proto.is_vararg,
        max_stack_size    = new_max_stack,
        code              = new_code,
        constants         = new_constants,
        upvalues          = proto.upvalues,
        protos            = new_protos,
        lineinfo          = proto.lineinfo,
        locvars           = proto.locvars,
    )