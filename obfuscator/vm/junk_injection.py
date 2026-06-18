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

[전략 D] 숫자 보장 instruction 후 combination junk
    직전 instruction이 "결과가 반드시 정수"인 opcode이면 해당 레지스터에
    net-zero combination을 삽입: 여러 연산을 연쇄해 최종 값이 원래 값과
    동일하게 복원되도록 설계됨.
    정수 보장 opcode: BAND, BOR, BXOR, SHL, SHR, BNOT, LEN,
                      LOADK(정수 상수)

    주의: 전략 C(max_stack 위 전용 junk 레지스터)는 폐기됨.
    VARARG(B==0) / multret CALL(C==0)이 런타임에 max_stack 경계를
    넘어 동적으로 레지스터를 채우므로, max_stack 위에 "안전한 전용
    구간"이라는 게 존재하지 않는다. 해당 구간을 junk가 점유하면
    원본 가변인자/다중반환 값과 충돌해 크래시 또는 값 손상이 발생한다.
"""
from __future__ import annotations
import random
from ..parser import Proto

SBX_OFFSET = 0x3FFFF >> 1  # 131071

# 다음 instruction과 의미적으로 결합되는 opcode들 (사이에 junk 삽입 금지)
# EQ/LT/LE/TEST/TESTSET (31~35): "조건 불일치 시 다음 instruction(JMP) skip" 구조
_SKIP_NEXT_OPS = {3, 31, 32, 33, 34, 35}

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

# 결과 레지스터 A가 반드시 정수(integer)인 opcode들
# ADD/SUB/MUL/DIV/MOD/POW/UNM/IDIV 제외: float 결과 가능
# BAND/BOR/BXOR/SHL/SHR/BNOT: Lua 5.3 bitwise → integer 보장
# LEN: integer 보장
_NUMERIC_DEST_OPS = {
    20, 21, 22, 23, 24,            # BAND, BOR, BXOR, SHL, SHR
    26,                            # BNOT
    28,                            # LEN
}

OP_MOVE  = 0
OP_LOADK = 1
OP_ADD   = 13
OP_SUB   = 14
OP_BAND  = 20
OP_BOR   = 21
OP_BXOR  = 22
OP_UNM   = 25
OP_BNOT  = 26

# RK 상수 참조: B/C 필드에 256+kidx 를 넣으면 consts[kidx+1] 을 읽는다.
# (vm.lua는 상수 풀을 regs[256+] 에 미리 풀어두므로 regs[256]==consts[1].
#  kidx=0 이면 operand=256 → 첫 상수.)
_RK_CONST_OFFSET = 256


# ---------------------------------------------------------------------------
# 인코딩 헬퍼
# ---------------------------------------------------------------------------

def _encode(op: int, a: int, b: int, c: int) -> int:
    return (op & 0x3F) | ((a & 0xFF) << 6) | ((c & 0x1FF) << 14) | ((b & 0x1FF) << 23)


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
    # float 제외: bitwise ops(BNOT/BXOR/BAND/BOR)는 Lua 5.3에서 integer only
    return isinstance(c, int) and not isinstance(c, bool)


# ---------------------------------------------------------------------------
# 전략 D: 정수 보장 레지스터 combination junk
# ---------------------------------------------------------------------------

def _gen_numeric_combination(reg: int, constants: list) -> list[int]:
    """
    reg가 정수임이 보장될 때, net-zero combination 연산 시퀀스를 반환.
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

    bnot = _encode(OP_BNOT, r, r, 0)
    unm  = _encode(OP_UNM,  r, r, 0)
    bor  = _encode(OP_BOR,  r, r, r)
    band = _encode(OP_BAND, r, r, r)

    # P0~P9: K 없는 패턴 (항상 안전 — register operand만 사용)
    patterns = [
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
    ]

    # K 기반 패턴: RK operand(256+kidx)는 B/C 필드가 9비트(<=511)라서
    # kidx<=255 여야 한다. 또 VM은 상수 풀의 앞 256개만 regs[256..511]에
    # 미리 풀어두므로 kidx>=256인 상수는 RK로 주소지정 자체가 불가능하다.
    # 상수가 이미 256개 이상이면(=새 K를 256번 슬롯 이상에 넣어야 하면)
    # RK가 operand 필드를 오버플로해 엉뚱한 레지스터를 가리키게 되므로
    # (예: 256+257=513 → 513&0x1FF=1 → regs[1]) K 패턴을 생략한다.
    def _krk(k_val: int) -> int | None:
        for i, c in enumerate(constants):
            if type(c) is type(k_val) and c == k_val:
                return _RK_CONST_OFFSET + i if i <= 255 else None
        if len(constants) > 255:
            return None
        constants.append(k_val)
        return _RK_CONST_OFFSET + (len(constants) - 1)

    K  = random.randint(1, 0x7FFFFFFF)
    K2 = random.randint(1, 0x7FFFFFFF)
    rkK, rkK2 = _krk(K), _krk(K2)

    if rkK is not None:
        bxk = _encode(OP_BXOR, r, r, rkK)
        adk = _encode(OP_ADD,  r, r, rkK)
        sbk = _encode(OP_SUB,  r, r, rkK)
        patterns.append([bxk, bxk])                  # P10
        patterns.append([adk, sbk])                  # P11
        patterns.append([bnot, bxk, bxk, bnot])      # P12
        patterns.append([unm,  adk, sbk, unm])       # P13
        patterns.append([bxk, bxk, bnot, bnot])      # P14
        if rkK2 is not None:
            bxk2 = _encode(OP_BXOR, r, r, rkK2)
            patterns.append([adk, bxk2, bxk2, sbk])  # P15

    return random.choice(patterns)


# ---------------------------------------------------------------------------
# 전략 D: 직전 instruction 기반 정수 보장 레지스터 탐색
# ---------------------------------------------------------------------------

def _numeric_dest_from_prev(prev_ins: int, constants: list) -> int | None:
    """
    prev_ins (직전 instruction)이 정수를 dest A에 쓰는 opcode인지 확인.
    맞으면 A를 반환, 아니면 None.
    """
    op, a, _, _ = _decode(prev_ins)

    if op in _NUMERIC_DEST_OPS:
        return a

    if op == OP_LOADK:
        bx = (prev_ins >> 14) & 0x3FFFF
        if bx < len(constants) and _is_numeric_const(constants[bx]):
            return a

    return None


# ---------------------------------------------------------------------------
# 통합 junk 선택기
# ---------------------------------------------------------------------------

def _pick_junks_for_gap(
    code: list[int],
    idx: int,
    orig_stack: int,
    constants: list,
) -> list[int]:
    """
    gap idx에 삽입할 junk instruction 목록을 반환.
    빈 리스트 = 삽입 안 함.

    전략 우선순위:
      D (직전 정수 combination) > B (dead-write MOVE) > A (self MOVE fallback)
    """
    prev_ins = code[idx - 1] if idx > 0 else None
    next_ins = code[idx]     if idx < len(code) else None

    # 전략 D: 직전 instruction이 정수 dest → combination junk
    if prev_ins is not None and random.random() < 0.55:
        num_reg = _numeric_dest_from_prev(prev_ins, constants)
        if num_reg is not None:
            return _gen_numeric_combination(num_reg, constants)

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
    junk를 삽입한 새 code, max_stack_size, 새 constants 를 반환.
    max_stack은 변경하지 않는다 (전략 D는 기존 레지스터만 사용).
    """
    n = len(code)
    if n == 0:
        return code, max_stack, constants

    # constants는 junk K 추가로 변형되므로 복사본 사용
    constants = list(constants)

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
            junks = _pick_junks_for_gap(code, gap, max_stack, constants)
            if junks:
                insertions[gap] = list(junks)

    if not insertions:
        return code, max_stack, constants

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

    return new_code, max_stack, constants


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