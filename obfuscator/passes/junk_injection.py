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
"""
from __future__ import annotations
import random
from .parser import Proto

SBX_OFFSET = 0x3FFFF >> 1  # 131071

# 다음 instruction과 의미적으로 결합되는 opcode들 (사이에 junk 삽입 금지)
# EQ/LT/LE/TEST/TESTSET (31~35): "조건 불일치 시 다음 instruction(JMP) skip" 구조
#   -> 사이에 junk가 끼면 skip 결과가 junk로 떨어져 분기 의미가 깨짐
_SKIP_NEXT_OPS = {31, 32, 33, 34, 35}

# jump 계열 opcode: target = i + 1 + sBx
_JUMP_OPS = {30, 39, 40, 42}  # JMP, FORLOOP, FORPREP, TFORLOOP

OP_MOVE = 0
OP_BAND = 20
OP_BOR  = 21


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


# ---------------------------------------------------------------------------
# junk instruction 생성
# ---------------------------------------------------------------------------

# A에 read도 동반하는 opcode들 (junk가 직전에 A를 건드리면 위험)
# -> 다음 instruction의 A를 junk target으로 쓸 때 이 집합에 속하면 skip
_A_IS_INPUT_OPS = {
    36, 37, 38,            # CALL, TAILCALL, RETURN (A=함수/리턴 시작 슬롯, 입력으로 사용)
    41, 42, 43,            # TFORCALL, TFORLOOP, SETLIST (A=상태/테이블, 입력)
    39, 40,                # FORLOOP, FORPREP (A..A+3 모두 루프 상태, 입력)
    9,                      # SETUPVAL (A=read)
    8, 10,                  # SETTABUP, SETTABLE (A=upval/table, read)
    29,                     # CONCAT (B..C range, A is dest only actually - but keep safe)
}


def _gen_self_junk(reg: int, safe: bool) -> int:
    """레지스터 reg를 자기 자신으로 덮어쓰는 무해한 junk (MOVE/BAND/BOR A,A,A).

    safe=False (reg가 아직 nil일 수 있는 영역)면 MOVE만 사용 — BAND/BOR는
    `nil & nil` 형태로 즉시 에러나기 때문.
    """
    if not safe:
        return _encode(OP_MOVE, reg, reg, 0)

    choice = random.choice((OP_MOVE, OP_BAND, OP_BOR))
    if choice == OP_MOVE:
        return _encode(OP_MOVE, reg, reg, 0)
    return _encode(choice, reg, reg, reg)


def _gen_deadwrite_junk(reg: int) -> int:
    """
    reg에 연산 결과를 쓰지만, 바로 다음 instruction이 reg를 덮어쓸 것이
    보장된 상황에서만 사용하는 junk. ADD/SUB/BAND/BOR/BXOR A,A,A 형태로
    실제 산술 연산을 수행하되 값이 어차피 버려짐.
    """
    op = random.choice((13, 14, 20, 21, 22))  # ADD, SUB, BAND, BOR, BXOR
    return _encode(op, reg, reg, reg)


def _pick_junk_for_gap(code: list[int], idx: int, max_stack: int, num_params: int) -> int | None:
    """
    code[idx-1] (junk 직전 instruction)과 code[idx] (junk 직후 instruction)을
    참고해서, 안전한 junk instruction을 생성한다. 불가능하면 None.

    idx 는 "삽입될 위치" (이 위치에 junk가 들어가면 기존 code[idx]는 한 칸 뒤로 밀림)

    num_params: 함수 진입 시점에 항상 초기화되어 있는 것이 보장되는 레지스터 범위
                (0..num_params-1). BAND/BOR/ADD/SUB 등 "읽기 동반" 연산은
                이 범위 밖에서는 regs[reg]가 nil일 수 있어 사용 불가.
    """
    next_ins = code[idx] if idx < len(code) else None

    # dead-write 패턴: 다음 instruction의 dest A가 num_params 범위(항상 초기화됨) 내일 때만
    if next_ins is not None and random.random() < 0.4:
        nop, na, _, _ = _decode(next_ins)
        if nop not in _A_IS_INPUT_OPS and 0 <= na < num_params:
            return _gen_deadwrite_junk(na)

    # 기본: self-junk (max_stack 범위 내 임의 레지스터, 자기 자신 연산)
    if max_stack <= 0:
        return None
    reg = random.randint(0, max(max_stack - 1, 0))
    safe = reg < num_params
    return _gen_self_junk(reg, safe)


# ---------------------------------------------------------------------------
# 메인 삽입 로직
# ---------------------------------------------------------------------------

def _inject_code(code: list[int], max_stack: int, num_params: int, rate: float) -> list[int]:
    n = len(code)
    if n == 0:
        return code

    # gap[i] : code[i] 앞에 junk를 넣을지 여부 (i == n 이면 맨 끝)
    # LOADKX(op==2) 다음은 항상 EXTRAARG이므로 그 사이엔 삽입 금지
    forbidden_before: set[int] = set()
    i = 0
    while i < n:
        op = code[i] & 0x3F
        if op == 2:  # OP_LOADKX
            forbidden_before.add(i + 1)  # EXTRAARG 앞에 삽입 금지
            i += 2
            continue
        if op in _SKIP_NEXT_OPS:
            forbidden_before.add(i + 1)  # 다음 JMP 앞에 삽입 금지 (skip 의미 보존)
        if op == 41:  # TFORCALL -> 다음은 항상 TFORLOOP, 결과 레지스터 결합
            forbidden_before.add(i + 1)
        i += 1

    insertions: dict[int, int | None] = {}  # gap index -> junk instr (or None)
    for gap in range(0, n + 1):
        if gap in forbidden_before:
            continue
        if random.random() < rate:
            junk = _pick_junk_for_gap(code, gap, max_stack, num_params)
            if junk is not None:
                insertions[gap] = junk

    if not insertions:
        return code

    # old index -> new index 매핑 구성
    old_to_new = [0] * n
    new_code: list[int] = []
    for gap in range(0, n + 1):
        if gap in insertions:
            new_code.append(insertions[gap])
        if gap < n:
            old_to_new[gap] = len(new_code)
            new_code.append(code[gap])

    # 역매핑: new index -> old index (junk가 아닌 것만)
    new_to_old: dict[int, int] = {v: k for k, v in enumerate(old_to_new)}

    for new_i, ins in enumerate(new_code):
        op = ins & 0x3F
        if op not in _JUMP_OPS:
            continue
        if new_i not in new_to_old:
            continue  # junk instruction (jump opcode가 junk로 안 생기므로 사실상 없음)

        old_i = new_to_old[new_i]
        old_sbx = _sbx(ins)
        old_target = old_i + 1 + old_sbx

        # old_target이 코드 끝(n)인 경우도 처리 (old_to_new는 0..n-1만 있음)
        if old_target == n:
            new_target = len(new_code)
        elif 0 <= old_target < n:
            new_target = old_to_new[old_target]
        else:
            # 비정상 타겟: 그대로 둠 (발생하지 않아야 함)
            continue

        new_sbx = new_target - new_i - 1
        new_code[new_i] = _set_sbx(ins, new_sbx)

    return new_code


def inject_junk(proto: Proto, rate: float = 0.15) -> Proto:
    """
    proto.code에 junk instruction을 삽입하고, jump target을 재계산한
    새 Proto를 반환한다 (재귀적으로 모든 sub-proto에도 적용).

    rate: 각 gap(instruction 사이)마다 junk가 삽입될 확률.
    """
    new_code = _inject_code(proto.code, proto.max_stack_size, proto.num_params, rate)
    new_protos = [inject_junk(sub, rate) for sub in proto.protos]

    return Proto(
        source            = proto.source,
        line_defined      = proto.line_defined,
        last_line_defined = proto.last_line_defined,
        num_params        = proto.num_params,
        is_vararg         = proto.is_vararg,
        max_stack_size    = proto.max_stack_size,
        code              = new_code,
        constants         = proto.constants,
        upvalues          = proto.upvalues,
        protos            = new_protos,
        lineinfo          = proto.lineinfo,
        locvars           = proto.locvars,
    )