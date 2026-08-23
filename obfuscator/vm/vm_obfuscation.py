"""
VM 디스패처 핸들러 prune + 가짜 핸들러 삽입.

- 실제 바이트코드에서 사용되지 않는 opcode의 핸들러를 vm.lua에서 제거
- 비어있는 opcode 번호 슬롯에 동작 없는 더미 핸들러를 무작위로 채워넣음
"""
from __future__ import annotations
import random
import re

from ..parser import Proto
from .vm_mutation import mutate_handlers, _lua_depth_delta

_LUA_OP_COUNT = 58  # Lua 5.3 opcode 0~46 plus karity integrity pseudo ops

# ---------------------------------------------------------------------------
# Split opcode catalog
# ---------------------------------------------------------------------------
_BINARY_SPLIT_OPS = {13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}
_UNARY_SPLIT_OPS  = {25, 26, 27, 28}
_LOAD_SPLIT_OPS   = {0, 1}
ALL_SPLIT_OPS     = _BINARY_SPLIT_OPS | _UNARY_SPLIT_OPS | _LOAD_SPLIT_OPS

_BINARY_OP_LUA = {
    13: "+", 14: "-", 15: "*", 16: "%", 17: "^",
    18: "/", 19: "//", 20: "&", 21: "|", 22: "~",
    23: "<<", 24: ">>",
}
_UNARY_PREFIX = {
    25: "-",    # UNM
    26: "~",    # BNOT
    27: "not ", # NOT
    28: "#",    # LEN
}

_GRAPH_BINARY_SLOTS = {
    13: "__VM_SLOT_ADD__", 14: "__VM_SLOT_SUB__", 15: "__VM_SLOT_MUL__",
    20: "__VM_SLOT_BAND__", 21: "__VM_SLOT_BOR__", 22: "__VM_SLOT_BXOR__",
    23: "__VM_SLOT_SHL__", 24: "__VM_SLOT_SHR__",
}
_GRAPH_UNARY_SLOTS = {25: "__VM_SLOT_UNM__", 26: "__VM_SLOT_BNOT__"}
_VALUE_UNARY_TAGS = {27, 28}
_VALUE_BINARY_TAGS = {16, 17, 18, 19}
_SEMANTIC_BINARY_TOKENS = {
    16: "__VM_OP_MOD__", 17: "__VM_OP_POW__",
    18: "__VM_OP_DIV__", 19: "__VM_OP_IDIV__",
}
_SEMANTIC_UNARY_TOKENS = {27: "__VM_OP_NOT__", 28: "__VM_OP_LEN__"}

_SPLIT_PAD = "\n        "

# ---------------------------------------------------------------------------
# Fusion (superopcode) catalog
# ---------------------------------------------------------------------------
# fuse 가능한 명령어: 항상 fall-through하는 단순 직선 명령만 (보수적 소규모).
#   MOVE(0), LOADK(1), GETUPVAL(5), 이항 산술(13-24), 단항(25-28)
# 제어흐름(JMP/test/CALL/RETURN/loop)은 instr2를 조건부로 건너뛸 수 있어 제외.
FUSE_OPS = {0, 1, 5} | _BINARY_SPLIT_OPS | _UNARY_SPLIT_OPS


def split_handler_bodies(orig_op: int, parts: int) -> list[str]:
    """Return handler body strings for each part of a split instruction."""
    if orig_op in _GRAPH_BINARY_SLOTS:
        slot = _GRAPH_BINARY_SLOTS[orig_op]
        if parts == 2:
            return [
                f" _split_set(_arith2s(rget(B),rget(C),_av,{slot})){_SPLIT_PAD}",
                f" rset(A,_split_get()){_SPLIT_PAD}",
            ]
        else:
            return [
                f" _split_set(_sem(__VM_DATA_VALUE__,rget(B),nil,nil)){_SPLIT_PAD}",
                f" _split_set(_arith2s(_split_get(),rget(C),_av,{slot})){_SPLIT_PAD}",
                f" rset(A,_split_get()){_SPLIT_PAD}",
            ]
    if orig_op in _GRAPH_UNARY_SLOTS:
        slot = _GRAPH_UNARY_SLOTS[orig_op]
        if parts == 2:
            return [
                f" _split_set(rget(B)){_SPLIT_PAD}",
                f" rset(A,_arith1s(_split_get(),_av,{slot})){_SPLIT_PAD}",
            ]
        return [
            f" _split_set(_sem(__VM_DATA_VALUE__,rget(B),nil,nil)){_SPLIT_PAD}",
            f" _split_set(_arith1s(_split_get(),_av,{slot})){_SPLIT_PAD}",
            f" rset(A,_split_get()){_SPLIT_PAD}",
        ]
    if orig_op in _BINARY_OP_LUA:
        lua_op = _BINARY_OP_LUA[orig_op]
        def binary_expr(left: str, right: str) -> str:
            if orig_op in _SEMANTIC_BINARY_TOKENS:
                token = _SEMANTIC_BINARY_TOKENS[orig_op]
                return f"_carry(_sem({token},{left},{right},nil),_av,{orig_op})"
            expr = f"{left}{lua_op}{right}"
            if orig_op in _VALUE_BINARY_TAGS:
                return f"_carry({expr},_av,{orig_op})"
            return expr
        if parts == 2:
            return [
                f" _split_set({binary_expr('rget(B)', 'rget(C)')}){_SPLIT_PAD}",
                f" rset(A,_split_get()){_SPLIT_PAD}",
            ]
        else:
            return [
                f" _split_set(rget(B)){_SPLIT_PAD}",
                f" _split_set({binary_expr('_split_get()', 'rget(C)')}){_SPLIT_PAD}",
                f" rset(A,_split_get()){_SPLIT_PAD}",
            ]
    elif orig_op in _UNARY_PREFIX:
        pfx = _UNARY_PREFIX[orig_op]
        if orig_op in _SEMANTIC_UNARY_TOKENS:
            token = _SEMANTIC_UNARY_TOKENS[orig_op]
            unary_expr = lambda value: f"_carry(_sem({token},{value},nil,nil),_av,{orig_op})"
        else:
            unary_expr = lambda value: f"{pfx}{value}"
        if parts == 2:
            return [
                f" _split_set(rget(B)){_SPLIT_PAD}",
                f" rset(A,{unary_expr('_split_get()')}){_SPLIT_PAD}",
            ]
        else:
            return [
                f" _split_set(rget(B)){_SPLIT_PAD}",
                f" _split_set({unary_expr('_split_get()')}){_SPLIT_PAD}",
                f" rset(A,_split_get()){_SPLIT_PAD}",
            ]
    elif orig_op == 0:  # MOVE
        if parts == 2:
            return [
                f" _split_set(_sem(__VM_DATA_VALUE__,rget(B),nil,nil)){_SPLIT_PAD}",
                f" rset(A,_carry(_split_get(),_av,0)){_SPLIT_PAD}",
            ]
        else:
            return [
                f" _split_set(_sem(__VM_DATA_VALUE__,rget(B),nil,nil)){_SPLIT_PAD}",
                f" _split_set(_split_get()){_SPLIT_PAD}",
                f" rset(A,_carry(_split_get(),_av,0)){_SPLIT_PAD}",
            ]
    elif orig_op == 1:  # LOADK
        if parts == 2:
            return [
                f" _split_set(_sem(__VM_DATA_VALUE__,kval(consts[Bx+1],proto),nil,nil)){_SPLIT_PAD}",
                f" rset(A,_carry(_split_get(),_av,1)){_SPLIT_PAD}",
            ]
        else:
            return [
                f" _split_set(_sem(__VM_DATA_VALUE__,kval(consts[Bx+1],proto),nil,nil)){_SPLIT_PAD}",
                f" _split_set(_split_get()){_SPLIT_PAD}",
                f" rset(A,_carry(_split_get(),_av,1)){_SPLIT_PAD}",
            ]
    return [f" {_SPLIT_PAD}"] * parts

# state 전이 패턴 — alias마다 다른 조합
_ST_TRANSITIONS = [
    "_st=(_st~A)&0xFF",
    "_st=(_st~B~(pc&0xFF))&0xFF",
    "_st=(_st~C~A)&0xFF",
    "_st=(_st~(A+B)&0xFF)&0xFF",
    "_st=(_st~Bx&0xFF)&0xFF",
    "_st=(_st~(pc~A))&0xFF",
    "_st=(_st~C~(pc&0x7F))&0xFF",
    "_st=(_st~A~B~C)&0xFF",
]

def _pick_transitions(n: int) -> list[str]:
    """n개의 서로 다른 전이 패턴을 랜덤 선택."""
    pool = _ST_TRANSITIONS[:]
    random.shuffle(pool)
    return pool[:n]


def _make_alias_body(body: str, transition: str, pre: bool) -> str:
    """body에 state 전이를 앞(pre=True) 또는 뒤(pre=False)에 삽입.

    return/멀티라인 body는 항상 앞에만 삽입.
    """
    stripped = body.strip()
    pad = "\n        "
    # return 포함 또는 멀티라인이면 무조건 pre
    has_return = 'return' in stripped
    is_multiline = '\n' in stripped
    if pre or has_return or is_multiline:
        return f"\n            {transition}\n            {stripped}{pad}"
    else:
        return f" {stripped}; {transition}{pad}"

_HANDLER_PATTERN = re.compile(r'(if|elseif)\s+op==(\d+)\s*then')
_CHAIN_END_MARKER = 'else error("unknown op "..op) end'


# ---------------------------------------------------------------------------
# 1. 사용 중인 opcode 수집
# ---------------------------------------------------------------------------
def collect_used_ops(proto: Proto, vop_map: dict[int, list[int]]) -> set[int]:
    """
    proto 트리를 재귀 순회하며 디스패처가 실제로 dispatch하는 vop 집합을 반환.

    OP_LOADKX(원본 op==2)의 다음 명령어(EXTRAARG)는 디스패처가 직접 decode하지
    않고 건너뛰므로 used set에 포함시키지 않는다.
    split vop는 apply_split_to_vm에서 mutation 없이 별도 추가되므로 여기선 제외.
    """
    used: set[int] = set()
    _collect(proto, vop_map, used)
    return used


def _collect(proto: Proto, vop_map: dict[int, list[int]], used: set[int]):
    code = proto.code
    i = 0
    n = len(code)
    while i < n:
        instr   = code[i]
        orig_op = instr & 0x3F
        for vop in vop_map[orig_op]:
            used.add(vop)

        if orig_op == 2:  # LOADKX → 다음 명령어는 EXTRAARG, 디스패치 안 됨
            i += 2
            continue

        i += 1

    for sub in proto.protos:
        _collect(sub, vop_map, used)


def collect_used_orig_ops(proto: Proto) -> set[int]:
    """proto 트리에서 실제로 등장하는 원본 opcode(0~46) 집합을 반환.

    split_map을 실제 사용되는 splittable op으로만 한정하기 위해 쓰인다.
    (사용되지 않는 op의 split 핸들러까지 CFF로 만들면 체인이 폭증한다.)
    """
    ops: set[int] = set()
    _collect_orig(proto, ops)
    return ops


def _collect_orig(proto: Proto, ops: set[int]):
    for instr in proto.code:
        ops.add(instr & 0x3F)
    for sub in proto.protos:
        _collect_orig(sub, ops)


# --- 멀티VM: vm_id로 배정된 proto들만 스코프하는 수집기 -------------------
def _iter_protos(proto: Proto):
    yield proto
    for sub in proto.protos:
        yield from _iter_protos(sub)


def collect_used_orig_ops_for_vm(proto: Proto, vm_assign: dict[int, int],
                                 vm_id: int) -> set[int]:
    ops: set[int] = set()
    for p in _iter_protos(proto):
        if vm_assign.get(id(p), 0) == vm_id:
            for instr in p.code:
                ops.add(instr & 0x3F)
    return ops


def collect_used_ops_for_vm(proto: Proto, vm_assign: dict[int, int], vm_id: int,
                            vop_map: dict[int, list[int]]) -> set[int]:
    """vm_id 배정 proto들이 디스패치하는 vop 집합(해당 VM의 vop_map 기준)."""
    used: set[int] = set()
    for p in _iter_protos(proto):
        if vm_assign.get(id(p), 0) != vm_id:
            continue
        code = p.code
        i, n = 0, len(code)
        while i < n:
            orig = code[i] & 0x3F
            for vop in vop_map[orig]:
                used.add(vop)
            if orig == 2:   # LOADKX → 다음 EXTRAARG는 디스패치 안 됨
                i += 2
                continue
            i += 1
    return used


# ---------------------------------------------------------------------------
# 2. vm.lua 핸들러 체인 파싱 / 재조립
# ---------------------------------------------------------------------------
_CHAIN_START_PATTERN = re.compile(r'if\s+op==\d+\s*then')


def _find_chain(vm_code: str) -> tuple[int, int]:
    """exec 함수 내 if/elseif op==N 체인의 (start, end) 인덱스를 반환."""
    anchor = vm_code.find("for i in setmetatable(")
    if anchor == -1:
        anchor = 0
    m = _CHAIN_START_PATTERN.search(vm_code, anchor)
    chain_start = m.start()
    chain_end = vm_code.find(_CHAIN_END_MARKER, chain_start)
    chain_end += len(_CHAIN_END_MARKER)
    return chain_start, chain_end


def _parse_handler_blocks(chain: str) -> dict[int, str]:
    matches = list(_HANDLER_PATTERN.finditer(chain))
    blocks: dict[int, str] = {}
    error_pos = chain.find(_CHAIN_END_MARKER)

    for i, m in enumerate(matches):
        op = int(m.group(2))
        body_start = m.end()
        body_end = matches[i + 1].start() if i + 1 < len(matches) else error_pos
        blocks[op] = chain[body_start:body_end]

    return blocks


def _rebuild_chain(blocks: dict[int, str]) -> str:
    parts = []
    for idx, op in enumerate(sorted(blocks.keys())):
        kw = "if    " if idx == 0 else "elseif"
        parts.append(f"{kw} op=={op:<2} then{blocks[op]}")
    parts.append(_CHAIN_END_MARKER)
    return "".join(parts)


# ---------------------------------------------------------------------------
# 3. split 핸들러 삽입
# ---------------------------------------------------------------------------
def apply_split_to_vm(vm_code: str,
                      split_map: dict[int, dict[str, tuple[int, ...]]],
                      mutate: bool = True) -> str:
    """split_map의 각 (orig_op, parts) 조합에 대해 분할 핸들러를 체인에 추가.

    split 핸들러는 실제로 실행되는 진짜 로직이므로, real/fake 핸들러와
    동일하게 CFF/junk(mutate)를 적용해 구조적으로 구별되지 않게 한다.
    (CFF가 없으면 `_split_tmp=rk(B)+rk(C)` 같은 본문이 그대로 노출되어
    분할 메커니즘이 쉽게 역추적된다.)
    """
    if not split_map:
        return vm_code
    chain_start, chain_end = _find_chain(vm_code)
    chain = vm_code[chain_start:chain_end]
    blocks = _parse_handler_blocks(chain)

    split_blocks: dict[int, str] = {}
    for orig_op, parts_map in split_map.items():
        for parts_str, vops in parts_map.items():
            bodies = split_handler_bodies(orig_op, int(parts_str))
            for vop, body in zip(vops, bodies):
                split_blocks[vop] = body

    if mutate:
        split_blocks = mutate_handlers(split_blocks)

    blocks.update(split_blocks)
    new_chain = _rebuild_chain(blocks)
    return vm_code[:chain_start] + new_chain + vm_code[chain_end:]


# ---------------------------------------------------------------------------
# 4. fusion(superopcode) 핸들러 삽입
# ---------------------------------------------------------------------------
def _op_body(op: int, a: str, b: str, c: str, bx: str,
             av: str = "_av") -> str:
    """단일 op의 동작을 주어진 필드 변수명으로 표현한 Lua 문장 1개."""
    if op == 0:   # MOVE
        return f"rset({a},_carry(_sem(__VM_DATA_VALUE__,rget({b}),nil,nil),{av},0))"
    if op == 1:   # LOADK
        return f"rset({a},_carry(_sem(__VM_DATA_VALUE__,kval(consts[{bx}+1],proto),nil,nil),{av},1))"
    if op == 5:   # GETUPVAL
        return f"rset({a},_carry(_sem(__VM_DATA_VALUE__,get_upvalue(upvals[{b}+1]),nil,nil),{av},5))"
    if op in _GRAPH_BINARY_SLOTS:
        linear = "1" if op == 13 else "-1" if op == 14 else "nil"
        return f"_arith2r({a},{b},{c},{av},{_GRAPH_BINARY_SLOTS[op]},{linear})"
    if op in _GRAPH_UNARY_SLOTS:
        linear = "-1" if op == 25 else "nil"
        return f"_arith1r({a},{b},{av},{_GRAPH_UNARY_SLOTS[op]},{linear})"
    if op in _BINARY_OP_LUA:
        expr = f"rget({b}){_BINARY_OP_LUA[op]}rget({c})"
        if op in _VALUE_BINARY_TAGS:
            expr = f"_carry({expr},{av},{op})"
        return f"rset({a},{expr})"
    if op in _UNARY_PREFIX:
        expr = f"{_UNARY_PREFIX[op]}rget({b})"
        if op in _VALUE_UNARY_TAGS:
            expr = f"_carry({expr},{av},{op})"
        return f"rset({a},{expr})"
    raise ValueError(f"non-fuseable op: {op}")


def fused_handler_body(op1: int, op2: int) -> str:
    """(op1, op2) 쌍을 하나로 실행하는 fused 핸들러 본문.

    슬롯 N(현재)은 instr1의 A/B/C를 갖고, 다음 슬롯 N+1을 직접 읽어
    instr2의 A/B/C를 디코드한 뒤 pc를 1 증가시켜 operand 슬롯을 건너뛴다.
    (LOADKX/EXTRAARG 처리와 동일한 2-슬롯 패턴.)
    """
    # 시프트는 _SH_* 토큰으로 두고 apply_instr_layout이 per-run 리터럴로 인라인한다
    # (decode/read_proto와 동일 레이아웃 공유). 반드시 레이아웃 인라인 전에 emit됨.
    lines = [
        "local _fav=_avd[pc]",
        "local _ei=_cd[pc]~_ksm(pc); pc=pc+1",
        "local _fa=(_ei>>_SH_A)&0xFF",
        "local _fb=(_ei>>_SH_B)&0x1FF",
        "local _fc=(_ei>>_SH_C)&0x1FF",
        "local _fbx=(_ei>>_SH_C)&0x3FFFF",
        _op_body(op1, "A", "B", "C", "Bx", "_av"),
        "_av_read()",
        _op_body(op2, "_fa", "_fb", "_fc", "_fbx", "_fav"),
    ]
    return " " + _SPLIT_PAD.join(lines) + _SPLIT_PAD


def apply_fuse_to_vm(vm_code: str,
                     fuse_map: dict[tuple[int, int], int],
                     mutate: bool = True) -> str:
    """fuse_map의 각 (op1, op2) 쌍에 대해 합쳐진 핸들러를 체인에 추가.

    fused 핸들러도 실제로 실행되는 진짜 로직이므로 real/split/fake와
    동일하게 CFF/junk(mutate)를 적용해 구조적으로 구별되지 않게 한다.
    """
    if not fuse_map:
        return vm_code
    chain_start, chain_end = _find_chain(vm_code)
    chain = vm_code[chain_start:chain_end]
    blocks = _parse_handler_blocks(chain)

    fuse_blocks: dict[int, str] = {}
    for (op1, op2), vop in fuse_map.items():
        fuse_blocks[vop] = fused_handler_body(op1, op2)

    if mutate:
        fuse_blocks = mutate_handlers(fuse_blocks)

    blocks.update(fuse_blocks)
    new_chain = _rebuild_chain(blocks)
    return vm_code[:chain_start] + new_chain + vm_code[chain_end:]


# ---------------------------------------------------------------------------
# 5. alias 핸들러 생성 + vop 치환
# ---------------------------------------------------------------------------
def apply_vop_to_vm(vm_code: str, vop_map: dict[int, list[int]]) -> str:
    """
    vm.lua의 op==N 체인을 파싱해서:
    1. 각 원본 op의 alias vop들에 대해 state 전이가 다른 핸들러를 생성
    2. 원본 op 번호 대신 alias vop 번호로 체인 재조립
    """
    chain_start, chain_end = _find_chain(vm_code)
    chain = vm_code[chain_start:chain_end]
    orig_bodies = _parse_handler_blocks(chain)

    new_blocks: dict[int, str] = {}
    for orig_op, aliases in vop_map.items():
        if orig_op not in orig_bodies:
            continue
        body = orig_bodies[orig_op]
        transitions = _pick_transitions(len(aliases))
        for i, vop in enumerate(aliases):
            transition = transitions[i % len(transitions)]
            pre = (i % 2 == 0)
            new_blocks[vop] = _make_alias_body(body, transition, pre)

    new_chain = _rebuild_chain(new_blocks)
    return vm_code[:chain_start] + new_chain + vm_code[chain_end:]


# ---------------------------------------------------------------------------
# 6. 가짜 핸들러 생성
# ---------------------------------------------------------------------------
# 절대 참이 될 수 없는 가드 조건들 (정수 op 코드 자체를 활용해 매번 다르게)
_FAKE_BODIES = [
    " local _j={}; for _i=1,(B or 0)%3 do _j[_i]=_i*7 end\n        ",
    " if false then rset(A,rget(B) and rget(C) or 0) end\n        ",
    " local _j=(A or 0)~(C or 0); if _j==-1 then rset(0,_j) end\n        ",
    " local _j=Bx or 0; _j=(_j+1)*2-(_j*2+2)\n        ",
    " if pc<0 then pc=pc+sBx end\n        ",
    " local _j={A,B,C}; if #_j==0 then return end\n        ",
    " local _j=(sBx or 0)*0; if _j~=0 then rset(A,_j) end\n        ",
    " if rget(A)==regs and rget(A)~=regs then error(\"unreachable\") end\n        ",
]


def _make_fake_block() -> str:
    return random.choice(_FAKE_BODIES)


# ---------------------------------------------------------------------------
# 7. 메인 진입점
# ---------------------------------------------------------------------------
def prune_and_inject_handlers(
    vm_code: str,
    used_ops: set[int],
    fake_handlers: bool = True,
    mutate: bool = True,
) -> str:
    """
    used_ops에 없는 opcode 핸들러를 제거하고, 비어있는 opcode 번호에
    동작 없는 가짜 핸들러를 무작위로 채워넣는다.

    체인 형태(if op==N then ... elseif op==M then ... else error(...) end)는 유지된다.

    fake_handlers: 빈 vop 슬롯에 더미 핸들러를 채울지 여부
    mutate: CFF/opaque predicate/junk 등 mutate_handlers를 적용할지 여부
    """
    chain_start, chain_end = _find_chain(vm_code)
    chain = vm_code[chain_start:chain_end]

    blocks = _parse_handler_blocks(chain)

    # 사용되는 핸들러만 남김
    blocks = {op: body for op, body in blocks.items() if op in used_ops}

    if fake_handlers:
        # 가짜 핸들러: used_ops 주변 vop 공간에서 랜덤 샘플
        # (vop는 최대 32767이므로 range 기반 열거 불가 → 랜덤 샘플로 대체)
        n_fake = random.randint(len(used_ops) // 2, len(used_ops) * 2 + 1)
        attempts = 0
        while len(blocks) - len(used_ops) < n_fake and attempts < n_fake * 10:
            attempts += 1
            fake_vop = random.randint(0, 0x7FFF)
            if fake_vop not in blocks:
                blocks[fake_vop] = _make_fake_block()

    # CFF/junk는 real + fake 모든 핸들러에 균일하게 적용: CFF 유무가
    # real/fake를 구별하는 oracle이 되지 않도록 구조적 대칭을 유지한다.
    if mutate:
        blocks = mutate_handlers(blocks)

    new_chain = _rebuild_chain(blocks)
    return vm_code[:chain_start] + new_chain + vm_code[chain_end:]


# ---------------------------------------------------------------------------
# 8. 디스패치 모양 변환 (선택형 dispatcher_type)
# ---------------------------------------------------------------------------
# 기존 4개 transform(vop/prune/split/fuse)이 완성한 if-elseif 체인을 다른 디스패치
# 모양으로 바꾼다. 모든 transform 이후 최종 렌더링 단계로만 호출되므로
# transform/serializer/vm.lua는 무변경이다.
#   - ifelseif : 원본 if-elseif 체인 그대로 (변환 없음)
#   - tailcall : 핸들러별 function + 꼬리호출(_step) 테이블 디스패치
#   - bsearch  : op 값 기준 중첩 이진 탐색(if/else) 트리 (for-loop 안 인라인 유지)
#
# fetch 라인(local ins=...decode(ins); pc=pc+1)은 _rename_vm_keys가 이미 치환한
# code 변수명을 그대로 재사용해야 하므로 템플릿에서 추출해 _step 본문에 넣는다.
_TAILCALL_FOR_ANCHOR  = "for i in setmetatable("
_TAILCALL_TAIL_RE     = re.compile(
    r'\s*(?P<epilogue>if _has_pending then _seal_pending\(\) end\s*)?'
    r'end\s*return\s*(?:\{r=\{\},n=0\}|_leave\(\{\},0(?:,[^)]*)?\))'
)

DISPATCH_KINDS = ("split4", "split6", "bsplit4", "bsplit6", "tailcall", "table")


def _resolve_dispatch(dispatch: str) -> str:
    """단일 exec에 적용할 구체 디스패치 종류. 'mixed'면 종류 랜덤."""
    if dispatch == "mixed":
        return random.choice(DISPATCH_KINDS)
    return dispatch


_SPLIT_KIND_RE = re.compile(r'^(b?)split(\d+)$')


def _apply_dispatch(vm_code: str, kind: str) -> str:
    """이미 해석된 구체 디스패치 종류(kind)를 exec 템플릿에 적용.

    kind: ifelseif | tailcall | bsearch | split{k} | bsplit{k}
      · split{k}  : k 그룹 분할, 그룹 내부 ifelseif  (예: split2)
      · bsplit{k} : k 그룹 분할, 그룹 내부 bsearch    (예: bsplit4)
    """
    if kind in {"tailcall", "table"}:
        return convert_dispatch_to_tailcall(vm_code)
    if kind == "bsearch":
        return convert_dispatch_to_bsearch(vm_code)
    m = _SPLIT_KIND_RE.match(kind)
    if m is not None:
        inner = "bsearch" if m.group(1) else "ifelseif"
        return convert_dispatch_to_split(vm_code, int(m.group(2)), inner)
    return vm_code  # ifelseif: 원본 체인 유지


def apply_dispatch(vm_code: str, dispatch: str) -> str:
    """단일 exec에 dispatcher_type을 해석·적용(mixed면 랜덤). 단일 VM 경로용."""
    return _apply_dispatch(vm_code, _resolve_dispatch(dispatch))


def _ends_with_top_return(body: str) -> bool:
    """body의 마지막 *최상위(depth 0)* 문장이 return으로 시작하는지.

    True면 tailcall 핸들러에 `return _step()`를 붙이면 안 된다(Lua는 최상위 return
    뒤 문장을 금지). op 37(TAILCALL) 같이 본문이 top-level return으로 끝나는
    핸들러만 해당. CFF로 감싼(while...end) 본문은 False라 trampoline 연결됨.
    """
    depth = 0
    last_top = ""
    for raw in body.splitlines():
        s = raw.strip()
        if depth <= 0 and s and not s.startswith("--"):
            last_top = s
        depth += _lua_depth_delta(raw)
    return last_top.startswith("return")


def convert_dispatch_to_tailcall(vm_code: str) -> str:
    """exec의 for-loop if-elseif 디스패치를 _H 테이블 + 꼬리호출 형태로 변환."""
    for_anchor = vm_code.find(_TAILCALL_FOR_ANCHOR)
    if for_anchor == -1:
        return vm_code  # 디스패치 루프가 없으면(이미 변환됨 등) 그대로 둔다

    chain_start, chain_end = _find_chain(vm_code)
    chain  = vm_code[chain_start:chain_end]
    blocks = _parse_handler_blocks(chain)

    # for-loop의 `do` 직후 ~ 체인 시작 사이 = fetch 라인(이미 renamed). 재사용.
    do_pos    = vm_code.index(" do", for_anchor) + len(" do")
    fetch_src = vm_code[do_pos:chain_start].strip()

    tail_m = _TAILCALL_TAIL_RE.match(vm_code, chain_end)
    if tail_m is None:
        raise RuntimeError("tailcall convert: dispatch loop tail not found")
    region_end = tail_m.end()
    epilogue = (tail_m.group("epilogue") or "").strip()

    # _step과 핸들러는 vararg 함수로 emit한다. function_obf는 이미 vararg인
    # 함수를 변환에서 제외하므로(skip_vm_dispatcher와 무관) 디스패치 hot path가
    # CFF 평탄화돼 꼬리호출이 깨지는 것을 막는다(= 무한 루프 방지). 동시에 호출
    # 시그니처도 숨겨져 function_obf와 동일한 효과를 얻는다.
    parts = [
        "local _H=setmetatable({},{__call=function(t)return t end})",
        "local function _step(...)",
        f"    {fetch_src}",
        "    return _H[op](A,B,C,Bx,sBx)",
        "end",
    ]
    for vop in sorted(blocks.keys()):
        body   = blocks[vop]
        suffix = "" if _ends_with_top_return(body) else f" {epilogue} return _step() "
        parts.append(f"_H[{vop}]=function(...) local A,B,C,Bx,sBx=...{body}{suffix}end")
    parts.append("return _step()")

    scaffold = "\n        ".join(parts)
    return vm_code[:for_anchor] + scaffold + vm_code[region_end:]


def convert_dispatch_to_bsearch(vm_code: str) -> str:
    """exec의 if-elseif op 체인을 op 값 기준 중첩 이진 탐색(if/else) 트리로 변환.

    핸들러는 for-loop 안에 인라인으로 유지되므로 exec 로컬(regs/rset/kval/consts/
    pc/upvals/...)에 그대로 직접 접근한다(tailcall과 달리 클로저·upvalue 불필요).
    정렬된 vop들을 반씩 갈라 `if op<pivot then ... else ... end`로 내려가고,
    리프에서 `op==vop`를 확인해 어떤 vop에도 없으면 error로 떨어진다.
    """
    chain_start, chain_end = _find_chain(vm_code)
    chain  = vm_code[chain_start:chain_end]
    blocks = _parse_handler_blocks(chain)
    if not blocks:
        return vm_code

    vops = sorted(blocks.keys())
    err  = 'error("unknown op "..op)'

    def build(lo: int, hi: int) -> str:
        if lo == hi:
            vop = vops[lo]
            return f"if op=={vop} then{blocks[vop]}else {err} end"
        mid   = (lo + hi + 1) // 2
        pivot = vops[mid]
        left  = build(lo, mid - 1)
        right = build(mid, hi)
        return f"if op<{pivot} then {left} else {right} end"

    tree = build(0, len(vops) - 1)
    return vm_code[:chain_start] + tree + vm_code[chain_end:]


def _emit_group_inner(
    ops: list[int], blocks: dict[int, str], inner: str, epilogue: str = ""
) -> str:
    """그룹 ops 에 대한 내부 디스패치 본문(inner: 'ifelseif'|'bsearch').

    각 핸들러 body 에는 tailcall 과 동일 규칙으로 trampoline suffix(`return _step()`)
    를 붙인다(top-level return 으로 끝나는 핸들러는 제외). 미매칭 op 는 error.
    """
    err = 'error("unknown op "..op)'

    def branch_body(vop: int) -> str:
        body = blocks[vop]
        suffix = "" if _ends_with_top_return(body) else f" {epilogue} return _step() "
        return f"{body}{suffix}"

    if inner == "bsearch":
        def build(lo: int, hi: int) -> str:
            if lo == hi:
                vop = ops[lo]
                return f"if op=={vop} then {branch_body(vop)}else {err} end"
            mid   = (lo + hi + 1) // 2
            pivot = ops[mid]
            return f"if op<{pivot} then {build(lo, mid-1)} else {build(mid, hi)} end"
        return build(0, len(ops) - 1)

    parts = []
    for i, vop in enumerate(ops):
        kw = "if" if i == 0 else "elseif"
        parts.append(f"{kw} op=={vop} then {branch_body(vop)}")
    parts.append(f"else {err} end")
    return " ".join(parts)


def convert_dispatch_to_split(vm_code: str, k: int = 2,
                              inner: str = "ifelseif") -> str:
    """디스패처를 k 개 그룹 함수(_g0.._g{k-1})로 분할한다.

    ifelseif/bsearch 는 전 핸들러를 한 exec 함수에 인라인해 CFF/junk 와 겹치면
    Lua 함수당 한계(control structure too long)를 넘는다. 정렬된 vop 을 연속 구간
    으로 k 등분해 각 그룹을 별도 함수(전체의 ~1/k 크기)에 담고, tailcall 과 동일한
    클로저+트램폴린(`_step` 꼬리호출)으로 연결한다. 각 그룹 내부는 inner 모양
    (ifelseif|bsearch)을 유지하므로 디스패치 다형성을 잃지 않으면서 크기만 낮춘다.
    """
    for_anchor = vm_code.find(_TAILCALL_FOR_ANCHOR)
    if for_anchor == -1:
        return vm_code

    chain_start, chain_end = _find_chain(vm_code)
    chain  = vm_code[chain_start:chain_end]
    blocks = _parse_handler_blocks(chain)
    if not blocks:
        return vm_code

    do_pos    = vm_code.index(" do", for_anchor) + len(" do")
    fetch_src = vm_code[do_pos:chain_start].strip()

    tail_m = _TAILCALL_TAIL_RE.match(vm_code, chain_end)
    if tail_m is None:
        raise RuntimeError("split convert: dispatch loop tail not found")
    region_end = tail_m.end()
    epilogue = (tail_m.group("epilogue") or "").strip()

    vops = sorted(blocks.keys())
    k    = max(2, min(k, len(vops)))
    size = -(-len(vops) // k)   # ceil division
    groups = [vops[i:i + size] for i in range(0, len(vops), size)]
    ng     = len(groups)
    gnames = [f"_g{i}" for i in range(ng)]

    # _step: fetch 후 op 를 그룹 최대값 기준 연속 구간으로 라우팅.
    # 그룹은 정렬 vop 의 연속 slice 라 op<=그룹max 로 유일하게 결정된다.
    route = " ".join(
        f"if op<={groups[i][-1]} then return {gnames[i]}(op,A,B,C,Bx,sBx) else"
        for i in range(ng - 1)
    )
    route = f"{route} return {gnames[-1]}(op,A,B,C,Bx,sBx)" + " end" * (ng - 1)
    if ng == 1:
        route = f"return {gnames[0]}(op,A,B,C,Bx,sBx)"

    # 그룹 함수는 vararg 로 emit → function_obf 가 hot path 를 CFF 평탄화(꼬리호출
    # 파괴)하지 않도록 한다(tailcall 과 동일 이유).
    #
    # dispatch sentinel: function_obf(skip_vm_dispatcher)는 `__call=function` 을
    # 포함한 함수를 exec(디스패처)로 인식해 CFF 평탄화에서 제외한다. 원본 for-loop
    # 는 이 토큰을 iterator 메타테이블로 갖고 있었고 tailcall 은 _H 메타테이블로
    # 유지한다. split 은 for-loop 를 통째로 치환하므로, 이 토큰이 사라지면 exec 가
    # 평탄화돼 트램폴린(`return _step()`)이 깨져 무한 루프가 된다. 따라서 sentinel
    # 을 명시적으로 유지한다(function_obf 가 vm_output_passes 첫 패스라 dead 여도
    # 그때까지 살아 있다).
    parts = [
        "local _dsm=setmetatable({},{__call=function(t)return t end})",
        f"local {','.join(gnames)}",
        "local function _step(...)",
        f"    {fetch_src}",
        f"    {route}",
        "end",
    ]
    for i, g in enumerate(groups):
        parts.append(
            f"{gnames[i]}=function(...) local op,A,B,C,Bx,sBx=... "
            f"{_emit_group_inner(g, blocks, inner, epilogue)} end"
        )
    parts.append("return _step()")

    scaffold = "\n        ".join(parts)
    return vm_code[:for_anchor] + scaffold + vm_code[region_end:]


# ---------------------------------------------------------------------------
# 9. 멀티VM: 함수(proto)마다 독립 VM 인터프리터 N벌 emit
# ---------------------------------------------------------------------------
# vm.lua의 `exec = function...end` 한 벌을 추출해, VM마다 독립 맵으로 변환한
# _ex0.._ex{N-1}를 만들고 라우팅 테이블 _EX로 묶는다. 디스패치 자체(if-elseif)는
# 기존 transform을 그대로 재사용한다(각 변형은 추출된 exec 템플릿 안에서 동작).
_EXEC_MARK_START = "--<<EXEC>>"
_EXEC_MARK_END   = "--<<ENDEXEC>>"


def build_exec_variants(vm_code: str, n: int, vm_maps: list,
                        used_ops_list: list[set[int]],
                        fake_handlers: bool = True, mutate: bool = True,
                        dispatch: str = "ifelseif") -> str:
    """vm_code(마커 포함 단일 exec 템플릿)를 N벌 exec + _EX 라우팅으로 재조립.

    dispatch: "ifelseif"(전부 if-elseif) | "tailcall"(전부 테이블+꼬리호출) |
              "bsearch"(전부 op 이진탐색) | "mixed"(VM마다 랜덤). 각 _ex{k}는
              별도 함수 스코프라 tailcall이 쓰는 local _H/_step이 서로 충돌하지
              않는다.
    """
    s = vm_code.index(_EXEC_MARK_START)
    e = vm_code.index(_EXEC_MARK_END)
    template = vm_code[s + len(_EXEC_MARK_START):e]

    defs = []
    for k in range(n):
        vop_map, split_map, fuse_map = vm_maps[k]
        c = apply_vop_to_vm(template, vop_map)
        c = prune_and_inject_handlers(c, used_ops_list[k],
                                      fake_handlers=fake_handlers, mutate=mutate)
        c = apply_split_to_vm(c, split_map, mutate=mutate)
        c = apply_fuse_to_vm(c, fuse_map, mutate=mutate)
        # exec 정의 head 이름만 _ex{k}로 변경 (make_closure는 이미 _EX로 라우팅)
        c = c.replace("exec = function", f"_ex{k} = function", 1)
        # VM별 디스패치 모양: ifelseif | tailcall | bsearch (mixed면 VM마다 랜덤)
        c = _apply_dispatch(c, _resolve_dispatch(dispatch))
        defs.append(c)

    # 마커 영역 → N벌 정의로 치환
    vm_code = vm_code[:s] + "\n".join(defs) + vm_code[e + len(_EXEC_MARK_END):]
    # 포워드 선언 + 라우팅 테이블
    names = ",".join(f"_ex{k}" for k in range(n))
    vm_code = vm_code.replace("local exec, _EX", f"local {names}, _EX", 1)
    vm_code = vm_code.replace("_EX={exec}", "_EX={" + names + "}", 1)
    return vm_code
