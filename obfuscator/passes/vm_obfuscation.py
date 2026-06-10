"""
VM 디스패처 핸들러 prune + 가짜 핸들러 삽입.

- 실제 바이트코드에서 사용되지 않는 opcode의 핸들러를 vm.lua에서 제거
- 비어있는 opcode 번호 슬롯에 동작 없는 더미 핸들러를 무작위로 채워넣음
"""
from __future__ import annotations
import random
import re

from .parser import Proto
from .vm_mutation import mutate_handlers

_LUA_OP_COUNT = 47  # Lua 5.3 opcode 0~46

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
_CHAIN_END_MARKER = 'else _err("unknown op "..op) end'


# ---------------------------------------------------------------------------
# 1. 사용 중인 opcode 수집
# ---------------------------------------------------------------------------
def collect_used_ops(proto: Proto, vop_map: dict[int, list[int]]) -> set[int]:
    """
    proto 트리를 재귀 순회하며 디스패처가 실제로 dispatch하는 vop 집합을 반환.

    OP_LOADKX(원본 op==2)의 다음 명령어(EXTRAARG)는 디스패처가 직접 decode하지
    않고 건너뛰므로 used set에 포함시키지 않는다.
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


# ---------------------------------------------------------------------------
# 2. vm.lua 핸들러 체인 파싱 / 재조립
# ---------------------------------------------------------------------------
_CHAIN_START_PATTERN = re.compile(r'if\s+op==\d+\s*then')


def _find_chain(vm_code: str) -> tuple[int, int]:
    """exec 함수 내 if/elseif op==N 체인의 (start, end) 인덱스를 반환."""
    anchor = vm_code.find("for i in _sm(")
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
# 3. alias 핸들러 생성 + vop 치환
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
# 4. 가짜 핸들러 생성
# ---------------------------------------------------------------------------
# 절대 참이 될 수 없는 가드 조건들 (정수 op 코드 자체를 활용해 매번 다르게)
_FAKE_BODIES = [
    " local _j={}; for _i=1,(B or 0)%3 do _j[_i]=_i*7 end\n        ",
    " if false then rset(A,regs[B] and regs[C] or 0) end\n        ",
    " local _j=(A or 0)~(C or 0); if _j==-1 then rset(0,_j) end\n        ",
    " local _j=Bx or 0; _j=(_j+1)*2-(_j*2+2)\n        ",
    " if pc<0 then pc=pc+sBx end\n        ",
    " local _j={A,B,C}; if #_j==0 then return end\n        ",
    " local _j=(sBx or 0)*0; if _j~=0 then rset(A,_j) end\n        ",
    " if regs[A]==regs and regs[A]~=regs then error(\"unreachable\") end\n        ",
]


def _make_fake_block() -> str:
    return random.choice(_FAKE_BODIES)


# ---------------------------------------------------------------------------
# 5. 메인 진입점
# ---------------------------------------------------------------------------
def prune_and_inject_handlers(vm_code: str, used_ops: set[int]) -> str:
    """
    used_ops에 없는 opcode 핸들러를 제거하고, 비어있는 opcode 번호에
    동작 없는 가짜 핸들러를 무작위로 채워넣는다.

    체인 형태(if op==N then ... elseif op==M then ... else error(...) end)는 유지된다.
    """
    chain_start, chain_end = _find_chain(vm_code)
    chain = vm_code[chain_start:chain_end]

    blocks = _parse_handler_blocks(chain)

    # 사용되는 핸들러만 남김
    blocks = {op: body for op, body in blocks.items() if op in used_ops}

    # 가짜 핸들러: used_ops 주변 vop 공간에서 랜덤 샘플
    # (vop는 최대 32767이므로 range 기반 열거 불가 → 랜덤 샘플로 대체)
    n_fake = random.randint(len(used_ops) // 2, len(used_ops) * 2 + 1)
    attempts = 0
    while len(blocks) - len(used_ops) < n_fake and attempts < n_fake * 10:
        attempts += 1
        fake_vop = random.randint(0, 0x7FFF)
        if fake_vop not in blocks:
            blocks[fake_vop] = _make_fake_block()

    blocks = mutate_handlers(blocks)

    new_chain = _rebuild_chain(blocks)
    return vm_code[:chain_start] + new_chain + vm_code[chain_end:]