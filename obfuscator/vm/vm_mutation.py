from __future__ import annotations
import random
import re

_RETURN_RE  = re.compile(r'\breturn\b')
_LOCAL_RE   = re.compile(r'\blocal\s+(\w+)\s*=')
_IND        = "        "


def _zv(c: list[int]) -> str:
    n = c[0]; c[0] += 1
    return f"_z{n}"


# ---------------------------------------------------------------------------
# Opaque Predicates
# ---------------------------------------------------------------------------

def _op_expr() -> str:
    return random.choice([
        "(A+B*C)", "(Bx~(pc&0xFF))", "(A|(B+C))",
        "(sBx+(A*B))", "((A~B)+(C*Bx)&0xFFFF)", "(pc+(A|Bx))",
    ])


def _always_true() -> str:
    v = _op_expr()
    k = random.randint(1, 0x3FFF)
    base = random.choice([
        f"({v})*({v}+1)&1==0",
        f"({v})~({v})==0",
        f"({v})~{k}~{k}==({v})",
        f"({v})-({v})==0",
        f"(not not ({v}))==(not not ({v}))",
    ])
    if random.random() < 0.4:
        v2 = _op_expr()
        base = f"({base}) and (({v2})~({v2})==0)"
    return base


def _always_false() -> str:
    v = _op_expr()
    k  = random.randint(1, 0x3FFF)
    k2 = k + random.randint(1, 500)
    base = random.choice([
        f"({v})~=({v})",
        f"(({v})~({v}))~=0",
        f"(({v})+{k})==(({v})+{k2})",
        f"({v})*0~=0",
        f"(not ({v}==({v})))",
    ])
    if random.random() < 0.4:
        v2 = _op_expr()
        base = f"({base}) or (({v2})~=({v2}) and false)"
    return base


# ---------------------------------------------------------------------------
# 코드 조각 생성
# ---------------------------------------------------------------------------

def _arith_expr() -> str:
    """순수 표현식. rset 인자 등에 사용 (statement 아님)."""
    k    = random.randint(1, 0xFFFF)
    slot = random.randint(0, 3)
    return random.choice([
        f"(A or 0)~{k}~{k}",
        f"(Bx or 0)&0xFFFF",
        f"(pc+(A|0))&0xFFFF",
        f"(C*B+A)&0xFF",
        f"((sBx~A)+0)&0x7FFFF",
        f"(B~C)&0xFF",
        f"(A~B~C)&0xFF",
        f"regs[{slot}] and 0 or (A*0)",
    ])


def _junk_ref(var: str, c: list[int]) -> str:
    zv = _zv(c)
    k  = random.randint(1, 0xFFFF)
    return random.choice([
        f"local {zv}=({var} and 0 or 0)~{k}; {zv}={zv}~{zv}",
        f"local {zv}=type({var})==\"nil\" and 0 or 0",
        f"local {zv}=({var}~=nil) and 0 or 0",
    ])


def _live_arith(c: list[int]) -> str:
    zv = _zv(c)
    k  = random.randint(1, 0xFFFF)
    return random.choice([
        f"local {zv}=(A or 0)~{k}; {zv}={zv}~{k}",
        f"local {zv}=(Bx or 0)~{k}~{k}",
        f"local {zv}=(pc+(A|0))&0xFFFF",
        f"local {zv}=(C*B+A)&0xFF",
        f"local {zv}=((sBx~A)+0)&0x7FFFF",
    ])


def _dead_lines(c: list[int]) -> list[str]:
    zv1 = _zv(c); zv2 = _zv(c)
    slot = random.randint(0, 3); val = random.randint(0, 0xFF)
    return [
        f"local {zv1}={val}",
        f"if {_always_false()} then",
        f"  rset({slot},{zv1})",
        f"  local {zv2}=regs[{slot}]",
        f"  rset(A,{zv2})",
        f"end",
    ]


def _live_read_lines(c: list[int]) -> list[str]:
    zv = _zv(c); slot = random.randint(0, 3)
    return [
        f"local {zv}=regs[{slot}]",
        f"if {_always_true()} then {zv}={zv} end",
    ]


def _fake_rset_lines(c: list[int]) -> list[str]:
    """always_false 가드로 보호된 fake rset() 블록.
    real handler와 시각적으로 유사한 패턴을 사용해 혼동을 유도한다.
    """
    lines = [f"if {_always_false()} then"]
    for _ in range(random.randint(1, 2)):
        choice = random.randint(0, 4)
        if choice == 0:
            lines.append(f"  rset(A,{_arith_expr()})")
        elif choice == 1:
            zv   = _zv(c)
            slot = random.randint(0, 3)
            lines.append(f"  local {zv}=regs[{slot}]")
            lines.append(f"  rset({slot},{zv})")
        elif choice == 2:
            zv      = _zv(c)
            s1, s2  = random.randint(0, 3), random.randint(0, 3)
            lines.append(f"  local {zv}=regs[{s1}]")
            lines.append(f"  rset({s2},{_arith_expr()})")
            lines.append(f"  rset(A,{zv})")
        elif choice == 3:
            lines.append(f"  rset(B,regs[C])")
        else:
            zv = _zv(c)
            lines.append(f"  local {zv}={_arith_expr()}")
            lines.append(f"  if {_always_true()} then rset(A,{zv}) end")
    lines.append("end")
    return lines


# ---------------------------------------------------------------------------
# Lua block depth
# ---------------------------------------------------------------------------

def _lua_depth_delta(line: str) -> int:
    s = line.strip()
    s = re.sub(r'"(?:[^"\\]|\\.)*"', '', s)
    s = re.sub(r"'(?:[^'\\]|\\.)*'", '', s)
    s_no_elseif = re.sub(r'\belseif\b', '', s)
    opens  = len(re.findall(r'\b(if|for|while|function)\b', s_no_elseif))
    closes = len(re.findall(r'\bend\b', s_no_elseif))
    if re.search(r'\bdo\b', s_no_elseif) and not re.search(r'\b(for|while)\b', s_no_elseif):
        opens += len(re.findall(r'\bdo\b', s_no_elseif))
    opens  += len(re.findall(r'\brepeat\b', s_no_elseif))
    closes += len(re.findall(r'\buntil\b', s_no_elseif))
    return opens - closes


def _split_safe_chunks(lines: list[str]) -> list[list[str]]:
    """depth==0 경계에서만 chunk를 자른다."""
    chunks: list[list[str]] = []
    current: list[str] = []
    depth = 0
    for ln in lines:
        current.append(ln)
        depth += _lua_depth_delta(ln)
        if depth <= 0 and current:
            if chunks and random.random() < 0.3:
                chunks[-1].extend(current)
            else:
                chunks.append(current[:])
            current = []
            depth = 0
    if current:
        if chunks:
            chunks[-1].extend(current)
        else:
            chunks.append(current)
    return chunks


# ---------------------------------------------------------------------------
# local 변수 hoisting
# ---------------------------------------------------------------------------

def _hoist_locals(lines: list[str]) -> tuple[list[str], list[str]]:
    hoist_decls: list[str] = []
    hoisted: set[str] = set()
    transformed: list[str] = []

    for ln in lines:
        for m in _LOCAL_RE.finditer(ln):
            v = m.group(1)
            if v not in hoisted:
                hoist_decls.append(f"local {v}")
                hoisted.add(v)
        new_ln = re.sub(r'\blocal\s+(\w+)\s*=', r'\1=', ln)
        transformed.append(new_ln)

    return hoist_decls, transformed


# ---------------------------------------------------------------------------
# CFF state machine
# ---------------------------------------------------------------------------

def _new_state(used: set[int]) -> int:
    while True:
        s = random.randint(100, 9999)
        if s not in used:
            used.add(s); return s


def _make_dead_body(c: list[int]) -> list[str]:
    """dead state body — rset 호출 포함 4가지 패턴 중 랜덤 선택."""
    lines: list[str] = []
    r = random.random()
    if r < 0.25:
        # live arith + fake rset
        lines.append(_live_arith(c))
        lines.extend(_fake_rset_lines(c))
    elif r < 0.50:
        # 기존 dead_lines (rset under always_false 포함)
        lines.extend(_dead_lines(c))
    elif r < 0.75:
        # live read + fake rset
        lines.extend(_live_read_lines(c))
        lines.extend(_fake_rset_lines(c))
    else:
        # 혼합
        lines.append(_live_arith(c))
        lines.extend(_dead_lines(c))
        if random.random() < 0.5:
            lines.extend(_live_read_lines(c))
    # 20% 확률로 fake rset 블록 하나 추가
    if random.random() < 0.2:
        lines.extend(_fake_rset_lines(c))
    return lines


def _build_cff(real_chunks: list[list[str]], c: list[int]) -> str:
    """
    real_chunks를 state machine으로 분산.

    개선 사항:
    - XOR 키로 state 값 인코딩 (static analysis 방해)
    - dead state 체인 (dead→dead→…→exit): dead가 항상 즉시 종료하지 않음
    - dead state에 fake rset() 호출 삽입: 실제 핵심 코드 식별 방해
    - always_false 하에 fake back-edge: dead state가 이전 state로 분기하는 것처럼 보임
    """
    all_real_lines = [ln for chunk in real_chunks for ln in chunk]
    hoist_decls, _ = _hoist_locals(all_real_lines)
    hoisted_chunks = [_hoist_locals(chunk)[1] for chunk in real_chunks]

    # state 변수 이름 + XOR 인코딩 키
    sv  = _zv(c)
    key = random.randint(0x100, 0x7FFF)

    def enc(s: int) -> int:
        return s ^ key

    # real states
    used: set[int] = {0}
    real_states = [(_new_state(used), chunk) for chunk in hoisted_chunks]
    real_order  = [st for st, _ in real_states]
    real_next   = {st: (real_order[i + 1] if i + 1 < len(real_order) else 0)
                   for i, st in enumerate(real_order)}

    # dead state 생성 후 랜덤 체인으로 연결
    n_dead   = random.randint(len(real_states), len(real_states) * 2 + 2)
    dead_ids = [_new_state(used) for _ in range(n_dead)]
    random.shuffle(dead_ids)

    dead_entries: list[tuple[int, list[str], int]] = []
    i = 0
    while i < len(dead_ids):
        chain_len = min(random.randint(1, 3), len(dead_ids) - i)
        chain     = dead_ids[i:i + chain_len]
        for j, sid in enumerate(chain):
            body     = _make_dead_body(c)
            next_sid = chain[j + 1] if j + 1 < chain_len else 0
            dead_entries.append((sid, body, next_sid))
        i += chain_len

    dead_next_map = {sid: nxt for sid, _, nxt in dead_entries}
    # fake back-edge 대상 후보: 모든 real + dead state id
    all_ids = real_order + [sid for sid, _, _ in dead_entries]

    all_entries: list[tuple[int, list[str], bool]] = (
        [(st, chunk, True)  for st, chunk in real_states] +
        [(sid, body, False) for sid, body, _ in dead_entries]
    )
    random.shuffle(all_entries)

    parts: list[str] = []
    for d in hoist_decls:
        parts.append(d)

    parts.append(f"local {sv}={enc(real_order[0])}")
    parts.append(f"while {sv}~={enc(0)} do")

    for idx, (st, lines, is_real) in enumerate(all_entries):
        kw = "if" if idx == 0 else "elseif"
        parts.append(f"  {kw} {sv}=={enc(st)} then")
        for ln in lines:
            parts.append(f"    {ln}")

        if is_real:
            parts.append(f"    {sv}={enc(real_next[st])}")
        else:
            # 35% 확률로 always_false 하에 fake back-edge 삽입
            # → dead state가 이전 state로 돌아가는 것처럼 보여 CFG 분석 방해
            if random.random() < 0.35 and all_ids:
                fake_tgt = random.choice(all_ids)
                parts.append(
                    f"    if {_always_false()} then {sv}={enc(fake_tgt)} end"
                )
            parts.append(f"    {sv}={enc(dead_next_map[st])}")

    parts.append("  end")
    parts.append("end")

    return ("\n" + _IND).join(parts)


# ---------------------------------------------------------------------------
# 핸들러 mutation
# ---------------------------------------------------------------------------

def _extract_real_lines(body: str) -> list[str]:
    return [ln.strip() for ln in body.splitlines()
            if ln.strip() and not ln.strip().startswith("--")]


def mutate_handler_body(body: str, c: list[int]) -> str:
    has_return = bool(_RETURN_RE.search(body))
    real_lines = _extract_real_lines(body)
    if not real_lines:
        return body

    # junk_ref: return 없는 핸들러에만 삽입
    local_vars = re.findall(r'\blocal\s+(\w+)\s*=', body)
    if local_vars and not has_return:
        pos = random.randint(0, len(real_lines))
        real_lines = real_lines[:pos] + \
                     [_junk_ref(random.choice(local_vars), c)] + \
                     real_lines[pos:]

    if has_return:
        prefix = [_live_arith(c)]
        if random.random() < 0.5:
            prefix.extend(_dead_lines(c))
        if random.random() < 0.5:
            prefix.extend(_live_read_lines(c))
        return " " + ("\n" + _IND).join(prefix + real_lines) + "\n" + _IND

    chunks = _split_safe_chunks(real_lines)

    if len(chunks) <= 1:
        prefix = [_live_arith(c)]
        if random.random() < 0.5:
            prefix.extend(_dead_lines(c))
        if random.random() < 0.5:
            prefix.extend(_live_read_lines(c))
        return " " + ("\n" + _IND).join(prefix + real_lines) + "\n" + _IND

    cff = _build_cff(chunks, c)
    return " " + cff + "\n" + _IND


def mutate_handlers(blocks: dict[int, str], rate: float = 1.0) -> dict[int, str]:
    c: list[int] = [0]
    new: dict[int, str] = {}
    for op, body in blocks.items():
        if random.random() < rate:
            new[op] = mutate_handler_body(body, c)
        else:
            new[op] = body
    return new
