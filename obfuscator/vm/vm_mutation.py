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
    """
    local 선언을 hoisting.
    반환: (hoist_decls, transformed_lines)
      hoist_decls: ["local fn", "local ca", ...]  (while 앞에 배치)
      transformed_lines: local 제거 후 할당만 남은 라인들
    """
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


def _build_cff(real_chunks: list[list[str]], c: list[int]) -> str:
    """
    real_chunks를 state machine으로 분산.
    local 변수를 hoisting해서 chunk 간 스코프 문제를 해결.
    """
    # 모든 real 라인에서 local 변수 hoisting
    all_real_lines = [ln for chunk in real_chunks for ln in chunk]
    hoist_decls, _ = _hoist_locals(all_real_lines)
    # 각 chunk도 hoisting 적용
    hoisted_chunks = [_hoist_locals(chunk)[1] for chunk in real_chunks]

    used: set[int] = {0}
    real_states = [(_new_state(used), chunk) for chunk in hoisted_chunks]
    real_order  = [st for st, _ in real_states]
    real_next   = {st: (real_order[i+1] if i+1 < len(real_order) else 0)
                   for i, st in enumerate(real_order)}

    n_dead = random.randint(len(real_states), len(real_states) * 2 + 1)
    dead_states = []
    for _ in range(n_dead):
        lines = _dead_lines(c) if random.random() < 0.5 else \
                [_live_arith(c)] + _live_read_lines(c)
        dead_states.append((_new_state(used), lines))

    all_entries = [(st, ls, True)  for st, ls in real_states] + \
                  [(st, ls, False) for st, ls in dead_states]
    random.shuffle(all_entries)

    sv = _zv(c)
    parts = []
    # hoisted decls를 while 앞에 배치
    for d in hoist_decls:
        parts.append(d)
    parts.append(f"local {sv}={real_order[0]}")
    parts.append(f"while {sv}~=0 do")

    for idx, (st, lines, is_real) in enumerate(all_entries):
        kw = "if" if idx == 0 else "elseif"
        parts.append(f"  {kw} {sv}=={st} then")
        for ln in lines:
            parts.append(f"    {ln}")
        parts.append(f"    {sv}={real_next[st] if is_real else 0}")

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