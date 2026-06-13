"""
함수 리터럴(`function(...) ... end`)에 대한 일반화된 난독화 패스.

1. 가변인자 래퍼: `function(a,b) ... end` -> `function(...) local a,b=... ... end`
   파라미터 이름과 호출 시그니처를 분리한다. 호출부는 그대로 두므로
   (`...`로 받아서 동일하게 풀어주기 때문에) 항상 안전하다.

2. 본문 CFF (Control-Flow Flattening): vm_mutation의 state-machine 패턴을
   재사용해 함수 본문의 top-level statement 순서를 state machine으로
   흩뿌린다. `goto`/`::label::`이 있는 함수, 이미 `...`를 사용하는
   함수, 본문이 비어있거나 너무 단순한 함수는 안전하게 skip한다.
"""
from __future__ import annotations
import random
import re

from luaparser import astnodes
from .base import BasePass, Replacement
from .vm_mutation import (
    _zv, _split_safe_chunks, _hoist_locals, _new_state, _lua_depth_delta,
)


_GOTO_RE  = re.compile(r'\bgoto\b')
_LABEL_RE = re.compile(r'::\s*\w+\s*::')


def _chunk_ends_with_return(lines: list[str]) -> bool:
    """chunk의 마지막 top-level statement가 `return`으로 시작하는지 확인.

    `return function() ... end`처럼 return 문이 여러 줄에 걸쳐 있을 수
    있으므로, depth==0 경계를 기준으로 top-level statement의 시작 라인을
    찾아 그 라인이 `return`으로 시작하는지 검사한다.
    """
    if not lines:
        return False

    depth = 0
    last_stmt_start = 0
    for idx, ln in enumerate(lines):
        if depth == 0:
            last_stmt_start = idx
        depth += _lua_depth_delta(ln)

    return bool(re.match(r'^\s*return\b', lines[last_stmt_start]))


def _find_param_span(script: str, node_start: int) -> tuple[int, int]:
    """node_start부터 첫 '(' 위치(open)와 매칭되는 ')'위치(close)를 반환.

    luaparser의 Name arg 노드는 start_char/stop_char 정보가 없으므로,
    함수 정의 텍스트에서 직접 괄호를 찾아 파라미터 목록의 범위를 구한다.
    'local function name(...)' / 'function obj.method(...)' /
    'function(...)' 모두 식별자/점 표기에는 '('가 나올 수 없으므로 안전하다.
    """
    i = node_start
    while script[i] != '(':
        i += 1
    open_idx = i
    depth = 1
    j = i + 1
    while depth > 0:
        if script[j] == '(':
            depth += 1
        elif script[j] == ')':
            depth -= 1
        j += 1
    close_idx = j - 1
    return open_idx, close_idx


# ---------------------------------------------------------------------------
# 함수 본문용 generic junk / opaque predicate (VM 컨텍스트 변수 미사용)
# ---------------------------------------------------------------------------

def _generic_const_pair() -> tuple[int, int]:
    a = random.randint(1, 0xFFFFFF)
    b = random.randint(1, 0xFFFFFF)
    return a, b


def _generic_always_true() -> str:
    a, b = _generic_const_pair()
    k = random.randint(1, 0x3FFF)
    return random.choice([
        f"(({a}~{b})~({a}~{b}))==0",
        f"({a}+{b})==({b}+{a})",
        f"(({a}~{k})~{k})==({a})",
        f"({a}*1)==({a})",
        f"(not not (({a})=={a}))",
    ])


def _generic_always_false() -> str:
    a, b = _generic_const_pair()
    k  = random.randint(1, 0x3FFF)
    k2 = k + random.randint(1, 500)
    return random.choice([
        f"({a})~=({a})",
        f"(({a})+{k})==(({a})+{k2})",
        f"({a})==({a}+1)",
        f"({a}*0)~=0",
        f"(not ({a}=={a}))",
    ])


def _generic_dead_lines(c: list[int]) -> list[str]:
    """항상 false인 분기 안에서만 동작하는 dead-code 라인들."""
    zv1, zv2 = _zv(c), _zv(c)
    val = random.randint(0, 0xFFFF)
    return [
        f"local {zv1}={val}",
        f"if {_generic_always_false()} then",
        f"  local {zv2}={zv1}~{val}",
        f"  {zv1}={zv2}",
        f"end",
    ]


def _generic_live_lines(c: list[int]) -> list[str]:
    """항상 실행되지만 부수효과 없는 무의미한 연산."""
    zv = _zv(c)
    a, b = _generic_const_pair()
    body = random.choice([
        f"local {zv}=({a}~{b})~({a}~{b})",
        f"local {zv}=({a}+{b})-({a}+{b})",
        f"local {zv}=({a}|{b})&0",
    ])
    lines = [body]
    if random.random() < 0.5:
        v2 = _zv(c)
        lines.append(f"if {_generic_always_true()} then local {v2}={zv} {zv}={v2} end")
    return lines


# ---------------------------------------------------------------------------
# CFF state machine (generic 버전)
# ---------------------------------------------------------------------------
_IND = "    "


def _build_generic_cff(real_chunks: list[list[str]], c: list[int], extra_hoist_names: list[str] | None = None) -> str:
    """real_chunks를 generic dead-state와 함께 state machine으로 분산.

    extra_hoist_names: `local function NAME(...)`에서 미리 추출한 이름들.
    `local NAME` 형태로 while 루프 앞에 선언해, 어느 분기에서 `NAME=function...`
    형태로 할당해도 다른 분기에서 NAME을 참조할 수 있게 한다.
    """
    all_real_lines = [ln for chunk in real_chunks for ln in chunk]
    hoist_decls, _ = _hoist_locals(all_real_lines)
    hoisted_chunks = [_hoist_locals(chunk)[1] for chunk in real_chunks]

    for name in (extra_hoist_names or []):
        decl = f"local {name}"
        if decl not in hoist_decls:
            hoist_decls.append(decl)

    used: set[int] = {0}
    real_states = [(_new_state(used), chunk) for chunk in hoisted_chunks]
    real_order  = [st for st, _ in real_states]
    real_next   = {st: (real_order[i + 1] if i + 1 < len(real_order) else 0)
                   for i, st in enumerate(real_order)}

    n_dead = random.randint(len(real_states), len(real_states) * 2 + 1)
    dead_states = []
    for _ in range(n_dead):
        lines = _generic_dead_lines(c) if random.random() < 0.5 else _generic_live_lines(c)
        dead_states.append((_new_state(used), lines))

    all_entries = [(st, ls, True) for st, ls in real_states] + \
                  [(st, ls, False) for st, ls in dead_states]
    random.shuffle(all_entries)

    sv = _zv(c)
    parts = []
    for d in hoist_decls:
        parts.append(d)
    parts.append(f"local {sv}={real_order[0]}")
    parts.append(f"while {sv}~=0 do")

    for idx, (st, lines, is_real) in enumerate(all_entries):
        kw = "if" if idx == 0 else "elseif"
        parts.append(f"  {kw} {sv}=={st} then")
        for ln in lines:
            parts.append(f"    {ln}")
        if not (is_real and _chunk_ends_with_return(lines)):
            parts.append(f"    {sv}={real_next[st] if is_real else 0}")

    parts.append("  end")
    parts.append("end")

    return ("\n" + _IND).join(parts)


# ---------------------------------------------------------------------------
# 본문 변환
# ---------------------------------------------------------------------------

_LOCAL_FUNC_RE = re.compile(r'^local\s+function\s+(\w+)\s*\(')


def _extract_lines(body_text: str) -> list[str]:
    return [ln.strip() for ln in body_text.splitlines() if ln.strip()]


def _prelift_local_functions(lines: list[str]) -> tuple[list[str], list[str]]:
    """`local function NAME(...) ... end` 형태를 `NAME=function(...) ... end`로
    재작성하고, NAME을 추가 hoist 대상 목록으로 반환한다.

    `local function`은 자기 자신을 참조(재귀)할 수 있도록 선언과 동시에
    스코프에 들어가는 특수 형태라, CFF로 여러 if/elseif 분기에 흩어지면
    선언된 분기를 벗어나는 즉시 스코프 밖으로 사라진다. 이를 일반
    `local NAME` 선언으로 hoist 가능한 형태(`NAME=function...`)로 미리
    변환해두면 `_hoist_locals`가 처리할 수 있다.
    """
    extra_names: list[str] = []
    new_lines: list[str] = []
    for ln in lines:
        m = _LOCAL_FUNC_RE.match(ln)
        if m:
            name = m.group(1)
            extra_names.append(name)
            # "local function NAME(args) ..." -> "NAME=function(args) ..."
            paren_pos = ln.index('(', m.end(1))
            new_lines.append(f"{name}=function{ln[paren_pos:]}")
        else:
            new_lines.append(ln)
    return extra_names, new_lines


def _transform_body(body_text: str, params: list[str]) -> str | None:
    """함수 본문 텍스트를 변환. 변환 불가능하면 None."""
    if _GOTO_RE.search(body_text) or _LABEL_RE.search(body_text):
        return None

    lines = _extract_lines(body_text)
    if not lines:
        return None

    extra_hoist_names, lines = _prelift_local_functions(lines)

    c: list[int] = [0]

    prefix_lines: list[str] = []
    if params:
        prefix_lines.append(f"local {','.join(params)}=...")

    chunks = _split_safe_chunks(lines)

    if len(chunks) <= 1:
        # 너무 단순한 본문: CFF는 의미 없으니 vararg 언팩만 적용
        # (단, prelift로 rewrite된 라인이 있으면 되돌릴 필요 없음 -
        #  NAME=function(...)도 NAME이 이미 local로 선언되어 있었다면
        #  유효하지만, 여기선 hoist가 없으므로 local로 복원해야 함)
        if extra_hoist_names:
            restored = []
            for ln in lines:
                m = re.match(r'^(\w+)=function', ln)
                if m and m.group(1) in extra_hoist_names:
                    restored.append(f"local function {m.group(1)}{ln[len(m.group(0)):]}")
                else:
                    restored.append(ln)
            lines = restored
        new_body = "\n".join(prefix_lines + lines)
        return new_body

    cff = _build_generic_cff(chunks, c, extra_hoist_names)
    new_body = "\n".join(prefix_lines + [cff])
    return new_body


class FunctionObfuscationPass(BasePass):
    """함수 리터럴에 가변인자 래퍼 + 본문 CFF를 적용한다.

    - 호출부(call site)는 전혀 건드리지 않는다 (`function(...) local a,b=... end`로
      파라미터를 다시 풀어주므로 외부에서 보이는 시그니처/호출 규약은 동일).
    - 이미 `...`를 사용하는 함수, `goto`/label이 있는 함수, 본문이 비어있는
      함수는 건드리지 않는다.
    """

    def run(self, script: str, tree) -> list[Replacement]:
        replacements: list[Replacement] = []
        # 이미 변환 대상으로 선택된 함수의 body 범위들.
        # 이 범위에 완전히 포함되는 nested 함수는 건너뛴다 (outer의 본문 텍스트에
        # nested 함수 정의가 그대로 한 chunk로 포함되어 처리되기 때문에,
        # 이중으로 변환하면 겹치는 Replacement가 생겨 출력이 깨짐).
        claimed_ranges: list[tuple[int, int]] = []

        # 바깥쪽 함수가 먼저 처리되도록 본문 크기(큰 것 우선) 순서로 순회
        func_nodes = [
            node for node in self.walk(tree)
            if isinstance(node, (astnodes.Function, astnodes.LocalFunction, astnodes.AnonymousFunction, astnodes.Method))
        ]
        func_nodes.sort(
            key=lambda n: (n.body.stop_char - n.body.start_char)
            if (n.body and n.body.start_char is not None and n.body.stop_char is not None)
            else -1,
            reverse=True,
        )

        for node in func_nodes:
            args = node.args
            if any(isinstance(a, astnodes.Varargs) for a in args):
                continue  # 이미 ... 사용 중

            params = [a.id for a in args if isinstance(a, astnodes.Name)]
            if len(params) != len(args):
                continue  # 알 수 없는 arg 형태

            # Method(`function obj:method(x)`)의 self는 Lua가 항상 첫
            # 번째 고정 파라미터로 암묵 전달하며 `...`에는 포함되지 않는다
            # (`function obj:method(...)`에서 `...`는 self 이후의 가변
            # 인자만 가리킴). 따라서 self는 건드리지 않고, 명시적 파라미터
            # (x 등)만 `...`로 풀어준다. params는 이미 self를 포함하지
            # 않으므로 별도 처리 불필요.

            body = node.body
            if body is None or body.start_char is None or body.stop_char is None:
                continue

            # 이미 처리된 outer 함수의 본문에 완전히 포함되면 건너뛴다.
            if any(cs <= body.start_char and body.stop_char <= ce for cs, ce in claimed_ranges):
                continue

            body_text = script[body.start_char: body.stop_char + 1]
            new_body = _transform_body(body_text, params)
            if new_body is None:
                continue

            claimed_ranges.append((body.start_char, body.stop_char))

            replacements.append(Replacement(
                start=body.start_char,
                end=body.stop_char,
                new_text=new_body,
            ))

            # 파라미터 목록 -> "..."로 교체 (괄호 안 내용 전체를 "..."로 변경)
            # Method의 self는 위에서 처리하지 않으므로, 명시적 params가
            # 있을 때만 해당 괄호 내용을 "..."로 바꾼다 (self는 그대로 유지됨).
            if params:
                open_idx, close_idx = _find_param_span(script, node.start_char)
                replacements.append(Replacement(
                    start=open_idx + 1,
                    end=close_idx - 1,
                    new_text="...",
                ))

        return replacements