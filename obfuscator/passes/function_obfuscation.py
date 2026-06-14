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

from luaparser import astnodes, ast
from .base import BasePass, Replacement
from ..vm.vm_mutation import _zv, _new_state

# CFF로 hoisting된 local 변수 + 내부 생성 zv 개수가 이 값을 넘으면,
# 개별 local 슬롯이 아니라 테이블 필드(`_T1.name`)로 몰아넣는다.
# Lua 5.3의 함수당 local 변수 한도는 200개이므로, CFF 자체가 쓰는
# state 변수(sv) 등의 여유를 두고 보수적으로 잡는다.
_TABLE_THRESHOLD  = 160
_VARS_PER_TABLE   = 160

# 문자열 리터럴(' 또는 ")을 구간으로 분리하기 위한 정규식.
# 식별자 치환 시 문자열 내부 텍스트는 건드리지 않기 위해 사용한다.
_STRING_LIT_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\''
)

# `function(...)`의 파라미터 목록(괄호 포함)을 구간으로 분리하기 위한 정규식.
# 파라미터는 Lua가 호출 시 자동으로 바인딩하는 함수-scope local이므로,
# 풀링/치환 대상이 아니다. 예를 들어 `__call=function(t)return t end`의
# 파라미터 `t`가 다른 곳의 풀링된 `t`(예: SELF 핸들러의 `local t=regs[B]`)와
# 이름이 같다고 해서 `function(_T1.t)`처럼 치환되면 문법 오류가 된다.
# 괄호 안(파라미터 목록)만 보호하고, 함수 본문은 보호 대상이 아니므로
# 본문 안의 `t`(다른 의미의 변수)는 정상적으로 치환된다.
_FUNC_PARAMS_SPAN_RE = re.compile(r'\bfunction\s*\([^)]*\)')

# 위 두 종류의 "보호 구간"을 한 번에 찾기 위한 결합 정규식.
_PROTECTED_RE = re.compile(
    f'(?:{_STRING_LIT_RE.pattern})|(?:{_FUNC_PARAMS_SPAN_RE.pattern})'
)


def _apply_outside_protected(text: str, transform) -> str:
    """text를 "보호 구간"(문자열 리터럴, `function(...)`의 파라미터 목록)과
    나머지로 분리하고, 보호 구간이 아닌 부분에만 transform(code_part)을
    적용한 뒤 다시 합친다. 보호 구간은 그대로 보존한다.
    """
    out_parts: list[str] = []
    last = 0
    for m in _PROTECTED_RE.finditer(text):
        out_parts.append(transform(text[last:m.start()]))
        out_parts.append(m.group(0))
        last = m.end()
    out_parts.append(transform(text[last:]))
    return "".join(out_parts)


def _strip_protected(text: str) -> str:
    """보호 구간을 같은 길이의 공백으로 대체한 텍스트를 반환한다
    (스캔/위치 보존 전용 용도 - 길이가 바뀌면 안 되는 컨텍스트에서 사용).
    """
    return _PROTECTED_RE.sub(lambda m: ' ' * len(m.group(0)), text)


def _replace_idents_outside_strings(text: str, mapping: dict[str, str]) -> str:
    """보호 구간(문자열 리터럴, `function(...)`의 파라미터 목록)을 보존하면서,
    나머지 코드 영역의 식별자만 mapping에 따라 치환한다.

    mapping의 key는 원래 식별자 이름, value는 치환될 텍스트
    (예: "_z3" -> "_T1._z3" 혹은 "foo" -> "_T2.foo").
    """
    if not mapping:
        return text

    ident_re = re.compile(r'\b(' + '|'.join(re.escape(k) for k in mapping) + r')\b')
    return _apply_outside_protected(text, lambda part: ident_re.sub(lambda mm: mapping[mm.group(1)], part))


# `local a,b,c=1,2,3` / `local a` / `elseif op==X then local _z0=...` 처럼
# 줄의 시작 여부나 `=` 유무와 무관하게, `local` 키워드 뒤에 오는 모든
# 식별자 목록을 찾기 위한 정규식. 기존 vm_mutation._LOCAL_RE는 줄 시작+
# 단일 이름 + `=` 가 모두 있어야 매치하므로 다중 선언이나 한 줄에 여러
# statement가 `;`로 이어진 경우, 혹은 `then local x=...`처럼 같은 줄
# 중간에 등장하는 선언을 모두 놓친다. 테이블화 대상 변수 집합을 정확히
# 모으고 해당 `local` 키워드를 안전하게 제거하기 위해 전체 텍스트에 대해
# 위치 무관하게 매치한다.
_LOCAL_DECL_RE = re.compile(
    r'\blocal\s+((?:[A-Za-z_]\w*\s*,\s*)*[A-Za-z_]\w*)(\s*=)?'
)


def _scan_local_names(text: str) -> set[str]:
    """text 안의 모든 `local NAME[,NAME...]` 선언에서 이름만 수집한다
    (텍스트는 변경하지 않음). 보호 구간(문자열 리터럴,
    `function(...)` 파라미터 목록) 내부는 무시한다.
    """
    names: set[str] = set()
    code_only = _strip_protected(text)
    for m in _LOCAL_DECL_RE.finditer(code_only):
        for name in m.group(1).split(','):
            names.add(name.strip())
    return names


def _collect_and_strip_locals(text: str, only_names: set[str] | None = None) -> tuple[set[str], str]:
    """text 안의 `local NAME[,NAME...]` 선언에서 `local` 키워드를 제거한다.

    - `local a,b=...` (초기값 있음) -> `a,b=...` (`local` 키워드만 제거,
      대입문으로 남아 유효한 statement가 됨)
    - `local a,b` (초기값 없음, declare-only) -> 통째로 제거. 이름들은
      이후 테이블 필드로 치환되므로, 명시적 nil 초기화 없이도 `_T0.a`처럼
      접근 시 자동으로 nil이 반환되어 동작이 동일하다. 단독으로 두면
      `a,b`라는 표현식만 남아 유효하지 않은 statement가 되므로 제거가 필요.

    only_names가 주어지면, 선언에 포함된 이름이 *모두* only_names에
    속할 때만 제거한다 (예: `local _T0={}` 같은 테이블 선언 자체는
    건드리지 않기 위함). only_names가 None이면 모든 local 선언을 제거한다.

    반환값의 set은 실제로 제거된(stripped) 이름들이다.
    보호 구간(문자열 리터럴, `function(...)` 파라미터 목록) 내부는
    건드리지 않는다.
    """
    stripped_names: set[str] = set()

    def _strip_match(m: re.Match) -> str:
        decl_names = [n.strip() for n in m.group(1).split(',')]
        if only_names is not None and not all(n in only_names for n in decl_names):
            return m.group(0)
        stripped_names.update(decl_names)
        if m.group(2):  # `=` 포함 -> 대입문으로 유지
            return m.group(1) + m.group(2)
        return ""  # declare-only -> 통째로 제거

    new_text = _apply_outside_protected(text, lambda part: _LOCAL_DECL_RE.sub(_strip_match, part))
    return stripped_names, new_text


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


def _strip_local_decls(lines: list[str]) -> tuple[set[str], list[str]]:
    """모든 `local a[,b,c...]=...` 선언에서 `local ` 키워드를 제거하고,
    선언된 이름 전체를 모아 반환한다.

    단일 이름(`local x=...`)과 다중 이름(`local a,b,c=1,2,3`) 선언을
    모두 처리한다 (`_hoist_locals`의 `_LOCAL_RE`는 단일 이름만 처리하므로
    다중 선언을 놓치는 문제를 여기서 함께 해결한다).
    """
    names: set[str] = set()
    transformed: list[str] = []
    for ln in lines:
        stripped_ln = ln.lstrip()
        leading_ws = ln[:len(ln) - len(stripped_ln)]

        m = _LOCAL_MULTI_RE.match(stripped_ln)
        if m:
            for name in m.group(1).split(','):
                names.add(name.strip())
            stripped = re.sub(r'^\s*local\s+', '', ln, count=1)
            transformed.append(leading_ws + stripped)
            continue

        m2 = _LOCAL_DECL_ONLY_RE.match(stripped_ln)
        if m2:
            decl_names = [n.strip() for n in m2.group(1).split(',')]
            names.update(decl_names)
            # 초기값이 없으므로 nil로 명시 초기화해 테이블 필드로 변환해도
            # 의미가 동일하게 유지되도록 한다 (`local x` -> `x=nil`).
            transformed.append(leading_ws + ",".join(decl_names) + "=" + ",".join(["nil"] * len(decl_names)))
            continue

        transformed.append(ln)
    return names, transformed


_LUA_BLOCK_KEYWORD_RE = re.compile(
    r'\b(function|if|for|while|repeat|do|then|until|end|elseif|else)\b'
)


def _find_function_body_end(text: str, body_start: int) -> int:
    """text[body_start:]에서, 이 위치를 여는 `function`의 본문이 끝나는
    `end` 키워드의 시작 인덱스를 반환한다 (찾지 못하면 len(text)).

    문자열 리터럴을 마스킹한 뒤, `function/if/for/while/repeat/do`류는
    depth+1, `end`/`until`은 depth-1로 계산한다 (`then`/`else`/`elseif`는
    depth에 영향 없음 - 이미 `if`/`for`/`while`이 +1을 책임짐).
    repeat...until은 `do`를 쓰지 않지만 `repeat`(+1)/`until`(-1)로
    동일하게 균형이 맞는다.
    """
    masked = _strip_protected(text)
    # `do`는 `for`/`while` 뒤에 오는 경우 별도로 depth를 늘리면 이중 계산이
    # 되므로, `function`/`if`/`for`/`while`/`repeat`만 +1, `end`/`until`만 -1로
    # 계산하고 단독 `do ... end` 블록(예: `do local x=1 end`)은 `do`가 +1,
    # `end`가 -1로 균형을 맞춘다. `for ... do ... end`/`while ... do ... end`는
    # `for`/`while`에서 +1, 대응 `end`에서 -1 (중간의 `do`는 무시).
    depth = 1
    pos = body_start
    while pos < len(masked):
        m = _LUA_BLOCK_KEYWORD_RE.search(masked, pos)
        if not m:
            return len(text)
        kw = m.group(1)
        if kw in ('function', 'if', 'repeat'):
            depth += 1
        elif kw in ('end', 'until'):
            depth -= 1
            if depth == 0:
                return m.start()
        elif kw in ('for', 'while'):
            depth += 1
        # then/else/elseif/do: depth 변화 없음
        pos = m.end()
    return len(text)


def _rename_colliding_params(text: str, pooled_names: set[str]) -> str:
    """`function(...)` 파라미터 이름이 pooled_names와 충돌하면, 해당 함수의
    파라미터 선언과 본문 내 모든 참조를 충돌 없는 새 이름으로 일괄
    변경한다.

    풀링 치환은 chunk 전체 텍스트에 대해 식별자 단위로 일괄 적용되므로,
    `__call=function(t)return t end`의 파라미터 `t`가 다른 곳(예: SELF
    핸들러의 `local t=regs[B]`)의 풀링된 `t`와 이름이 같으면 본문의 `t`까지
    `_Tn.t`로 치환되어 파라미터 바인딩이 끊긴다. 이를 막기 위해, 충돌하는
    파라미터만 미리 고유한 이름으로 바꿔둔다(예: `t` -> `_p0`).
    """
    if not pooled_names:
        return text

    counter = [0]
    out_parts: list[str] = []
    last = 0
    pos = 0
    while True:
        m = _FUNC_PARAMS_SPAN_RE.search(text, pos)
        if not m:
            break
        param_text = text[m.start():m.end()][len('function'):].strip()
        param_text = param_text[1:-1]  # strip surrounding ()
        params = [p.strip() for p in param_text.split(',')]
        params = [p for p in params if p and p != '...']
        colliding = [p for p in params if p in pooled_names]
        if not colliding:
            pos = m.end()
            continue

        body_end = _find_function_body_end(text, m.end())
        body_span_end = min(body_end + len('end'), len(text))

        rename_map = {}
        for p in colliding:
            new_name = f"_p{counter[0]}"
            counter[0] += 1
            rename_map[p] = new_name

        out_parts.append(text[last:m.start()])
        segment = text[m.start():body_span_end]
        ident_re = re.compile(r'\b(' + '|'.join(re.escape(k) for k in rename_map) + r')\b')

        def _rename_segment(part: str) -> str:
            sub_parts: list[str] = []
            sub_last = 0
            for sm in _STRING_LIT_RE.finditer(part):
                sub_parts.append(ident_re.sub(lambda mm: rename_map[mm.group(1)], part[sub_last:sm.start()]))
                sub_parts.append(sm.group(0))
                sub_last = sm.end()
            sub_parts.append(ident_re.sub(lambda mm: rename_map[mm.group(1)], part[sub_last:]))
            return "".join(sub_parts)

        segment = _rename_segment(segment)
        out_parts.append(segment)
        last = body_span_end
        pos = body_span_end

    out_parts.append(text[last:])
    return "".join(out_parts)


def _build_var_tables(names: list[str]) -> tuple[list[str], dict[str, str]]:
    """names를 _VARS_PER_TABLE개씩 묶어 테이블에 배정한다.

    반환: (table_decl_lines, name_to_ref)
      table_decl_lines: ["local _T1={}", "local _T2={}", ...]
      name_to_ref: {"foo": "_T1.foo", "_z3": "_T1._z3", ...}
    """
    table_decls: list[str] = []
    name_to_ref: dict[str, str] = {}
    for idx, name in enumerate(names):
        tbl_idx = idx // _VARS_PER_TABLE
        tbl = f"_T{tbl_idx}"
        if tbl_idx == len(table_decls):
            table_decls.append(f"local {tbl}={{}}")
        name_to_ref[name] = f"{tbl}.{name}"
    return table_decls, name_to_ref


def _build_generic_cff(real_chunks: list[list[str]], c: list[int], extra_hoist_names: list[str] | None = None,
                        chunk_ends_with_return: list[bool] | None = None) -> str:
    """real_chunks를 generic dead-state와 함께 state machine으로 분산.

    extra_hoist_names: `local function NAME(...)`에서 미리 추출한 이름들.
    `local NAME` 형태로 while 루프 앞에 선언해, 어느 분기에서 `NAME=function...`
    형태로 할당해도 다른 분기에서 NAME을 참조할 수 있게 한다.

    chunk_ends_with_return: real_chunks와 같은 길이의 리스트로, 각 chunk의
    마지막 statement가 Return인지를 AST로부터 미리 판별한 값. None이면
    전부 False로 취급한다.

    hoist되는 local 변수 + CFF 자체가 생성하는 내부 변수(zv)의 총 개수가
    `_TABLE_THRESHOLD`를 넘으면, 개별 `local` 슬롯 대신 테이블 필드
    (`_T0.name`, `_T1.name`, ...)로 몰아넣어 Lua 5.3의 함수당 local 200개
    한도를 회피한다. 이 변환은 거대한 VM dispatcher처럼 hoist 대상이
    매우 많은 경우에만 활성화되며, 일반적인 작은 함수는 영향이 없다.
    """
    if chunk_ends_with_return is None:
        chunk_ends_with_return = [False] * len(real_chunks)
    all_real_lines = [ln for chunk in real_chunks for ln in chunk]

    # 1) 각 chunk에 등장하는 local 선언 이름들을 모은다 (텍스트는 아직 그대로 둠).
    #    `then local x=...`처럼 줄 중간에 등장하는 선언도 잡기 위해
    #    chunk를 한 텍스트로 합쳐 위치 무관하게 스캔한다.
    #    `function(...)` 파라미터 목록 내부의 이름은 _scan_local_names가
    #    보호 구간으로 처리해 자동으로 제외된다(파라미터는 local 선언이 아님).
    real_names: set[str] = set()
    for chunk in real_chunks:
        real_names |= _scan_local_names("\n".join(chunk))

    hoist_names = list(real_names)
    for name in (extra_hoist_names or []):
        if name not in real_names:
            hoist_names.append(name)
            real_names.add(name)

    used: set[int] = {0}
    real_states = [(_new_state(used), chunk, ends_ret)
                    for chunk, ends_ret in zip(real_chunks, chunk_ends_with_return)]
    real_order  = [st for st, _, _ in real_states]
    real_next   = {st: (real_order[i + 1] if i + 1 < len(real_order) else 0)
                   for i, st in enumerate(real_order)}

    zv_start = c[0]

    n_dead = random.randint(len(real_states), len(real_states) * 2 + 1)
    dead_states = []
    for _ in range(n_dead):
        lines = _generic_dead_lines(c) if random.random() < 0.5 else _generic_live_lines(c)
        dead_states.append((_new_state(used), lines))

    all_entries = [(st, ls, True, ends_ret) for st, ls, ends_ret in real_states] + \
                  [(st, ls, False, False) for st, ls in dead_states]
    random.shuffle(all_entries)

    sv = _zv(c)
    zv_names = [f"_z{i}" for i in range(zv_start, c[0])]

    # 2) hoist 대상(real_names ∪ extra_hoist_names) + CFF가 생성한 zv(sv 포함)
    #    총 개수로 테이블화 여부를 결정한다.
    pooled_names = set(hoist_names) | set(zv_names)
    use_tables = len(pooled_names) > _TABLE_THRESHOLD

    parts = []
    if use_tables:
        table_decls, name_to_ref = _build_var_tables(list(pooled_names))
        for d in table_decls:
            parts.append(d)
    else:
        for name in hoist_names:
            parts.append(f"local {name}")
        name_to_ref = {}

    # 3) sv 초기화: 비-테이블 모드에서는 `local {sv}=...`을 직접 적되,
    #    테이블 모드에서는 sv도 pooled_names에 포함되어 있으므로 `local`
    #    없이 적어두면 아래 strip+substitute 단계에서 `_Tn.sv=...`로
    #    일괄 변환된다.
    if use_tables:
        parts.append(f"local {sv}={real_order[0]}")
    else:
        parts.append(f"local {sv}={real_order[0]}")
    parts.append(f"while {sv}~=0 do")

    for idx, (st, lines, is_real, ends_ret) in enumerate(all_entries):
        kw = "if" if idx == 0 else "elseif"
        parts.append(f"  {kw} {sv}=={st} then")
        for ln in lines:
            parts.append(f"    {ln}")
        if not (is_real and ends_ret):
            parts.append(f"    {sv}={real_next[st] if is_real else 0}")

    parts.append("  end")
    parts.append("end")

    body = ("\n" + _IND).join(parts)

    if use_tables:
        # pooled_names에 해당하는 모든 `local` 선언(real chunk 내부의
        # `local x=...`/`local x`, dead/live state의 `local _zN=...`,
        # 위에서 작성한 `local {sv}=...` 전부)을 일괄적으로 strip한 뒤,
        # 동일한 이름의 모든 참조를 테이블 필드로 치환한다.
        # only_names로 제한하므로 `local _T0={}` 같은 테이블 선언 자체는
        # 영향받지 않는다.
        #
        # 치환은 chunk 전체 텍스트에 대한 식별자 단위 일괄 치환이므로,
        # `function(t)...end`처럼 pooled_names와 이름이 겹치는 파라미터가
        # 있으면 본문의 파라미터 참조까지 `_Tn.t`로 치환되어 파라미터
        # 바인딩이 깨진다. 충돌하는 파라미터를 먼저 고유한 이름으로
        # 바꿔 이런 충돌을 제거한다.
        body = _rename_colliding_params(body, pooled_names)
        _, body = _collect_and_strip_locals(body, only_names=pooled_names)
        body = _replace_idents_outside_strings(body, name_to_ref)
    else:
        # hoist_names는 위에서 이미 `local NAME`으로 while 앞에 선언했으므로,
        # real chunk 본문 안의 `local NAME=...`/`local NAME`은 제거해야
        # 한다 (제거하지 않으면 분기 내부에서 새로 shadow되어 다른 분기와
        # 상태를 공유할 수 없게 됨). zv(`_zN`)는 원래부터 각 state 안에서만
        # 쓰이는 지역 변수이므로 그대로 둔다.
        _, body = _collect_and_strip_locals(body, only_names=set(hoist_names))

    return body


# ---------------------------------------------------------------------------
# 본문 변환
# ---------------------------------------------------------------------------

def _stmt_has_goto_or_label(stmt) -> bool:
    """statement 서브트리에 goto/label이 있는지 AST로 확인한다."""
    for n in ast.walk(stmt):
        if isinstance(n, (astnodes.Goto, astnodes.Label)):
            return True
    return False


def _stmt_text(script: str, stmt, body_min_start: int = 0) -> str | None:
    if stmt.start_char is None or stmt.stop_char is None:
        return None

    start = stmt.start_char

    # luaparser는 `foo(...)`/`foo:bar(...)` 같은 함수 호출문(Call/Invoke)의
    # start_char가 호출 대상(`foo`)이 아니라 `(`를 가리키는 버그가 있다
    # (`.func`/`.source` 노드의 start_char도 None이라 직접 보정 불가).
    # vm.lua는 statement당 한 줄 스타일이므로, 같은 줄의 시작까지
    # 거슬러 올라가 호출 대상 표현식을 포함시킨다.
    # body_min_start: 함수 본문의 시작 위치. Call/Invoke 보정 시 이 위치보다
    # 앞으로 line_start를 올릴 수 없다. 예를 들어 `local mmm = function() print(...) end`
    # 같은 코드에서 AnonymousFunction 내부 Call의 start_char가 `(`를 가리킬 때,
    # 보정이 줄 시작(`local mmm = ...`)까지 올라가면 `function()...end`의 `end`가
    # stop_char 범위에 포함되지 않아 잘린 텍스트가 생성되는 버그를 막는다.
    if isinstance(stmt, (astnodes.Call, astnodes.Invoke)):
        line_start = max(script.rfind('\n', 0, start) + 1, body_min_start)
        candidate = script[line_start:start]
        if candidate.strip():
            start = line_start

    return script[start: stmt.stop_char + 1].strip()


def _prelift_local_function_stmt(stmt, text: str) -> tuple[str | None, str]:
    """`local function NAME(...) ... end` statement를 `NAME=function(...) ... end`로
    재작성하고, NAME을 반환한다 (해당 타입이 아니면 (None, text) 그대로 반환).

    `local function`은 자기 자신을 참조(재귀)할 수 있도록 선언과 동시에
    스코프에 들어가는 특수 형태라, CFF로 여러 if/elseif 분기에 흩어지면
    선언된 분기를 벗어나는 즉시 스코프 밖으로 사라진다. 이를 일반
    `local NAME` 선언으로 hoist 가능한 형태(`NAME=function...`)로 미리
    변환해두면 이후 local-pooling 단계가 처리할 수 있다.
    """
    if not isinstance(stmt, astnodes.LocalFunction):
        return None, text

    name = stmt.name.id
    # text는 "local function NAME(...) ... end" 형태. 첫 '(' 위치부터
    # 그대로 이어 붙여 "NAME=function(...) ... end"로 재작성한다.
    paren_pos = text.index('(')
    return name, f"{name}=function{text[paren_pos:]}"


def _build_stmt_chunks(stmt_lines: list[list[str]], stmt_is_return: list[bool]) -> tuple[list[list[str]], list[bool]]:
    """statement 단위 line-list들을 chunk로 묶는다.

    각 statement는 이미 완결된 단위이므로 depth-tracking이 필요 없다.
    `_split_safe_chunks`와 동일한 0.3 확률의 인접 statement 병합만 적용한다.

    반환: (chunks, chunk_ends_with_return)
      chunk_ends_with_return[i] == chunks[i]에 합쳐진 마지막 statement가
      Return statement인지 여부.
    """
    chunks: list[list[str]] = []
    ends_with_return: list[bool] = []
    for lines, is_ret in zip(stmt_lines, stmt_is_return):
        if chunks and random.random() < 0.3:
            chunks[-1].extend(lines)
            ends_with_return[-1] = is_ret
        else:
            chunks.append(list(lines))
            ends_with_return.append(is_ret)
    return chunks, ends_with_return


def _transform_body(script: str, stmts: list, params: list[str], body_min_start: int = 0) -> str | None:
    """함수 본문(직계 statement 목록)을 변환. 변환 불가능하면 None.

    AST에서 얻은 직계 statement들의 `start_char`/`stop_char`로 텍스트를
    직접 잘라내므로, regex 기반 depth-tracking(`_split_safe_chunks`)에서
    발생할 수 있는 chunk 경계 오인식 문제가 없다. nested function의
    본문은 해당 statement의 텍스트에 그대로 포함되어 한 chunk 단위로만
    다뤄지므로 내부가 쪼개질 일이 없다.

    body_min_start: body.start_char. Call/Invoke stmt 텍스트 보정 시
    이 위치보다 앞으로 line_start를 올리지 않도록 _stmt_text에 전달한다.
    """
    if not stmts:
        return None

    for stmt in stmts:
        if _stmt_has_goto_or_label(stmt):
            return None

    stmt_lines: list[list[str]] = []
    stmt_is_return: list[bool] = []
    extra_hoist_names: list[str] = []

    for stmt in stmts:
        text = _stmt_text(script, stmt, body_min_start=body_min_start)
        if text is None:
            return None
        name, text = _prelift_local_function_stmt(stmt, text)
        if name is not None:
            extra_hoist_names.append(name)
        stmt_lines.append([ln.strip() for ln in text.splitlines() if ln.strip()])
        stmt_is_return.append(isinstance(stmt, astnodes.Return))

    c: list[int] = [0]

    prefix_lines: list[str] = []
    if params:
        prefix_lines.append(f"local {','.join(params)}=...")

    chunks, chunk_ends_with_return = _build_stmt_chunks(stmt_lines, stmt_is_return)

    if len(chunks) <= 1:
        # 너무 단순한 본문: CFF는 의미 없으니 vararg 언팩만 적용
        # (단, prelift로 rewrite된 statement가 있으면 되돌릴 필요 없음 -
        #  NAME=function(...)도 NAME이 이미 local로 선언되어 있었다면
        #  유효하지만, 여기선 hoist가 없으므로 local로 복원해야 함)
        lines = [ln for chunk in chunks for ln in chunk]
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

    cff = _build_generic_cff(chunks, c, extra_hoist_names, chunk_ends_with_return)
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

            new_body = _transform_body(script, body.body, params, body_min_start=body.start_char)
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