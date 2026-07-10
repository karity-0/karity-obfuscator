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


def _nested_always_true(depth: int) -> str:
    """항상 참인 opaque predicate를 depth만큼 논리 결합해 중첩한다.

    `true and true == true`, `true or false == true` 항등식만 사용하므로
    depth와 무관하게 결과는 언제나 참이다. 파서/디컴파일러가 상수 폴딩으로
    소거하기 어렵도록 매 층 서로 다른 상수쌍의 predicate를 섞는다.
    """
    expr = _generic_always_true()
    for _ in range(max(0, depth - 1)):
        if random.random() < 0.5:
            expr = f"(({expr}) and ({_generic_always_true()}))"
        else:
            expr = f"(({expr}) or ({_generic_always_false()}))"
    return f"({expr})"


def _nested_always_false(depth: int) -> str:
    """항상 거짓인 opaque predicate를 depth만큼 논리 결합해 중첩한다.

    `false or false == false`, `false and true == false` 항등식만 사용하므로
    depth와 무관하게 결과는 언제나 거짓이다. 가짜(dead) 분기 가드에 쓴다.
    """
    expr = _generic_always_false()
    for _ in range(max(0, depth - 1)):
        if random.random() < 0.5:
            expr = f"(({expr}) or ({_generic_always_false()}))"
        else:
            expr = f"(({expr}) and ({_generic_always_true()}))"
    return f"({expr})"


# ---------------------------------------------------------------------------
# 그럴듯한 가짜 흐름(fake flow) 생성기.
#
# dead state는 real 흐름이 절대 그 상태쌍으로 sv를 설정하지 않으므로 런타임에
# 도달하지 않는다 → 본문에 로컬 함수 호출/루프까지 넣어도 실행 안전하다.
# 제약: (1) 문법 유효성, (2) pooling/strip 정합성, (3) 전역 미참조.
#   * 로컬은 `_zv(c)`(→ `_zN`)로 만들어 pooled 되게 한다.
#   * for 루프 변수는 `local` 없이 선언되고 `_zN` 패턴도 아닌 이름(`_fv<rand>`)을
#     써서 pooling/치환 대상에서 자동 제외되게 한다(테이블 모드에서 `for _Tn._z=`
#     같은 문법 오류 방지).
#   * 전역(math/string/table 등)은 참조하지 않는다: VM처럼 제한된 _ENV에서
#     재난독화될 때 localize_globals와 충돌해 깨질 수 있기 때문. rich junk은
#     일반(비-VM) 경로 전용이고, VM 재난독화는 _junk_simple(보수적)만 쓴다.
# ---------------------------------------------------------------------------


def _obf_int(n: int) -> str:
    """항상 n과 같은 정수 표현식. 상수 폴딩을 방해해 state 상수를 감춘다.

    (실행되는 real 전이에도 사용되므로 모든 변형은 정확히 n과 같아야 한다:
    n~k~k==n, n+k-k==n, n|0==n(n>=0), (n<<0)~0==n.)
    """
    if random.random() < 0.45:
        return str(n)
    k = random.randint(1, 0xFFFF)
    return random.choice([
        f"({n}~{k}~{k})",
        f"({n}+{k}-{k})",
        f"({n}|0)",
        f"(({n}<<0)~0)",
    ])


def _junk_expr(c: list[int]) -> str:
    """부수효과 없어 보이는 그럴듯한 값 표현식 (dead 전용, 실행 안 됨).

    전역(math/string/table 등)은 절대 참조하지 않는다: VM처럼 제한된 _ENV에서
    재난독화될 때 localize_globals가 존재하지 않는 전역을 nil 로컬로 만들어
    깨질 수 있기 때문(dead여도 안전 마진 확보). 순수 산술 + 로컬만 쓴다.
    """
    a, b = _generic_const_pair()
    return random.choice([
        f"({a}~{b})",
        f"({a}+{b})",
        f"({a}*{(b % 997) + 1})",
        f"({a}//{(b % 999) + 1})",
        f"({a}%{(b % 9973) + 1})",
        f"(({a}|{b})&0xFFFFFF)",
        f"(({a}<<3)~{b})",
        f"({a}>>{(b % 13) + 1})",
    ])


def _junk_seg_assign(c: list[int]) -> list[str]:
    return [f"local {_zv(c)}={_junk_expr(c)}"]


def _junk_seg_chain(c: list[int]) -> list[str]:
    n = random.randint(2, 4)
    zvs = [_zv(c) for _ in range(n)]
    lines = [f"local {zvs[0]}={_junk_expr(c)}"]
    for i in range(1, n):
        op = random.choice(["+", "-", "~", "*", "%", "|", "&"])
        k = random.randint(1, 9999)
        lines.append(f"local {zvs[i]}={zvs[i - 1]}{op}{k}")
    return lines


def _junk_seg_call(c: list[int]) -> list[str]:
    """로컬 클로저 정의 + 호출로 "함수 호출" 느낌을 낸다 (전역 미참조).

    클로저 파라미터는 `local`이 아니라 함수 파라미터라 pooling 스캔 대상이
    아니고, `_z\\d+` 패턴도 아닌 이름(`_pa<rand>`)을 써서 테이블-치환에서도
    자동 제외되게 한다(파라미터 decl/use 불일치 방지).
    """
    fn = _zv(c)
    p = f"_pa{random.randint(0, 2 ** 31)}"
    a, b = _generic_const_pair()
    body_op = random.choice([f"{p}*{(b % 97) + 1}", f"{p}+{a % 100000}", f"{p}~{b % 65536}"])
    return [
        f"local {fn}=function({p}) return {body_op} end",
        f"local {_zv(c)}={fn}({_junk_expr(c)})",
    ]


def _junk_seg_loop(c: list[int]) -> list[str]:
    fv = f"_fv{random.randint(0, 2 ** 31)}"   # local 없는 for 변수 → pooling 제외
    z = _zv(c)
    return [
        f"local {z}={random.randint(0, 999)}",
        f"for {fv}=1,{random.randint(2, 6)} do",
        f"  {z}={z}+{fv}*{random.randint(1, 9)}",
        f"end",
    ]


def _junk_seg_cond(c: list[int]) -> list[str]:
    z = _zv(c)
    a, b = _generic_const_pair()
    return [
        f"local {z}={a}",
        f"if {_nested_always_false(2)} then",
        f"  {z}={b}",
        f"elseif {_generic_always_false()} then",
        f"  {z}={z}~{random.randint(1, 9999)}",
        f"end",
    ]


_JUNK_SEGS = (_junk_seg_assign, _junk_seg_chain, _junk_seg_call,
              _junk_seg_loop, _junk_seg_cond)


def _junk_simple(c: list[int]) -> list[str]:
    """VM 재난독화(제한된 _ENV)용 보수적 가짜 흐름.

    rich junk의 함수 정의/루프/다양한 연산자는 VM 템플릿을 이후 패스
    (localize_globals 등)와 함께 재난독화할 때 깨질 수 있으므로, 여기서는
    검증된 순수 산술(`~`/`+`/`-`/`|`/`&`)만 쓰는 짧은 흐름을 낸다.
    """
    zv = _zv(c)
    a, b = _generic_const_pair()
    lines = [random.choice([
        f"local {zv}=({a}~{b})~({a}~{b})",
        f"local {zv}=({a}+{b})-({a}+{b})",
        f"local {zv}=({a}|{b})&0",
    ])]
    if random.random() < 0.5:
        v2 = _zv(c)
        lines.append(f"if {_generic_always_false()} then local {v2}={zv}~{b} {zv}={v2} end")
    return lines


def _junk_flow(c: list[int], rich: bool = True) -> list[str]:
    """가변 길이(1~4 세그먼트)의 그럴듯한 가짜 흐름 (dead state 본문 전용).

    rich=False면 VM 재난독화용 보수적 흐름(_junk_simple)만 낸다.
    """
    if not rich:
        return _junk_simple(c)
    out: list[str] = []
    for _ in range(random.randint(1, 4)):
        out += random.choice(_JUNK_SEGS)(c)
    return out


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


def _build_generic_cff(blocks: list[dict], entry_id: int, c: list[int],
                       extra_hoist_names: list[str] | None = None,
                       rich_junk: bool = True) -> str:
    """블록 전이 그래프를 generic dead-state와 함께 state machine으로 분산.

    blocks: `_compile_stmts_to_blocks`가 만든 블록 리스트. 각 블록은 dict:
      {"id", "lines", "kind"} + kind별 전이 정보
        - kind=="goto"   : "succ"(다음 블록 id, 0=종료)
        - kind=="branch" : "cond"(조건식 텍스트), "t"(참 시 id), "e"(거짓 시 id)
        - kind=="return" : 전이 없음 (lines의 return이 함수를 빠져나감)
    entry_id: 실행이 시작될 블록 id.

    branch 블록은 원본 `if cond then ... else ... end`을 상태 머신으로 흡수한
    것으로, state 갱신을 `if cond then sv=then else sv=else end` 형태로 emit해
    조건 분기 자체를 평탄화한다.

    extra_hoist_names: `local function NAME(...)`에서 미리 추출한 이름들.
    `local NAME` 형태로 while 루프 앞에 선언해, 어느 분기에서 `NAME=function...`
    형태로 할당해도 다른 분기에서 NAME을 참조할 수 있게 한다.

    hoist되는 local 변수 + CFF 자체가 생성하는 내부 변수(zv)의 총 개수가
    `_TABLE_THRESHOLD`를 넘으면, 개별 `local` 슬롯 대신 테이블 필드
    (`_T0.name`, `_T1.name`, ...)로 몰아넣어 Lua 5.3의 함수당 local 200개
    한도를 회피한다. 이 변환은 거대한 VM dispatcher처럼 hoist 대상이
    매우 많은 경우에만 활성화되며, 일반적인 작은 함수는 영향이 없다.
    """
    # 1) 각 블록 body에 등장하는 local 선언 이름들을 모은다 (텍스트는 아직 그대로).
    #    `then local x=...`처럼 줄 중간에 등장하는 선언도 잡기 위해 블록 lines를
    #    한 텍스트로 합쳐 위치 무관하게 스캔한다. branch 블록의 조건식은 새 local을
    #    만들지 않으므로(기존 hoist/param 참조) lines만 스캔하면 충분하다.
    #    `function(...)` 파라미터 목록 내부의 이름은 _scan_local_names가
    #    보호 구간으로 처리해 자동으로 제외된다(파라미터는 local 선언이 아님).
    real_names: set[str] = set()
    for blk in blocks:
        real_names |= _scan_local_names("\n".join(blk["lines"]))

    hoist_names = list(real_names)
    for name in (extra_hoist_names or []):
        if name not in real_names:
            hoist_names.append(name)
            real_names.add(name)

    zv_start = c[0]

    # ------------------------------------------------------------------
    # 다차원 상태 + 계층형(hierarchical) 디스패치.
    #
    # 평면 `while sv~=0 do if sv==S1 ... elseif ... end end` 대신,
    # 상태를 2차원 쌍 (sv1, sv2)로 쪼갠다.
    #   - sv1: "그룹" 좌표 (바깥 elseif 체인)
    #   - sv2: 그룹 내부 "리프" 좌표 (안쪽 elseif 체인)
    # 종료쌍은 (0,0)으로 예약한다. 각 real state에는 전역 유일한 정수쌍을
    # 배정하므로 `sv1==g and sv2==b` 가 상태를 유일하게 식별한다.
    #
    # 정확성 규칙(반드시 유지):
    #   * 디스패치는 그룹/리프 모두 elseif 체인 → 한 iteration에 정확히 하나만
    #     실행 (별도 `if`로 풀면 leaf가 sv2를 같은 그룹의 다른 리프로 바꾸는
    #     순간 cascade 실행되는 버그가 생김).
    #   * 중첩(들여쓰기 지옥)은 (a) 그룹 레벨, (b) 항상-참 opaque 래퍼 층,
    #     (c) leaf body 안쪽 항상-참 중첩 에만 둔다 — 셋 다 상호배타이거나
    #     항상 참이라 안전.
    #   * state 갱신(`sv1=..; sv2=..`)은 항상-참 래퍼의 *가장 안쪽*에 두어
    #     무조건 정확히 한 번 실행되게 한다.
    #   * 가짜(dead) 형제 분기는 항상-거짓 opaque predicate로 가드하여
    #     절대 실행되지 않는다.
    # ------------------------------------------------------------------
    used: set[int] = {0}
    sv1 = _zv(c)
    sv2 = _zv(c)

    n_groups = random.randint(2, 4)
    group_ids = [_new_state(used) for _ in range(n_groups)]

    def _alloc_leaf() -> int:
        return _new_state(used)  # 전역 유일 → 쌍 (g,b)도 유일

    # 1) 각 블록에 (group, leaf) 상태쌍 배정. 0=종료쌍 (0,0).
    pair: dict[int, tuple[int, int]] = {0: (0, 0)}
    for blk in blocks:
        blk["g"] = random.choice(group_ids)
        blk["b"] = _alloc_leaf()
        pair[blk["id"]] = (blk["g"], blk["b"])
    entry_g, entry_b = pair[entry_id]

    # 2) 블록 종류별 state 갱신 코드 생성 → real_meta (updates: 방출할 라인 리스트).
    #    - return: 갱신 없음 (lines의 return이 함수를 종료)
    #    - goto  : `sv1=<ng> sv2=<nb>` (상수는 _obf_int로 위장 가능)
    #    - branch: `if(cond) then ... else ... end`을 없애고 and/or 산술 대입으로
    #      흡수한다. 원래 조건 흐름이 if 구조로 드러나지 않게 한다:
    #          local is_match=(cond)
    #          sv1 = is_match and <tg> or <eg>
    #          sv2 = is_match and <tb> or <eb>
    #      Lua에서 상태값은 항상 정수(>=100) 또는 0이고 0도 truthy이므로
    #      `cond and A or B` 단축평가가 모든 경우 정확하다(then=cond truthy).
    #      조건은 로컬에 한 번만 담아 side-effect도 정확히 1회 평가된다.
    #      `(cond\n)`로 감싸 조건 끝의 줄-주석/여러 줄도 안전하게 처리한다.
    real_meta: list[dict] = []
    for blk in blocks:
        kind = blk["kind"]
        if kind == "return":
            updates = []
        elif kind == "goto":
            ng, nb = pair[blk["succ"]]
            updates = [f"{sv1}={_obf_int(ng)} {sv2}={_obf_int(nb)}"]
        else:  # branch → and/or 흡수
            tg, tb = pair[blk["t"]]
            eg, eb = pair[blk["e"]]
            ism = _zv(c)
            updates = [
                f"local {ism}=({blk['cond']}\n)",
                f"{sv1}={ism} and {_obf_int(tg)} or {_obf_int(eg)}",
                f"{sv2}={ism} and {_obf_int(tb)} or {_obf_int(eb)}",
            ]
        real_meta.append({"g": blk["g"], "b": blk["b"], "lines": blk["lines"], "updates": updates})

    # 3) dead state: 그럴듯한 가변 길이 가짜 흐름 + 다양한 전이로 위장.
    #    도달 불가하므로 전이 대상은 무관하지만, real처럼 다른 상태로 점프하거나
    #    임의 상수로 가게 해 정적 분석 시 "종료(0,0) 고정"으로 보이지 않게 한다.
    n_dead = random.randint(len(real_meta), len(real_meta) * 2 + 1)
    dead_meta: list[dict] = []
    for _ in range(n_dead):
        dead_meta.append({
            "g": random.choice(group_ids), "b": _alloc_leaf(),
            "lines": _junk_flow(c, rich_junk), "updates": None,   # 전이는 all_pairs 확정 후 채움
        })

    # 모든 상태쌍을 모아 dead 전이 대상 후보로 쓴다(자기 자신 포함 무해 - 도달 불가).
    all_pairs = [(m["g"], m["b"]) for m in real_meta + dead_meta]

    def _dead_updates() -> list[str]:
        r = random.random()
        if r < 0.5:
            g2, b2 = random.choice(all_pairs)       # 실제 존재하는 상태로 점프하는 척
        elif r < 0.8:
            g2, b2 = random.randint(100, 9999), random.randint(100, 9999)
        else:
            g2, b2 = 0, 0                            # 가끔은 종료
        return [f"{sv1}={_obf_int(g2)} {sv2}={_obf_int(b2)}"]

    for m in dead_meta:
        m["updates"] = _dead_updates()

    groups: dict[int, list[dict]] = {g: [] for g in group_ids}
    for m in real_meta + dead_meta:
        groups[m["g"]].append(m)
    for g in groups:
        random.shuffle(groups[g])
    ordered_groups = [g for g in group_ids if groups[g]]
    random.shuffle(ordered_groups)

    # 3) 디스패치 코드 방출 (relative 들여쓰기; 최종 join이 base indent 추가).
    _PRED_DEPTH = 2          # opaque predicate 논리 결합 깊이
    lines: list[str] = []

    def emit(level: int, s: str) -> None:
        lines.append("  " * level + s)

    emit(0, f"local {sv1}={entry_g}")
    emit(0, f"local {sv2}={entry_b}")
    emit(0, f"while {sv1}~=0 or {sv2}~=0 do")

    for gi, g in enumerate(ordered_groups):
        gkw = "if" if gi == 0 else "elseif"
        emit(1, f"{gkw} {sv1}=={g} then")

        # (b) 그룹 내부 디스패치를 항상-참 래퍼 층으로 감싼다.
        n_wrap = random.randint(1, 2)
        for w in range(n_wrap):
            emit(2 + w, f"if {_nested_always_true(_PRED_DEPTH)} then")
        base = 2 + n_wrap

        leaves = groups[g]
        for li, m in enumerate(leaves):
            lkw = "if" if li == 0 else "elseif"
            emit(base, f"{lkw} {sv2}=={m['b']} then")

            # (c) leaf body 안쪽 항상-참 중첩 (들여쓰기 지옥).
            n_inner = random.randint(0, 2)
            for x in range(n_inner):
                emit(base + 1 + x, f"if {_nested_always_true(_PRED_DEPTH)} then")
            bb = base + 1 + n_inner
            for ln in m["lines"]:
                emit(bb, ln)
            # state 갱신은 가장 안쪽에 → 항상-참 층을 통과해 무조건 실행.
            # (goto=1줄, branch=and/or 3줄, return=빈 리스트 → 갱신 없음)
            for u in m["updates"]:
                emit(bb, u)
            for x in reversed(range(n_inner)):
                emit(base + 1 + x, "end")
        emit(base, "end")  # 리프 elseif 체인 닫기

        for w in reversed(range(n_wrap)):
            emit(2 + w, "end")  # 래퍼 층 닫기

        # 그룹 내부 가짜 dead 형제 (항상-거짓 가드 → 실행 안 됨).
        emit(2, f"if {_nested_always_false(_PRED_DEPTH)} then")
        for jl in _junk_flow(c, rich_junk):
            emit(3, jl)
        emit(2, "end")

    emit(1, "end")  # 그룹 elseif 체인 닫기

    # top-level 가짜 dead (항상-거짓).
    emit(1, f"if {_nested_always_false(_PRED_DEPTH)} then")
    for jl in _junk_flow(c, rich_junk):
        emit(2, jl)
    emit(1, "end")

    emit(0, "end")  # while 닫기

    zv_names = [f"_z{i}" for i in range(zv_start, c[0])]

    # 4) hoist 대상(real_names ∪ extra_hoist_names) + CFF가 생성한 zv
    #    (sv1/sv2/junk 전부) 총 개수로 테이블화 여부를 결정한다.
    pooled_names = set(hoist_names) | set(zv_names)
    use_tables = len(pooled_names) > _TABLE_THRESHOLD

    prologue: list[str] = []
    if use_tables:
        table_decls, name_to_ref = _build_var_tables(list(pooled_names))
        prologue.extend(table_decls)
    else:
        # 비-테이블 모드: hoist 선언(`local NAME`)은 strip 단계에서 declare-only로
        # 같이 제거되므로 여기서 붙이지 않고, strip 이후에 본문 앞에 붙인다(아래).
        name_to_ref = {}

    # sv1/sv2 초기화 `local {sv}=...`는 위 emit에 이미 포함돼 있다. 테이블
    # 모드에서는 sv1/sv2도 pooled_names에 속하므로 아래 strip+substitute가
    # `_Tn.sv1=...`로 일괄 변환하고, 비-테이블 모드에서는 hoist 대상이 아니라
    # state-local(`local sv1`)로 그대로 남는다.
    body = ("\n" + _IND).join(prologue + lines)

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
        # real chunk 본문 안의 `local NAME=...`(→`NAME=...`) / `local NAME`(→제거)을
        # strip한다 (제거 안 하면 분기 내부에서 shadow되어 분기 간 상태 공유 불가).
        # hoist 선언(`local NAME`)도 declare-only라 이 strip에 같이 지워지므로,
        # strip을 먼저 끝낸 뒤 hoist 선언을 본문 앞에 붙인다. 이렇게 해야 hoist된
        # local이 while 앞에 실제로 선언되어 분기 간 공유되고, 누락 시 전역으로
        # 새지 않는다. zv(`_zN`)는 hoist 대상이 아니라 state-local로 그대로 둔다.
        _, body = _collect_and_strip_locals(body, only_names=set(hoist_names))
        if hoist_names:
            decls = ("\n" + _IND).join(f"local {n}" for n in hoist_names)
            body = decls + "\n" + _IND + body

    return body


# ---------------------------------------------------------------------------
# 본문 변환
# ---------------------------------------------------------------------------

# tree-sitter-lua 함수 노드 타입: function_declaration = `[local] function NAME`,
# function_definition = 익명 `function(...)`.
_FUNC_NODE_TYPES = ("function_declaration", "function_definition")


def _is_local_func(node) -> bool:
    """`local function NAME(...)` 형태인지 (function_declaration + 첫 자식 local)."""
    return (node.type == "function_declaration"
            and bool(node.children) and node.children[0].type == "local")


def _block_stmts(ctx, block) -> list:
    """block의 직계 문장 노드들 (주석 제외).

    tree-sitter는 주석(`comment`)도 named 노드로 block 자식에 넣으므로,
    luaparser의 statement 목록(주석 미포함)과 동작을 맞추려면 걸러낸다.
    """
    return [c for c in block.children if c.is_named and c.type != "comment"]


def _subtree_has_goto_or_label(node) -> bool:
    """노드 서브트리에 goto/label이 있으면 True (중첩 함수 내부 포함, 보수적)."""
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type in ("goto_statement", "label_statement"):
            return True
        stack.extend(n.children)
    return False


def _prelift_local_function_stmt(ctx, stmt, text: str) -> tuple[str | None, str]:
    """`local function NAME(...) ... end` statement를 `NAME=function(...) ... end`로
    재작성하고, NAME을 반환한다 (해당 타입이 아니면 (None, text) 그대로 반환).

    `local function`은 자기 자신을 참조(재귀)할 수 있도록 선언과 동시에
    스코프에 들어가는 특수 형태라, CFF로 여러 if/elseif 분기에 흩어지면
    선언된 분기를 벗어나는 즉시 스코프 밖으로 사라진다. 이를 일반
    `local NAME` 선언으로 hoist 가능한 형태(`NAME=function...`)로 미리
    변환해두면 이후 local-pooling 단계가 처리할 수 있다.

    `function r.u8()` / `function obj:method()`처럼 점/메서드 표기 이름은
    local-function이 아니므로 prelift 대상이 아니다(불투명 chunk로 유지).
    """
    if not _is_local_func(stmt):
        return None, text

    name_node = ctx.first_child(stmt, "identifier")
    if name_node is None:
        return None, text
    name = ctx.text(name_node)
    # text는 "local function NAME(...) ... end" 형태. 첫 '(' 위치부터
    # 그대로 이어 붙여 "NAME=function(...) ... end"로 재작성한다.
    paren_pos = text.index('(')
    return name, f"{name}=function{text[paren_pos:]}"


def _compile_stmts_to_blocks(ctx, stmts, extra_hoist_names: list[str]) -> tuple[list[dict], int]:
    """문장열을 상태 머신 블록 전이 그래프로 컴파일한다.

    `if_statement`을 만나면 조건을 평가하는 branch 블록 + then/else 본문을 각각
    sub-블록열로 재귀 컴파일해, `if/else` 구조 자체를 상태 머신에 흡수한다
    (합류점 = if 다음 문장의 블록). `elseif`는 else 자리의 if로 재귀한다.

    while/for/repeat/do 등 다른 복합문은 통째로 불투명 goto 블록으로 둔다:
    루프 내부의 `break`가 CFF 디스패치 while로 새면 안 되고, 루프는 한 chunk로
    유지하는 편이 안전하다. (직선 흐름의 if는 그 안에 break가 문법상 올 수 없어
    흡수해도 안전하고, goto/label 있는 함수는 호출부에서 이미 통째로 skip한다.)

    각 문장(모든 중첩 레벨)에 `local function NAME` prelift를 적용해, 여러
    상태로 흩어져도 NAME이 함수 스코프 hoist 대상으로 남게 한다.

    반환: (blocks, entry_id). 각 블록 dict는 `_build_generic_cff` 참고.
    entry_id는 실행 시작 블록 id (0=종료).
    """
    blocks: list[dict] = []
    counter = [0]

    def _new_id() -> int:
        counter[0] += 1
        return counter[0]

    def _stmts_of(block_node) -> list:
        # 본문이 비어 있는 `if c then end`/`elseif c then end`/`else end`는
        # tree-sitter가 consequence/body 필드를 주지 않아 None이 온다 → 빈 블록.
        return _block_stmts(ctx, block_node) if block_node is not None else []

    def _stmt_lines(stmt) -> list[str]:
        text = ctx.text(stmt).strip()
        name, text = _prelift_local_function_stmt(ctx, stmt, text)
        if name is not None:
            extra_hoist_names.append(name)
        return [ln.strip() for ln in text.splitlines() if ln.strip()]

    def _branch(cond: str, then_entry: int, else_entry: int) -> int:
        # 조건식은 원문 그대로(줄바꿈 포함) 유지한다 — 조건 끝의 줄-주석이나
        # 여러 줄 조건은 update emit 시 `(cond\n)` 로 감싸 안전하게 처리한다.
        bid = _new_id()
        blocks.append({"id": bid, "lines": [], "kind": "branch",
                       "cond": cond, "t": then_entry, "e": else_entry})
        return bid

    def _compile_if(node, after_id: int) -> int:
        # tree-sitter-lua는 elseif를 중첩이 아니라 if_statement의 형제
        # `alternative` 필드로 평탄하게 나열한다: [elseif_statement...] + [else_statement?].
        # 따라서 alternative 자식을 순서대로 모두 수집해 직접 체인을 만든다.
        alts = [ch for i, ch in enumerate(node.children)
                if node.field_name_for_child(i) == "alternative"]
        elseifs = [a for a in alts if a.type == "elseif_statement"]
        else_node = next((a for a in alts if a.type == "else_statement"), None)

        # 체인의 최종 else 진입점 (else 없으면 if 다음 문장으로 합류).
        if else_node is not None:
            chain = _compile_seq(_stmts_of(else_node.child_by_field_name("body")), after_id)
        else:
            chain = after_id

        # elseif들을 뒤에서 앞으로 감싸 else 체인을 구성.
        for ei in reversed(elseifs):
            ei_cond = ctx.text(ei.child_by_field_name("condition")).strip()
            ei_then = _compile_seq(_stmts_of(ei.child_by_field_name("consequence")), after_id)
            chain = _branch(ei_cond, ei_then, chain)

        # 최상위 if.
        cond = ctx.text(node.child_by_field_name("condition")).strip()
        then_entry = _compile_seq(_stmts_of(node.child_by_field_name("consequence")), after_id)
        return _branch(cond, then_entry, chain)

    def _compile_seq(stmt_list, after_id: int) -> int:
        # 뒤에서 앞으로 컴파일 → 각 블록의 후속 id를 바로 알 수 있다.
        next_id = after_id
        for stmt in reversed(stmt_list):
            if stmt.type == "if_statement":
                next_id = _compile_if(stmt, next_id)
            else:
                bid = _new_id()
                blk = {"id": bid, "lines": _stmt_lines(stmt)}
                if stmt.type == "return_statement":
                    blk["kind"] = "return"
                else:
                    blk["kind"] = "goto"
                    blk["succ"] = next_id
                blocks.append(blk)
                next_id = bid
        return next_id

    entry = _compile_seq(stmts, 0)
    return blocks, entry


def _transform_body(ctx, block, params: list[str], rich_junk: bool = True) -> str | None:
    """함수 본문(block 노드)을 변환. 변환 불가능하면 None.

    top-level 문장열을 블록 전이 그래프로 컴파일(`_compile_stmts_to_blocks`)한 뒤
    state machine으로 평탄화한다. `if/else`는 조건 branch 블록으로 흡수되어
    분기 구조 자체가 평탄화되고, 루프/nested function 본문은 불투명 블록으로
    한 단위로만 다뤄진다.
    """
    stmts = _block_stmts(ctx, block)
    if not stmts:
        return None

    for stmt in stmts:
        if _subtree_has_goto_or_label(stmt):
            return None

    extra_hoist_names: list[str] = []
    blocks, entry = _compile_stmts_to_blocks(ctx, stmts, extra_hoist_names)

    c: list[int] = [0]

    prefix_lines: list[str] = []
    if params:
        prefix_lines.append(f"local {','.join(params)}=...")

    # 너무 단순한 본문(단일 simple/return 문, 분기 없음)은 CFF가 무의미하니
    # vararg 언팩만 적용한다. branch 블록이 하나라도 있으면(조건 흡수 대상)
    # side-effect 있는 조건이 사라지지 않도록 CFF 경로로 보낸다.
    if len(blocks) == 1 and blocks[0]["kind"] != "branch":
        lines = blocks[0]["lines"]
        if extra_hoist_names:
            restored = []
            for ln in lines:
                m = re.match(r'^(\w+)=function', ln)
                if m and m.group(1) in extra_hoist_names:
                    restored.append(f"local function {m.group(1)}{ln[len(m.group(0)):]}")
                else:
                    restored.append(ln)
            lines = restored
        return "\n".join(prefix_lines + lines)

    cff = _build_generic_cff(blocks, entry, c, extra_hoist_names, rich_junk=rich_junk)
    return "\n".join(prefix_lines + [cff])


# VM 디스패처(exec) 식별용 sentinel. exec의 dispatch 루프
# `for i in setmetatable({},{__call=function(t)return t end}) do` 에만 등장하며,
# `__call`은 VM 템플릿 전체에서 이 한 곳에서만 쓰이는 메타메서드 키다
# (사용자 코드는 bytecode로 blob에 들어가므로 VM 텍스트에 나타나지 않는다).
# rename/number/string 난독화에도 살아남는다(`__call`은 테이블 필드 키,
# `function`은 키워드).
_DISPATCH_SENTINEL = re.compile(r'__call\s*=\s*function')


class FunctionObfuscationPass(BasePass):
    """함수 리터럴에 가변인자 래퍼 + 본문 CFF를 적용한다.

    - 호출부(call site)는 전혀 건드리지 않는다 (`function(...) local a,b=... end`로
      파라미터를 다시 풀어주므로 외부에서 보이는 시그니처/호출 규약은 동일).
    - 이미 `...`를 사용하는 함수, `goto`/label이 있는 함수, 본문이 비어있는
      함수는 건드리지 않는다.

    skip_vm_dispatcher: VM 출력물 재난독화 시 켠다. dispatch sentinel
      (`__call=function`)을 직접 포함하는 함수, 즉 VM 디스패처(exec)와 이를
      감싸는 _vmf wrapper만 변환에서 제외한다. exec 본문은 거대한 dispatch
      state machine이라 텍스트 기반 CFF로 평탄화하면 분기마다 흩어진 local
      function 정의가 스코프 밖으로 사라져 깨지고, hot path라 비용도 크다.
      반면 exec *내부*의 작은 헬퍼 클로저(rget/rset/get_box/make_closure 등)와
      형제 cold 헬퍼들(kae_decrypt/read_proto/run 등)은 정상적으로 변환된다
      (헬퍼가 참조하는 exec 로컬은 변환 후에도 upvalue로 남아 접근 가능하고,
      exec 자체는 평탄화되지 않아 헬퍼 정의 순서/스코프가 유지된다).
    """

    # 파싱은 tree-sitter(C, ~10x)로. 파이프라인이 tree 인자로 TSContext를 준다.
    parser = "treesitter"

    def __init__(self, skip_vm_dispatcher: bool = False):
        self.skip_vm_dispatcher = skip_vm_dispatcher

    def run(self, script: str, ctx) -> list[Replacement]:
        replacements: list[Replacement] = []
        # 이미 변환 대상으로 선택된 함수의 body(block) 범위들. 이 범위에 완전히
        # 포함되는 nested 함수는 건너뛴다 (outer 본문 텍스트에 nested 함수 정의가
        # 한 chunk로 포함돼 처리되므로, 이중 변환하면 Replacement가 겹쳐 깨짐).
        claimed_ranges: list[tuple[int, int]] = []

        def _block_of(n):
            return ctx.first_child(n, "block")

        def _bsize(n) -> int:
            b = _block_of(n)
            return (ctx.ce(b) - ctx.cs(b)) if b is not None else -1

        # 함수 노드 수집 + 본문 큰 것 우선(바깥 함수가 먼저 처리되도록)
        func_nodes = [n for n in ctx.walk() if n.type in _FUNC_NODE_TYPES]
        func_nodes.sort(key=_bsize, reverse=True)

        # VM 디스패처 스킵 준비: sentinel을 *직접* 포함하는 함수(= exec 및 이를
        # 감싸는 _vmf wrapper)만 변환에서 제외한다. exec 본문은 거대한
        # dispatch state machine이라 텍스트 기반 CFF로 평탄화하면 분기마다
        # 흩어진 local function 정의가 스코프 밖으로 사라져 깨지고, 매
        # instruction마다 도는 hot path라 평탄화 비용도 크다.
        #
        # 단, exec *내부*의 작은 헬퍼 클로저(rget/rset/get_box/make_closure 등)는
        # 각자 독립적으로 CFF/vararg 변환해도 안전하다: 그들이 참조하는 exec
        # 로컬(regs/boxes/upvals 등)은 변환 후에도 그대로 upvalue로 남아
        # 접근 가능하고, exec 자체는 평탄화되지 않으므로 헬퍼 정의 순서/스코프가
        # 유지된다. 따라서 이전처럼 exec 본문 range 전체를 막지 않고, sentinel을
        # 직접 포함하는 함수 노드만 건너뛴다.
        skip_node_ids: set[int] = set()
        if self.skip_vm_dispatcher:
            for node in func_nodes:
                b = _block_of(node)
                if b is None:
                    continue
                if _DISPATCH_SENTINEL.search(ctx.text(b)):
                    skip_node_ids.add(node.id)

        for node in func_nodes:
            block = _block_of(node)
            if block is None:
                continue
            bstart, bend = ctx.cs(block), ctx.ce(block)

            if self.skip_vm_dispatcher and node.id in skip_node_ids:
                # sentinel을 직접 포함하는 함수(wrapper/exec) 자체만 스킵.
                # exec 내부의 헬퍼 클로저는 아래에서 정상 변환된다.
                continue

            params_node = ctx.first_child(node, "parameters")
            if params_node is None:
                continue
            if any(c.type == "vararg_expression" for c in params_node.children):
                continue  # 이미 ... 사용 중

            # Method(`function obj:method(x)`)의 self는 method_index_expression에
            # 있어 parameters 밖이므로 params에 들어오지 않는다. 명시적 파라미터만
            # `...`로 풀어주고 self는 그대로 둔다.
            params = [ctx.text(c) for c in params_node.children if c.type == "identifier"]

            # 이미 처리된 outer 함수의 본문에 완전히 포함되면 건너뛴다.
            if any(cs <= bstart and bend <= ce for cs, ce in claimed_ranges):
                continue

            # VM 재난독화(skip_vm_dispatcher)에서는 rich junk을 끈다: 함수 정의/
            # 루프/다양한 연산자가 든 가짜 흐름이 VM 템플릿을 이후 패스와 함께
            # 재난독화할 때(localize_globals 등) 깨질 수 있어, 보수적 흐름만 쓴다.
            new_body = _transform_body(ctx, block, params, rich_junk=not self.skip_vm_dispatcher)
            if new_body is None:
                continue

            claimed_ranges.append((bstart, bend))
            replacements.append(Replacement(start=bstart, end=bend, new_text=new_body))

            # 파라미터 목록 내부('(' 다음 ~ ')' 이전)를 "..."로 교체. params가
            # 있을 때만(자기 self/빈 목록은 건드리지 않음).
            if params:
                replacements.append(Replacement(
                    start=ctx.cs(params_node) + 1,
                    end=ctx.ce(params_node) - 1,
                    new_text="...",
                ))

        return replacements