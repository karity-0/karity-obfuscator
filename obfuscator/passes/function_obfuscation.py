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
import time

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
    나머지 코드 영역의 *변수 참조* 식별자만 mapping에 따라 치환한다.

    mapping의 key는 원래 식별자 이름, value는 치환될 텍스트
    (예: "_z3" -> "_T1._z3" 혹은 "foo" -> "_T2.foo").

    텍스트 치환은 *변수 참조*와 *필드/키 이름*을 구분해야 한다. pooled 로컬
    `mul`이 있을 때:
      * 필드 접근  `opts.mul`  → `opts._T0.mul` 로 바꾸면 깨진다(치환 금지).
      * 메서드     `obj:mul()` → 메서드 이름이므로 치환 금지.
      * 생성자 키  `{mul=..}`  → `{_T0.mul=..}` 는 문법 오류(치환 금지).
    반면:
      * 연결       `a..mul`    → mul은 변수(치환).
      * 대입 대상  `mul=..` / 다중대입 `a,mul=..` (생성자 밖) → 변수(치환).

    정규식만으로는 `,mul=`가 생성자 키인지 다중대입인지 구분할 수 없어(괄호 문맥
    필요), 괄호 스택을 추적하는 문자 스캐너로 처리한다. 괄호 스택은 `(`/`[`/`{`만
    보며(블록 키워드는 무시), 보호 구간은 내부적으로 괄호가 균형이라 건너뛰어도
    스택 정합성이 유지된다. 생성자 키는 "여는 `{` 또는 top-level `,` 바로 뒤 +
    단일 `=` 앞 + 스택 top이 `{`" 로 판정한다(중첩 함수 안의 대입은 선행 문자가
    `)`/키워드라 자연히 제외된다).
    """
    return _subst_var_refs(text, mapping, _PROTECTED_RE)


def _subst_var_refs(text: str, mapping: dict[str, str], protected_re: re.Pattern) -> str:
    """`_replace_idents_outside_strings`의 코어. 괄호 스택을 추적하는 문자 스캐너로
    *변수 참조* 식별자만 mapping에 따라 치환하고, 필드 접근(`.x`)/메서드(`:x`)/
    테이블 생성자 키(`{x=..}`)는 건너뛴다.

    protected_re: 그대로 복사(스캔 제외)할 구간의 정규식.
      * pooling 치환 → `_PROTECTED_RE`(문자열 + `function(...)` 파라미터 목록).
      * 파라미터 rename → `_STRING_LIT_RE`(문자열만; `function(...)` 파라미터
        선언 자체를 rename해야 하므로 파라미터 목록은 보호하지 않는다).
    """
    if not mapping:
        return text

    out: list[str] = []
    i, L = 0, len(text)
    stack: list[str] = []
    while i < L:
        pm = protected_re.match(text, i)   # 보호 구간은 그대로 복사
        if pm and pm.end() > i:
            out.append(pm.group(0))
            i = pm.end()
            continue
        ch = text[i]
        if ch.isalpha() or ch == '_':
            j = i + 1
            while j < L and (text[j].isalnum() or text[j] == '_'):
                j += 1
            ident = text[i:j]
            if ident in mapping:
                k = i - 1
                while k >= 0 and text[k] in ' \t\r\n':
                    k -= 1
                prev = text[k] if k >= 0 else ''
                prev2 = text[k - 1] if k - 1 >= 0 else ''
                # 필드 접근(단일 `.`)/메서드(`:`). `..`(연결)은 필드가 아니다.
                is_field = (prev == ':') or (prev == '.' and prev2 != '.')
                is_key = False
                if not is_field and stack and stack[-1] == '{' and prev in ('{', ','):
                    p = j
                    while p < L and text[p] in ' \t\r\n':
                        p += 1
                    if p < L and text[p] == '=' and (p + 1 >= L or text[p + 1] != '='):
                        is_key = True
                out.append(ident if (is_field or is_key) else mapping[ident])
            else:
                out.append(ident)
            i = j
            continue
        if ch in '([{':
            stack.append(ch)
        elif ch in ')]}':
            if stack:
                stack.pop()
        out.append(ch)
        i += 1
    return ''.join(out)


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


# ---------------------------------------------------------------------------
# 런타임 값(함수 파라미터 / 상태 변수)에서 파생된 opaque predicate.
#
# 핵심: 단순 상수 tautology(`(a~b)~b==a`)나 값과 무관한 tautology
# (`v==nil or v~=nil`)는 상수 폴딩/단축평가 한 번이면 접힌다. 그래서 여기서는
# *실행 시점 값에 실제로 의존하는 계산을 강제하되 결과는 항상 참/거짓인* 항등식을
# 쓴다. 예: `(v*(v+1))%2==0` — 연속한 두 정수의 곱은 항상 짝수라 언제나 참이지만,
# analyzer는 v의 값에 대한 정수/모듈러 추론 없이는 접을 수 없다.
#
# 정확성 제약:
#   * 이 정수 항등식들은 *정수* 에서만 성립한다(부동소수 3.5 등에선 깨짐).
#     - 상태 변수(kind=="int")는 항상 정수라 무가드로 쓴다.
#     - 파라미터(kind=="num")는 타입 미상이라 `math.type(v)=="integer"` 로
#       가드한다(비-VM 경로 전용; math 전역 사용). 정수가 아니면 산술을 아예
#       평가하지 않고 short-circuit → 타입 안전.
#     - VM 경로 파라미터(kind=="any")는 전역/타입 가정 없이 안전해야 하므로
#       nil 항등식만(폴딩되지만 안전 우선). VM은 상태 변수 int 항등식이 주력.
#   * 사용하는 항등식은 2의 거듭제곱 법(parity/저비트)만 쓴다 → 2의 보수
#     오버플로(mod 2^64)에도 하위 비트/짝홀이 보존돼 maxinteger 근처에서도 성립.
#     (`(v*3)%3==0` 같은 mod-3 류는 오버플로 시 깨지므로 쓰지 않는다.)
# ---------------------------------------------------------------------------

def _int_true_forms(v: str) -> list[str]:
    """정수 v에 대해 항상 참이지만 v에 실제로 의존하는 식들(2의 거듭제곱 법)."""
    return [
        f"(({v}*({v}+1))%2==0)",          # 연속 정수 곱은 짝수
        f"(({v}&1)==({v}%2))",            # 하위 비트 == 홀짝
        f"((({v}~5)&1)==(({v}&1)~1))",    # 홀수와 XOR은 하위 비트를 뒤집음
        f"(({v}|1)%2==1)",                # OR 1 은 홀수
        f"((({v}<<1)&1)==0)",             # 좌시프트 하위 비트는 0
    ]


def _int_false_forms(v: str) -> list[str]:
    """정수 v에 대해 항상 거짓이지만 v에 실제로 의존하는 식들."""
    return [
        f"(({v}*({v}+1))%2==1)",          # 연속 정수 곱은 홀수가 될 수 없음
        f"(({v}|1)%2==0)",                # OR 1 은 짝수가 될 수 없음
        f"(({v}&1)~=({v}%2))",
        f"((({v}<<1)|1)%2==0)",           # 홀수는 짝수가 아님
    ]


def _zero_from(v: str) -> str:
    """정수 v에 실제로 의존하지만 값은 항상 0인 식 (2의 거듭제곱 법 → 오버플로 안전).
    junk 로컬 v를 상태 전이 등에 상쇄 항으로 엮되, `v*0`처럼 단번에 접히지 않게 한다.
    """
    return random.choice([
        f"(({v}*({v}+1))%2)",     # 연속 정수 곱은 짝수 → %2==0
        f"(({v}<<1)&1)",          # 좌시프트 하위 비트 0
        f"(({v}|1)%2-1)",         # 홀수%2 - 1 == 0
    ])


def _one_from(v: str) -> str:
    """정수 v에 실제로 의존하지만 값은 항상 1인 식."""
    return random.choice([
        f"(({v}|1)%2)",           # OR 1 은 홀수 → %2==1
        f"(({v}*({v}+1))%2+1)",   # 짝수 + 1
    ])


def _var_true(name: str, kind: str) -> str:
    """`name`을 참조하지만 항상 참인 식 (kind에 따라 값-의존 강도가 다름)."""
    if kind == "int":
        return random.choice(_int_true_forms(name))
    if kind == "num":   # 파라미터: 정수일 때만 값-의존 항등식, 아니면 short-circuit
        return f"(math.type({name})~=\"integer\" or {random.choice(_int_true_forms(name))})"
    return random.choice([   # kind == "any": VM 경로 안전 폴백(전역 미사용)
        f"({name}==nil or {name}~=nil)",
        f"(not ({name}==nil and {name}~=nil))",
    ])


def _var_false(name: str, kind: str) -> str:
    """`name`을 참조하지만 항상 거짓인 식."""
    if kind == "int":
        return random.choice(_int_false_forms(name))
    if kind == "num":
        return f"(math.type({name})==\"integer\" and {random.choice(_int_false_forms(name))})"
    return random.choice([
        f"({name}==nil and {name}~=nil)",
        f"(not ({name}==nil or {name}~=nil))",
    ])


def _int_live(live_vars):
    """live_vars 중 값-의존 항등식을 쓸 수 있는(int/num) 변수만."""
    return [(n, k) for (n, k) in (live_vars or []) if k in ("int", "num")]


def _pred_true(live_vars=None) -> str:
    """항상 참인 단일 predicate. 값-의존 변수(int/num)가 있으면 높은 확률로 그
    변수에서 파생된 (폴딩 저항) 항등식을 쓰고, 없을 때만 상수 tautology로 폴백."""
    ivs = _int_live(live_vars)
    if ivs and random.random() < 0.85:
        name, kind = random.choice(ivs)
        return _var_true(name, kind)
    if live_vars and random.random() < 0.5:
        name, kind = random.choice(live_vars)
        return _var_true(name, kind)
    return _generic_always_true()


def _pred_false(live_vars=None) -> str:
    """항상 거짓인 단일 predicate (_pred_true와 동일 정책)."""
    ivs = _int_live(live_vars)
    if ivs and random.random() < 0.85:
        name, kind = random.choice(ivs)
        return _var_false(name, kind)
    if live_vars and random.random() < 0.5:
        name, kind = random.choice(live_vars)
        return _var_false(name, kind)
    return _generic_always_false()


def _nested_always_true(depth: int, live_vars=None) -> str:
    """항상 참인 opaque predicate를 depth만큼 논리 결합해 중첩한다.

    `true and true == true`, `true or false == true` 항등식만 사용하므로
    depth와 무관하게 결과는 언제나 참이다. 파서/디컴파일러가 상수 폴딩으로
    소거하기 어렵도록 매 층 서로 다른 상수쌍의 predicate를 섞고, live_vars가
    주어지면 함수 파라미터/상태 변수에서 파생된 predicate도 섞는다.
    """
    expr = _pred_true(live_vars)
    for _ in range(max(0, depth - 1)):
        if random.random() < 0.5:
            expr = f"(({expr}) and ({_pred_true(live_vars)}))"
        else:
            expr = f"(({expr}) or ({_pred_false(live_vars)}))"
    return f"({expr})"


def _nested_always_false(depth: int, live_vars=None) -> str:
    """항상 거짓인 opaque predicate를 depth만큼 논리 결합해 중첩한다.

    `false or false == false`, `false and true == false` 항등식만 사용하므로
    depth와 무관하게 결과는 언제나 거짓이다. 가짜(dead) 분기 가드에 쓴다.
    """
    expr = _pred_false(live_vars)
    for _ in range(max(0, depth - 1)):
        if random.random() < 0.5:
            expr = f"(({expr}) or ({_pred_false(live_vars)}))"
        else:
            expr = f"(({expr}) and ({_pred_true(live_vars)}))"
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


# ---------------------------------------------------------------------------
# 상태값 아핀 인코딩.
#
# 평탄화된 state 값을 원본 분기 개수와 1:1로 매핑되는 작은 정수 그대로 두면
# state transition table만 뽑아 원본 CFG를 그대로 복원할 수 있다. 각 상태를
# 아핀 변환 E(s)=(s*k+b) mod m 으로 인코딩해 *저장은 계산된 값으로* 하고,
# 디스패처의 *비교 시점에만* D(e)=((e-b)*kinv) mod m 으로 역연산한다. 따라서
# 전이 테이블에 남는 상수는 인코딩된 값이라 원본 상태 번호를 직접 드러내지
# 않고, 비교식에도 산술 역연산이 섞여 단순 `sv==const` 패턴 매칭이 깨진다.
#
# m은 소수, k∈[2,m) 은 소수 m과 항상 서로소라 역원이 존재한다. 모든 상태
# id(<10000)와 종료값 0은 m(>1e5)보다 작아 인코딩이 단사(injective)이므로
# 서로 다른 상태는 서로 다른 인코딩 값을 갖고 종료 상태와도 충돌하지 않는다.
# ---------------------------------------------------------------------------
_ENC_PRIMES = (100003, 100019, 100043, 100057, 100069, 100103, 100109, 100129)


class _Affine:
    def __init__(self):
        self.m = random.choice(_ENC_PRIMES)
        self.k = random.randint(2, self.m - 1)
        self.b = random.randint(0, self.m - 1)
        self.kinv = pow(self.k, -1, self.m)   # m 소수 → 항상 존재

    def enc(self, s: int) -> int:
        return (s * self.k + self.b) % self.m

    def enc_expr(self, s: int) -> str:
        """상태 s의 인코딩 값을 (상수 폴딩 방해가 섞인) Lua 정수식으로."""
        return _obf_int(self.enc(s))

    def delta(self, cur: int, nxt: int) -> int:
        """현재 상태 cur에서 다음 상태 nxt로 가는 *상대* XOR 델타.
        `E(cur) ~ E(nxt)`. 전이를 `sv = sv ~ delta` 로 emit하면, sv==E(cur)일 때
        결과가 E(nxt)가 된다. 저장되는 상수는 절대 목적지가 아니라 델타라서,
        전이 테이블만 덤프해도 목적지 상태를 바로 읽을 수 없다(현재 상태의
        런타임 값을 알아야 복원 가능).
        """
        return self.enc(cur) ^ self.enc(nxt)

    def delta_expr(self, cur: int, nxt: int) -> str:
        return _obf_int(self.delta(cur, nxt))

    def dec_expr(self, sv: str) -> str:
        """sv(인코딩 값을 담은 변수)를 원본 상태값으로 역연산하는 Lua 식.
        `((sv-b)*kinv) % m` — Lua의 `%`는 양의 m에 대해 항상 [0,m) 결과라
        (sv-b)가 음수여도 정확하다. |sv-b|<m, kinv<m 이라 곱도 64비트 안전.
        어떤 식 문맥에 넣어도 안전하도록 전체를 괄호로 감싼다.
        """
        inner = f"(({sv})-{_obf_int(self.b)})*{_obf_int(self.kinv)}"
        return f"(({inner})%{self.m})"


_ZV_DECL_RE = re.compile(r'\blocal\s+(_z\d+)\s*=')


def _last_zv(lines: list[str]) -> str | None:
    """lines에서 마지막으로 선언된 `local _zN=` 의 이름을 반환(없으면 None).

    dead 블록의 junk 계산 결과를 상태 전이식에 상쇄 연산(`~(_zN*0)`)으로
    엮어, junk가 순수 로컬 계산이 아니라 상태 변수 계산에 관여하는 것처럼
    보이게 해 dead code elimination이 함부로 못 지우게 하는 데 쓴다.
    """
    last = None
    for ln in lines:
        for m in _ZV_DECL_RE.finditer(ln):
            last = m.group(1)
    return last


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


def _junk_seg_assign(c: list[int], live_vars=None) -> list[str]:
    return [f"local {_zv(c)}={_junk_expr(c)}"]


def _junk_seg_chain(c: list[int], live_vars=None) -> list[str]:
    n = random.randint(2, 4)
    zvs = [_zv(c) for _ in range(n)]
    lines = [f"local {zvs[0]}={_junk_expr(c)}"]
    for i in range(1, n):
        op = random.choice(["+", "-", "~", "*", "%", "|", "&"])
        k = random.randint(1, 9999)
        lines.append(f"local {zvs[i]}={zvs[i - 1]}{op}{k}")
    return lines


def _junk_seg_call(c: list[int], live_vars=None) -> list[str]:
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


def _junk_seg_loop(c: list[int], live_vars=None) -> list[str]:
    fv = f"_fv{random.randint(0, 2 ** 31)}"   # local 없는 for 변수 → pooling 제외
    z = _zv(c)
    return [
        f"local {z}={random.randint(0, 999)}",
        f"for {fv}=1,{random.randint(2, 6)} do",
        f"  {z}={z}+{fv}*{random.randint(1, 9)}",
        f"end",
    ]


def _junk_seg_cond(c: list[int], live_vars=None) -> list[str]:
    z = _zv(c)
    a, b = _generic_const_pair()
    return [
        f"local {z}={a}",
        f"if {_nested_always_false(2, live_vars)} then",
        f"  {z}={b}",
        f"elseif {_pred_false(live_vars)} then",
        f"  {z}={z}~{random.randint(1, 9999)}",
        f"end",
    ]


# --- 아래는 더 다양한 형태의 rich junk (비-VM 경로 전용). 전역 이름 조회 없이
#     동작하도록 설계한다: 테이블 생성자 `{}`/숫자 for/문자열 메타테이블 메서드
#     (`("s"):rep`)/테이블에 담은 클로저. 그래서 localize_globals 와도 안전하고
#     (참조되는 전역이 없음), dead 블록이라 실행되지도 않는다. 각 세그먼트는
#     마지막 줄이 `local _zN=<정수식>` 이라 sink(_last_zv)가 항상 정수다. ---

_JUNK_STR_ALPHABET = "abcdefghijklmnopqrstuvwxyz"


def _rand_str_lit(n: int | None = None) -> str:
    n = n or random.randint(3, 8)
    return '"' + ''.join(random.choice(_JUNK_STR_ALPHABET) for _ in range(n)) + '"'


def _junk_seg_table(c: list[int], live_vars=None) -> list[str]:
    """테이블 생성 + 순회 (전역 미참조: `{}` 생성자와 숫자 for + `#` 만)."""
    t = _zv(c)
    acc = _zv(c)
    fv = f"_fv{random.randint(0, 2 ** 31)}"
    elems = ",".join(_junk_expr(c) for _ in range(random.randint(3, 5)))
    return [
        f"local {t}={{{elems}}}",
        f"local {acc}=0",
        f"for {fv}=1,#{t} do {acc}={acc}~{t}[{fv}] end",
        f"local {_zv(c)}={acc}&0xFFFFFF",
    ]


def _junk_seg_string(c: list[int], live_vars=None) -> list[str]:
    """문자열 조작 후 버리기. 문자열 리터럴의 메타테이블 메서드(`:rep`/`:sub`)와
    `#`/`..` 만 쓰므로 전역 `string` 을 이름으로 조회하지 않는다.
    """
    s = _zv(c)
    s2 = _zv(c)
    return [
        f"local {s}=({_rand_str_lit()}):rep({random.randint(2, 4)})..({_rand_str_lit()})",
        f"local {s2}=({s}):sub({random.randint(1, 3)},#{s})",
        f"local {_zv(c)}=#{s2}+#{s}",
    ]


def _junk_seg_recursion(c: list[int], live_vars=None) -> list[str]:
    """테이블에 담은 클로저로 유한 재귀 (전역 미참조; `local function` 미사용 —
    `local function`은 pooling 스캔 정규식을 교란하므로 테이블 필드에 담는다).
    인자를 매 호출 감소시키고 <=0에서 return → 실행돼도 반드시 종료(dead 전용).
    """
    box = _zv(c)
    p = f"_pa{random.randint(0, 2 ** 31)}"
    return [
        f"local {box}={{}}",
        f"{box}[1]=function({p}) if {p}<=0 then return 0 end return {p}+{box}[1]({p}-1) end",
        f"local {_zv(c)}={box}[1]({random.randint(3, 6)})",
    ]


def _junk_seg_fakevm(c: list[int], live_vars=None) -> list[str]:
    """자체 완결형 가짜 디스패처 — 진짜 상태 머신처럼 보이는 fake state transitions.

    실제 dispatcher와 무관한 shadow 상태 변수를 돌리는 미니 state machine
    (분기 + 루프 + 조기 종료). 반복 가드(`_g<8`)와 종단 상태(0)로 실행돼도 반드시
    종료된다(dead 블록이라 실제 실행은 안 됨). VMP류처럼 더미가 실행 경로처럼
    보이게 하는 핵심 조각. 마지막 줄 `local _zN=<정수>` 이 sink.
    """
    sv = _zv(c); g = _zv(c); acc = _zv(c)
    s0, s1, s2 = (random.randint(1000, 9999) for _ in range(3))
    return [
        f"local {sv}={s0}",
        f"local {g}=0",
        f"local {acc}={random.randint(0, 9999)}",
        f"while {sv}~=0 and {g}<8 do",
        f"  {g}={g}+1",
        f"  if {sv}=={s0} then {acc}={acc}~{random.randint(1, 9999)} {sv}={s1}",
        f"  elseif {sv}=={s1} then {acc}={acc}+{random.randint(1, 999)} {sv}={s2}",
        f"  elseif {sv}=={s2} then {acc}={acc}~{random.randint(1, 9999)} {sv}=0",
        f"  else {sv}=0 end",
        f"end",
        f"local {_zv(c)}={acc}&0xFFFF",
    ]


# 가벼운 세그먼트는 여러 번, 무거운(fakevm/recursion) 세그먼트는 덜 나오도록 가중.
_JUNK_SEGS = (
    _junk_seg_assign, _junk_seg_assign,
    _junk_seg_chain, _junk_seg_chain,
    _junk_seg_call,
    _junk_seg_loop,
    _junk_seg_cond,
    _junk_seg_table,
    _junk_seg_string,
    _junk_seg_recursion,
    _junk_seg_fakevm,
)


def _junk_simple(c: list[int], live_vars=None) -> list[str]:
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
        lines.append(f"if {_pred_false(live_vars)} then local {v2}={zv}~{b} {zv}={v2} end")
    return lines


def _junk_flow(c: list[int], rich: bool = True, live_vars=None,
               n_segs: int | None = None) -> list[str]:
    """가변 길이 그럴듯한 가짜 흐름.

    rich=False면 VM 재난독화용 보수적 흐름(_junk_simple)만 낸다.
    live_vars가 주어지면 내부 opaque predicate가 파라미터/상태값을 섞는다.
    n_segs로 세그먼트 수를 지정할 수 있다(live junk는 비용 제어 위해 1~2로 제한).
    """
    if not rich:
        return _junk_simple(c, live_vars)
    out: list[str] = []
    for _ in range(n_segs if n_segs is not None else random.randint(1, 4)):
        out += random.choice(_JUNK_SEGS)(c, live_vars)
    return out


def _emit_absorbing_junk(emit, level: int, c: list[int], rich: bool, live_vars,
                         absorb_sv: str | None) -> None:
    """항상-거짓 가드 junk 블록(=실행 안 됨)을 emit하고, junk 결과(sink)를 상태
    변수에 무해하게 흡수한다: `sv = sv ~ zero_from(sink)`.

    이건 *정적 분석 교란*용이다: 실행되진 않지만 real case와 형태가 같은 죽은
    분기를 흩뿌려 "어떤 게 진짜 실행 경로인가"를 정적으로 판단하기 어렵게 한다.
    (실제 실행 경로에서 도는 junk는 아래 `_emit_live_junk`가 담당한다.)
    """
    jflow = _junk_flow(c, rich, live_vars)
    sink = _last_zv(jflow)
    emit(level, f"if {_nested_always_false(2, live_vars)} then")
    for jl in jflow:
        emit(level + 1, jl)
    if sink and absorb_sv:
        emit(level + 1, f"{absorb_sv}={absorb_sv}~{_zero_from(sink)}")
    emit(level, "end")


def _emit_live_junk(emit, level: int, c: list[int], rich: bool, live_vars,
                    absorb_sv: str | None, n_segs: int = 2) -> None:
    """*실제 실행 경로*에 그대로(가드 없이) 들어가는 junk (VMP/Themida 스타일 핵심).

    real handler 본문 안에서 조건 없이 실행되며, 결과(sink)를 상태 변수에 *참
    항등식*(`sv = sv ~ zero_from(sink)`)으로 흡수한다. zero_from은 임의 정수
    입력에 대해 *항상 0*이므로(`(x*(x+1))%2` 등, parity) sv는 값이 바뀌지 않아
    실행돼도 정확하고, 동시에:
      * 이 junk는 매번 *실제로 실행*되므로 동적 트레이스에도 진짜 작업처럼 보인다,
      * 결과가 dispatcher 상태 변수 계산에 흘러들어가므로, "output에 영향 없음"을
        증명하려면 zero_from이 항상 0인 이유(parity)까지 data-flow로 파야 한다.
    내부 루프/재귀는 유한 종료가 보장된다(fakevm `_g<8`, 재귀 depth 유한, for 유한).
    return 블록 앞에 놓여도 안전하도록 호출부에서 real code *앞*에 emit한다.
    """
    jflow = _junk_flow(c, rich, live_vars, n_segs=n_segs)
    sink = _last_zv(jflow)
    for jl in jflow:
        emit(level, jl)
    if sink and absorb_sv:
        emit(level, f"{absorb_sv}={absorb_sv}~{_zero_from(sink)}")


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
        # 문자열만 보호(파라미터 선언 자체를 rename해야 하므로 function(...)은
        # 보호하지 않는다). 필드/메서드/생성자 키는 _subst_var_refs가 건너뛰므로
        # 본문의 `obj.mul`/`{mul=..}`가 잘못 rename되지 않는다.
        segment = _subst_var_refs(segment, rename_map, _STRING_LIT_RE)
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


# ---------------------------------------------------------------------------
# 디스패처 스타일 (여러 스타일을 랜덤 선택해 패턴 매칭 자동화를 어렵게 한다).
#
# 셋 다 공통으로:
#   * 상태값은 _Affine 으로 인코딩해 저장(계산된 값), 비교 시점에만 역연산.
#   * dead 블록의 junk sink 변수를 상태 전이식(`~(_zN*0)`)과 (선택적으로)
#     실제 hoist 로컬 계산에 값-보존적으로 엮어 DCE 저항성을 높인다.
#   * opaque predicate는 파라미터/상태값에서 파생된 항목을 섞는다(live).
# ---------------------------------------------------------------------------


def _blocks_have_return(blocks: list[dict]) -> bool:
    """어떤 블록에든 함수를 빠져나가는 return이 있으면 True.

    kind=="return" 뿐 아니라 불투명(goto) 블록의 while/for 본문 속 return,
    prelift된 중첩 함수(`NAME=function...return...end`) 속 return 까지 텍스트로
    보수적으로 잡는다(중첩 함수의 return은 사실 무관하지만, 보수적으로 잡아
    클로저 디스패처를 끄는 편이 안전하다). 문자열 리터럴 내부는 무시한다.
    """
    for blk in blocks:
        if blk["kind"] == "return":
            return True
        if re.search(r'\breturn\b', _strip_protected("\n".join(blk["lines"]))):
            return True
    return False


def _dead_target_pair(pair: dict, all_ids: list[int]) -> tuple[int, int]:
    """dead 블록의 (group, leaf) 전이 대상(인코딩 전 값). 도달 불가라 임의."""
    r = random.random()
    if r < 0.5 and all_ids:
        return pair[random.choice(all_ids)]
    if r < 0.8:
        return random.randint(100, 9999), random.randint(100, 9999)
    return 0, 0


def _dead_target_single(sid: dict, all_ids: list[int]) -> int:
    """dead 블록의 단일 상태 전이 대상(인코딩 전 값)."""
    r = random.random()
    if r < 0.5 and all_ids:
        return sid[random.choice(all_ids)]
    if r < 0.8:
        return random.randint(100, 9999)
    return 0


def _dead_realvar_entangle(hoist_names: list[str], sink: str | None) -> list[str]:
    """dead 블록에서 junk sink 변수를 실제 hoist 로컬 계산에 값-보존적으로 엮는
    라인(선택적).

    `and/or` tautology(`rn=(false) and sink or rn`)는 조건만 접으면 rn으로 폴딩돼
    DCE를 못 막는다. 대신 *실제 rn 값을 사용해 원복시키는 identity 연산*을 쓴다:

        rn = ({rn, sink})[(sink*(sink+1))%2 + 1]

    `{rn, sink}` 는 `[1]=rn, [2]=sink` 테이블이고, 인덱스는 `_one_from(sink)`(항상
    1이지만 sink에 실제로 의존) → 항상 rn을 되돌려준다. 즉 값은 rn 그대로지만:
      * rn 의 실제 값을 테이블에 담았다가 다시 꺼내므로 rn 이 계산에 관여한다,
      * sink 는 테이블 원소이자 인덱스식에도 쓰여 제거 불가,
      * 폴딩하려면 테이블 할당/동적 인덱싱 + parity 추론이 필요.
    타입 불문 안전(rn 임의 타입), 값 불변 → 도달성 가정과 무관하게 안전하다.
    """
    if not hoist_names or not sink or random.random() >= 0.55:
        return []
    rn = random.choice(hoist_names)
    return [f"{rn}=({{{rn},{sink}}})[{_one_from(sink)}]"]


def _branch_updates_flat(cond: str, sv: str, enc: _Affine, cur: int, t: int, e: int,
                         c: list[int]) -> list[str]:
    """단일 상태 branch 갱신 (상대 델타). and/or 삼항과 테이블-셀렉트 중 랜덤.

    전이는 절대값이 아니라 `sv = sv ~ delta` 상대 델타로 쓴다. sv==E(cur)이므로
    `sv ~ (E(cur)~E(t))` == E(t). 저장 상수가 목적지가 아니라 델타라서 전이
    테이블만으론 목적지를 못 읽는다. 델타는 정수(truthy)라 and/or 단축평가도 정확.
    테이블-셀렉트는 and/or 패턴 자체를 없애 원본 if 역변환을 방해한다.
    """
    ism = _zv(c)
    lines = [f"local {ism}=({cond}\n)"]
    dt, de = enc.delta_expr(cur, t), enc.delta_expr(cur, e)
    if random.random() < 0.5:
        s1 = _zv(c)
        lines.append(f"local {s1}={{[true]={dt},[false]={de}}}")
        lines.append(f"{sv}={sv}~{s1}[not not {ism}]")
    else:
        lines.append(f"{sv}={sv}~({ism} and {dt} or {de})")
    return lines


def _branch_updates_nested(cond: str, sv1: str, sv2: str, enc1: _Affine, enc2: _Affine,
                           cur_g: int, cur_b: int, tg: int, tb: int, eg: int, eb: int,
                           c: list[int]) -> list[str]:
    """2차원 상태 branch 갱신 (_branch_updates_flat의 (sv1,sv2) 상대-델타 버전)."""
    ism = _zv(c)
    lines = [f"local {ism}=({cond}\n)"]
    d1t, d1e = enc1.delta_expr(cur_g, tg), enc1.delta_expr(cur_g, eg)
    d2t, d2e = enc2.delta_expr(cur_b, tb), enc2.delta_expr(cur_b, eb)
    if random.random() < 0.5:
        s1 = _zv(c); s2 = _zv(c)
        lines.append(f"local {s1}={{[true]={d1t},[false]={d1e}}}")
        lines.append(f"local {s2}={{[true]={d2t},[false]={d2e}}}")
        lines.append(f"{sv1}={sv1}~{s1}[not not {ism}]")
        lines.append(f"{sv2}={sv2}~{s2}[not not {ism}]")
    else:
        lines.append(f"{sv1}={sv1}~({ism} and {d1t} or {d1e})")
        lines.append(f"{sv2}={sv2}~({ism} and {d2t} or {d2e})")
    return lines


def _emit_dispatch_nested(blocks, entry_id, c, param_vars, rich_junk, hoist_names):
    """계층형 2차원 상태 디스패치: 바깥 group elseif 체인 + 안쪽 leaf elseif 체인.
    (sv1=group, sv2=leaf). 항상-참 래퍼/들여쓰기 지옥 + 항상-거짓 dead 형제 포함.
    """
    sv1 = _zv(c); sv2 = _zv(c)
    enc1 = _Affine(); enc2 = _Affine()
    live = list(param_vars) + [(sv1, "int"), (sv2, "int")]

    used: set[int] = {0}
    group_ids = [_new_state(used) for _ in range(random.randint(2, 4))]

    pair: dict[int, tuple[int, int]] = {0: (0, 0)}
    for blk in blocks:
        blk["g"] = random.choice(group_ids)
        blk["b"] = _new_state(used)
        pair[blk["id"]] = (blk["g"], blk["b"])
    entry_g, entry_b = pair[entry_id]

    real_meta: list[dict] = []
    for blk in blocks:
        kind = blk["kind"]
        cg, cb = blk["g"], blk["b"]
        if kind == "return":
            updates = []
        elif kind == "goto":
            ng, nb = pair[blk["succ"]]
            # 상대 델타 전이: sv==E(cur)이므로 sv~(E(cur)~E(next))==E(next).
            updates = [f"{sv1}={sv1}~{enc1.delta_expr(cg, ng)} {sv2}={sv2}~{enc2.delta_expr(cb, nb)}"]
        else:  # branch
            tg, tb = pair[blk["t"]]
            eg, eb = pair[blk["e"]]
            updates = _branch_updates_nested(blk["cond"], sv1, sv2, enc1, enc2,
                                             cg, cb, tg, tb, eg, eb, c)
        real_meta.append({"g": cg, "b": cb, "lines": blk["lines"], "updates": updates, "real": True})

    all_ids = [blk["id"] for blk in blocks]
    n_dead = random.randint(len(real_meta), len(real_meta) * 2 + 1)
    dead_meta: list[dict] = []
    for _ in range(n_dead):
        dg, db = random.choice(group_ids), _new_state(used)   # dead 블록 자신의 상태 먼저 확정
        jl = _junk_flow(c, rich_junk, live)
        tg, tb = _dead_target_pair(pair, all_ids)
        sink = _last_zv(jl)
        # dead도 상대 델타로 전이(도달 불가라 무해). junk sink 를 값-의존 0 항
        # (_zero_from: 항상 0이지만 sink에 실제로 의존)으로 델타에 엮어 DCE 방해.
        weave = f"~{_zero_from(sink)}" if sink else ""
        updates = _dead_realvar_entangle(hoist_names, sink) + [
            f"{sv1}={sv1}~{enc1.delta_expr(dg, tg)}{weave} {sv2}={sv2}~{enc2.delta_expr(db, tb)}"]
        dead_meta.append({"g": dg, "b": db, "lines": jl, "updates": updates, "real": False})

    groups: dict[int, list[dict]] = {g: [] for g in group_ids}
    for m in real_meta + dead_meta:
        groups[m["g"]].append(m)
    for g in groups:
        random.shuffle(groups[g])
    ordered_groups = [g for g in group_ids if groups[g]]
    random.shuffle(ordered_groups)

    lines: list[str] = []

    def emit(level, s):
        lines.append("  " * level + s)

    emit(0, f"local {sv1}={enc1.enc_expr(entry_g)}")
    emit(0, f"local {sv2}={enc2.enc_expr(entry_b)}")
    emit(0, f"while {sv1}~={enc1.enc_expr(0)} or {sv2}~={enc2.enc_expr(0)} do")

    for gi, g in enumerate(ordered_groups):
        gkw = "if" if gi == 0 else "elseif"
        emit(1, f"{gkw} {enc1.dec_expr(sv1)}=={g} then")
        n_wrap = random.randint(1, 2)
        for w in range(n_wrap):
            emit(2 + w, f"if {_nested_always_true(2, live)} then")
        base = 2 + n_wrap
        for li, m in enumerate(groups[g]):
            lkw = "if" if li == 0 else "elseif"
            emit(base, f"{lkw} {enc2.dec_expr(sv2)}=={m['b']} then")
            n_inner = random.randint(0, 2)
            for x in range(n_inner):
                emit(base + 1 + x, f"if {_nested_always_true(2, live)} then")
            bb = base + 1 + n_inner
            # real case 안에 junk 인터리빙(항상 real code *앞*에 — return 블록은
            # 본문 마지막이 return이라 뒤에 문장을 두면 문법 오류). 위치가 더 이상
            # "루프 끝 고정"이 아니게 되어 위치만으로 더미를 거르기 어려워진다.
            if rich_junk and m["real"] and random.random() < 0.85:
                _emit_live_junk(emit, bb, c, rich_junk, live, sv2)   # 실제 실행되는 junk
            if random.random() < 0.35:
                _emit_absorbing_junk(emit, bb, c, rich_junk, live, sv2)   # 정적 교란(dead)
            for ln in m["lines"]:
                emit(bb, ln)
            for u in m["updates"]:
                emit(bb, u)
            for x in reversed(range(n_inner)):
                emit(base + 1 + x, "end")
        emit(base, "end")
        for w in reversed(range(n_wrap)):
            emit(2 + w, "end")
        # 그룹 내부 가짜 dead 형제: 개수를 랜덤화(0~2)해 위치/개수 시그니처를 흐린다.
        for _ in range(random.randint(0, 2)):
            _emit_absorbing_junk(emit, 2, c, rich_junk, live, sv1)

    emit(1, "end")
    for _ in range(random.randint(1, 2)):
        _emit_absorbing_junk(emit, 1, c, rich_junk, live, sv1)
    emit(0, "end")
    return lines


def _emit_dispatch_flat(blocks, entry_id, c, param_vars, rich_junk, hoist_names):
    """평면 단일-상태 디스패치: 하나의 sv에 대한 단일 elseif 체인.
    (계층형과 다른 텍스트 형태 → 디스패처 패턴 다양화.)
    """
    sv = _zv(c)
    enc = _Affine()
    live = list(param_vars) + [(sv, "int")]

    used: set[int] = {0}
    sid: dict[int, int] = {0: 0}
    for blk in blocks:
        blk["s"] = _new_state(used)
        sid[blk["id"]] = blk["s"]
    entry_s = sid[entry_id]

    real_meta: list[dict] = []
    for blk in blocks:
        kind = blk["kind"]
        cur = blk["s"]
        if kind == "return":
            updates = []
        elif kind == "goto":
            updates = [f"{sv}={sv}~{enc.delta_expr(cur, sid[blk['succ']])}"]
        else:
            updates = _branch_updates_flat(blk["cond"], sv, enc, cur,
                                           sid[blk["t"]], sid[blk["e"]], c)
        real_meta.append({"s": cur, "lines": blk["lines"], "updates": updates, "real": True})

    all_ids = [blk["id"] for blk in blocks]
    n_dead = random.randint(len(real_meta), len(real_meta) * 2 + 1)
    dead_meta: list[dict] = []
    for _ in range(n_dead):
        ds = _new_state(used)                 # dead 블록 자신의 상태 먼저 확정
        jl = _junk_flow(c, rich_junk, live)
        sink = _last_zv(jl)
        weave = f"~{_zero_from(sink)}" if sink else ""
        u = f"{sv}={sv}~{enc.delta_expr(ds, _dead_target_single(sid, all_ids))}{weave}"
        updates = _dead_realvar_entangle(hoist_names, sink) + [u]
        dead_meta.append({"s": ds, "lines": jl, "updates": updates, "real": False})

    metas = real_meta + dead_meta
    random.shuffle(metas)

    lines: list[str] = []

    def emit(level, s):
        lines.append("  " * level + s)

    emit(0, f"local {sv}={enc.enc_expr(entry_s)}")
    emit(0, f"while {sv}~={enc.enc_expr(0)} do")
    n_wrap = random.randint(0, 2)
    for w in range(n_wrap):
        emit(1 + w, f"if {_nested_always_true(2, live)} then")
    base = 1 + n_wrap
    for i, m in enumerate(metas):
        kw = "if" if i == 0 else "elseif"
        emit(base, f"{kw} {enc.dec_expr(sv)}=={m['s']} then")
        n_inner = random.randint(0, 2)
        for x in range(n_inner):
            emit(base + 1 + x, f"if {_nested_always_true(2, live)} then")
        bb = base + 1 + n_inner
        # real case *앞*에 junk 인터리빙(return 블록 뒤에 문장 두면 문법 오류이므로 앞).
        if rich_junk and m["real"] and random.random() < 0.85:
            _emit_live_junk(emit, bb, c, rich_junk, live, sv)   # 실제 실행되는 junk
        if random.random() < 0.35:
            _emit_absorbing_junk(emit, bb, c, rich_junk, live, sv)   # 정적 교란(dead)
        for ln in m["lines"]:
            emit(bb, ln)
        for u in m["updates"]:
            emit(bb, u)
        for x in reversed(range(n_inner)):
            emit(base + 1 + x, "end")
    emit(base, "end")
    for w in reversed(range(n_wrap)):
        emit(1 + w, "end")
    for _ in range(random.randint(1, 2)):
        _emit_absorbing_junk(emit, 1, c, rich_junk, live, sv)
    emit(0, "end")
    return lines


def _emit_dispatch_closure(blocks, entry_id, c, param_vars, rich_junk, hoist_names):
    """테이블 기반 함수-포인터 점프 디스패치.

    각 상태를 테이블 H의 (인코딩된 상태값 키)에 클로저로 담고, 디스패처는
    `(H[sv])()` 로 점프한다. 핸들러가 상태 변수를 upvalue로 갱신한다. 핸들러가
    실행 도중 함수를 빠져나가면(closure의 return) 의미가 깨지므로, 이 디스패처는
    return이 전혀 없는 함수(`_blocks_have_return`==False)에만 쓴다. 테이블에
    동적 인덱싱으로 접근하므로 dead 핸들러도 정적으로는 제거할 수 없다.
    """
    sv = _zv(c); ht = _zv(c)
    enc = _Affine()
    live = list(param_vars) + [(sv, "int")]

    used: set[int] = {0}
    sid: dict[int, int] = {0: 0}
    for blk in blocks:
        blk["s"] = _new_state(used)
        sid[blk["id"]] = blk["s"]
    entry_s = sid[entry_id]

    metas: list[dict] = []
    for blk in blocks:
        cur = blk["s"]
        if blk["kind"] == "goto":
            # 핸들러는 sv==E(cur)일 때만 (H[sv]로) 진입하므로 상대 델타가 정확.
            updates = [f"{sv}={sv}~{enc.delta_expr(cur, sid[blk['succ']])}"]
        else:  # branch (return 블록 없음이 보장됨)
            updates = _branch_updates_flat(blk["cond"], sv, enc, cur,
                                           sid[blk["t"]], sid[blk["e"]], c)
        metas.append({"s": cur, "lines": blk["lines"], "updates": updates, "real": True})

    all_ids = [blk["id"] for blk in blocks]
    n_dead = random.randint(len(metas), len(metas) * 2 + 1)
    for _ in range(n_dead):
        ds = _new_state(used)
        jl = _junk_flow(c, rich_junk, live)
        sink = _last_zv(jl)
        weave = f"~{_zero_from(sink)}" if sink else ""
        u = f"{sv}={sv}~{enc.delta_expr(ds, _dead_target_single(sid, all_ids))}{weave}"
        updates = _dead_realvar_entangle(hoist_names, sink) + [u]
        metas.append({"s": ds, "lines": jl, "updates": updates, "real": False})

    random.shuffle(metas)

    lines: list[str] = []

    def emit(level, s):
        lines.append("  " * level + s)

    emit(0, f"local {sv}={enc.enc_expr(entry_s)}")
    emit(0, f"local {ht}={{}}")
    for m in metas:
        emit(0, f"{ht}[{enc.enc_expr(m['s'])}]=function()")
        # 핸들러는 return이 없으므로(클로저 디스패처 전제) junk 인터리빙이 어디든
        # 안전하지만, 일관성 위해 본문 앞에 둔다. real 핸들러엔 실제 실행되는
        # live junk을, 그와 별개로 정적 교란용 dead junk을 섞는다.
        if rich_junk and m["real"] and random.random() < 0.85:
            _emit_live_junk(emit, 1, c, rich_junk, live, sv)
        if random.random() < 0.35:
            _emit_absorbing_junk(emit, 1, c, rich_junk, live, sv)
        for ln in m["lines"]:
            emit(1, ln)
        for u in m["updates"]:
            emit(1, u)
        emit(0, "end")
    emit(0, f"while {sv}~={enc.enc_expr(0)} do")
    emit(1, f"if {_nested_always_true(2, live)} then")
    emit(2, f"({ht}[{sv}])()")
    emit(1, "end")
    for _ in range(random.randint(1, 2)):
        _emit_absorbing_junk(emit, 1, c, rich_junk, live, sv)
    emit(0, "end")
    return lines


def _build_generic_cff(blocks: list[dict], entry_id: int, c: list[int],
                       extra_hoist_names: list[str] | None = None,
                       rich_junk: bool = True,
                       param_names: list[str] | None = None) -> str:
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

    # 디스패처 스타일을 랜덤 선택한다 (패턴 매칭 자동화 방해). 계층형/평면은
    # 항상 가능하고, 테이블-클로저 점프는 return이 없는 함수 + rich junk(비-VM)
    # 경로에서만 안전하게 쓴다(클로저의 return이 함수를 못 빠져나가므로).
    #
    # 파라미터 opaque predicate: 비-VM(rich_junk)에서는 `math.type` 가드 + 값-의존
    # 정수 항등식("num")을 쓴다. VM 경로(제한 _ENV)에서는 math 전역이 위험하므로
    # 파라미터를 predicate에서 빼고(상태 변수 int 항등식만 사용) 안전을 택한다.
    #
    # 단, 파라미터/로컬 중 `math`가 있으면 함수 스코프에서 전역 `math`가 가려져
    # `math.type(...)`이 그 값을 인덱싱하다 깨질 수 있다 → 이 경우 파라미터는
    # 전역 미사용 안전 폴백("any", nil 항등식)으로 낮춘다. 상태 변수 int 항등식은
    # math를 안 쓰므로 항상 안전하다.
    if not rich_junk:
        param_vars = []
    else:
        shadowed = ("math" in (param_names or [])) or ("math" in hoist_names)
        pkind = "any" if shadowed else "num"
        param_vars = [(p, pkind) for p in (param_names or [])]
    emitters = [_emit_dispatch_nested, _emit_dispatch_flat]
    if rich_junk and not _blocks_have_return(blocks):
        emitters.append(_emit_dispatch_closure)
    emitter = random.choice(emitters)
    lines = emitter(blocks, entry_id, c, param_vars, rich_junk, hoist_names)

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

    # Collect declarations from the original function scope before lowering
    # branches into detached state blocks.  The textual block scan performed
    # by _build_generic_cff is still useful as a fallback, but declarations
    # following semicolon-separated statements inside an if branch can
    # otherwise remain branch-local after flattening.  Once another state
    # reads such a name Lua resolves it as a global (usually nil).
    #
    # Do not descend into nested functions: their locals belong to a different
    # lexical scope and must not be hoisted into this function.
    scope_local_names: set[str] = set()
    pending = list(block.children)
    while pending:
        current = pending.pop()
        if current.type in _FUNC_NODE_TYPES:
            continue
        if current.type == "variable_declaration":
            scope_local_names.update(_scan_local_names(ctx.text(current)))
            continue
        pending.extend(current.children)

    extra_hoist_names: list[str] = sorted(scope_local_names)
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

    cff = _build_generic_cff(blocks, entry, c, extra_hoist_names, rich_junk=rich_junk,
                             param_names=params)
    return "\n".join(prefix_lines + [cff])


# VM 디스패처(exec) 식별용 sentinel. exec의 dispatch 루프
# `for i in setmetatable({},{__call=function(t)return t end}) do` 에만 등장하며,
# `__call`은 VM 템플릿 전체에서 이 한 곳에서만 쓰이는 메타메서드 키다
# (사용자 코드는 bytecode로 blob에 들어가므로 VM 텍스트에 나타나지 않는다).
# rename/number/string 난독화에도 살아남는다(`__call`은 테이블 필드 키,
# `function`은 키워드).
_DISPATCH_SENTINEL = re.compile(r'__call\s*=\s*function')
_VM_HOT_LOOP_SENTINEL = re.compile(r'__VM_HOT_LOOP__')


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
        self.last_transformed_count = 0

    def run(self, script: str, ctx) -> list[Replacement]:
        replacements: list[Replacement] = []
        scan_start = time.perf_counter()
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
            sentinel_spans = [
                (match.start(), match.end() - 1)
                for pattern in (_DISPATCH_SENTINEL, _VM_HOT_LOOP_SENTINEL)
                for match in pattern.finditer(script)
            ]
            function_spans = []
            for candidate in func_nodes:
                candidate_block = _block_of(candidate)
                if candidate_block is not None:
                    function_spans.append((
                        ctx.cs(candidate_block), ctx.ce(candidate_block),
                        candidate.id,
                    ))
            for start, end in sentinel_spans:
                owners = [
                    span for span in function_spans
                    if span[0] <= start and end <= span[1]
                ]
                if owners:
                    skip_node_ids.add(min(
                        owners, key=lambda span: span[1] - span[0]
                    )[2])

        self.last_candidate_count = len(func_nodes)
        self.last_skipped_dispatcher_count = len(skip_node_ids)
        self.last_candidate_scan_elapsed = time.perf_counter() - scan_start
        transform_start = time.perf_counter()

        for node in func_nodes:
            block = _block_of(node)
            if block is None:
                continue
            bstart, bend = ctx.cs(block), ctx.ce(block)

            if self.skip_vm_dispatcher and node.id in skip_node_ids:
                # sentinel을 직접 포함하는 함수(wrapper/exec) 자체만 스킵.
                # exec 내부의 헬퍼 클로저는 아래에서 정상 변환된다.
                continue

            if self.skip_vm_dispatcher:
                # Handler-graph backends are emitted as functions inside dense
                # table banks and already carry compiler-generated control
                # flow. Running generic CFF over those closures is both
                # redundant and unsafe for their integer-only paths. This does
                # not exclude ordinary local helpers nested in the dispatcher.
                ancestor = node.parent
                in_table_bank = False
                while ancestor is not None and ancestor.type not in _FUNC_NODE_TYPES:
                    if ancestor.type == "table_constructor":
                        in_table_bank = True
                        break
                    ancestor = ancestor.parent
                if in_table_bank:
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

        self.last_transformed_count = len(claimed_ranges)
        self.last_transform_elapsed = time.perf_counter() - transform_start
        return replacements
