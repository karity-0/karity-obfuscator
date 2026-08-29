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
from bisect import bisect_left
from dataclasses import dataclass
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

# Lua 5.3 reserved words. These can never be variable identifiers.
# Text-level pooling must therefore never collect or substitute them.
_LUA_KEYWORDS = {
    "and", "break", "do", "else", "elseif", "end", "false", "for",
    "function", "goto", "if", "in", "local", "nil", "not", "or",
    "repeat", "return", "then", "true", "until", "while",
}

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
_FUNC_PARAMS_SPAN_RE = re.compile(
    r'\bfunction'
    r'(?:\s+[A-Za-z_]\w*(?:[.:][A-Za-z_]\w*)*)?'
    r'\s*'
    r'\(([^)]*)\)'
)

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

def _strip_strings_only(text: str) -> str:
    """문자열 리터럴만 같은 길이의 공백으로 마스킹한다.

    함수 본문 경계 탐색처럼 `function` 키워드 자체를 세어야 하는 스캐너에서
    `_strip_protected()`를 쓰면 `function(...)` 시그니처까지 지워져 nested
    function의 depth가 깨질 수 있으므로 이 helper를 별도로 사용한다.
    """
    return _STRING_LIT_RE.sub(lambda m: ' ' * len(m.group(0)), text)



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
            if ident in mapping and ident not in _LUA_KEYWORDS:
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
    r'\blocal\s+(?!function\b)'
    r'((?:[A-Za-z_]\w*\s*,\s*)*[A-Za-z_]\w*)(\s*=)?'
)

_FOR_BINDING_RE = re.compile(
    r'\bfor\s+'
    r'([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)'
    r'\s*(?:=|\bin\b)'
)


def _scan_for_binding_names(text: str) -> set[str]:
    """numeric/generic for가 선언하는 lexical local 이름을 수집한다.

    보호 구간을 공백으로 마스킹한 뒤 전체 텍스트를 regex로 스캔하면,
    보호 구간 양옆의 토큰이 가짜로 이어질 수 있다. 예를 들어 어떤
    `function(...)` 시그니처가 통째로 공백이 되면서 앞의 `for`와 뒤쪽
    identifier가 하나의 문법 구조처럼 보일 수 있다.

    따라서 보호 구간 사이의 실제 code chunk를 각각 독립적으로 스캔한다.
    """
    names: set[str] = set()

    def _collect(part: str) -> str:
        for m in _FOR_BINDING_RE.finditer(part):
            for name in m.group(1).split(','):
                name = name.strip()
                if name and name not in _LUA_KEYWORDS:
                    names.add(name)
        return part

    _apply_outside_protected(text, _collect)
    return names


def _scan_local_names(text: str) -> set[str]:
    """text 안의 실제 `local NAME[,NAME...]` 선언 이름만 수집한다.

    중요: 보호 구간을 공백으로 바꾼 하나의 문자열에서 regex를 돌리지 않는다.
    `local function foo(...)`의 function 시그니처가 마스킹되면:

        local                  while ...

    같은 가짜 토큰 연결이 생겨 `while`/`local` 같은 Lua keyword가 local
    이름으로 오인될 수 있기 때문이다.

    보호 구간 사이의 code chunk를 독립적으로 스캔하면 이런 cross-boundary
    오탐이 구조적으로 불가능하다.
    """
    names: set[str] = set()

    def _collect(part: str) -> str:
        for m in _LOCAL_DECL_RE.finditer(part):
            for name in m.group(1).split(','):
                name = name.strip()
                if name and name not in _LUA_KEYWORDS:
                    names.add(name)
        return part

    _apply_outside_protected(text, _collect)
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
# Phase 2: AST lexical-binding resolver
# ---------------------------------------------------------------------------
#
# 이전 table pooling은 식별자 *문자열*을 identity로 사용했다. 따라서 서로 다른
# lexical scope의 `local v`가 모두 같은 `_Tn.v`로 합쳐질 수 있었고, nested
# function의 per-call local까지 바깥 table field가 되어 semantics가 깨졌다.
#
# 여기서는 CFF를 만들기 전에 tree-sitter AST에서 각 local binding에 고유한
# alpha-name을 부여한다. 이후 text-level CFF/pooling은 이 고유 이름만 보므로
# 같은 철자의 서로 다른 binding을 절대 합치지 않는다.
#
# 더 중요한 점은 모든 local을 hoist하지 않는다는 것이다.
# `_compile_stmts_to_blocks()`가 실제로 분해하는 범위(root block + if/elseif/else
# branch)에서 선언된 binding만 poolable/hoist 대상으로 표시한다.
#
# while/for/repeat/do 및 nested function은 CFF에서 하나의 opaque statement로
# 유지되므로, 그 안에서 선언된 local은 원래 lexical scope에 그대로 남는다.
# nested function이 바깥 binding을 capture하는 경우에는 resolver가 그 참조만
# 바깥 binding의 alpha-name으로 바꾸므로, 이후 table mapping이 정확한 upvalue
# reference만 `_Tn._bN`으로 연결한다.


@dataclass(frozen=True)
class _LexBinding:
    original: str
    alpha: str
    kind: str
    poolable: bool
    owner_function_id: int


@dataclass
class _LexicalPlan:
    replacements: list[tuple[int, int, str]]
    starts: list[int]
    root_param_names: list[str]
    poolable_names: list[str]
    bindings: list[_LexBinding]


class _LexScope:
    __slots__ = ("parent", "names")

    def __init__(self, parent: "_LexScope | None" = None):
        self.parent = parent
        self.names: dict[str, _LexBinding] = {}

    def bind(self, binding: _LexBinding) -> None:
        self.names[binding.original] = binding

    def resolve(self, name: str) -> _LexBinding | None:
        scope: _LexScope | None = self
        while scope is not None:
            hit = scope.names.get(name)
            if hit is not None:
                return hit
            scope = scope.parent
        return None


def _ts_field_children(node, field_name: str) -> list:
    out = []
    for i, child in enumerate(node.children):
        if node.field_name_for_child(i) == field_name:
            out.append(child)
    return out


def _ts_field_name(parent, child) -> str | None:
    cid = getattr(child, "id", None)
    for i, candidate in enumerate(parent.children):
        if candidate is child or (
            cid is not None and getattr(candidate, "id", None) == cid
        ):
            return parent.field_name_for_child(i)
    return None


def _binding_prefix(script: str) -> str:
    prefix = "__KLB"
    while prefix in script:
        prefix += "X"
    return prefix


class _LexicalPlanner:
    def __init__(self, ctx, root_function):
        self.ctx = ctx
        self.root_function = root_function
        self.prefix = _binding_prefix(ctx.script)
        self.counter = 0
        self.replacement_by_span: dict[tuple[int, int], str] = {}
        self.bindings: list[_LexBinding] = []
        self.poolable_names: list[str] = []
        self.root_param_names: list[str] = []

    def _owner_id(self, node) -> int:
        return int(getattr(node, "id", id(node)))

    def _new_binding(
        self,
        name: str,
        kind: str,
        poolable: bool,
        owner_function,
        decl_node=None,
        *,
        fixed_alpha: str | None = None,
    ) -> _LexBinding:
        if fixed_alpha is None:
            alpha = f"{self.prefix}{self.counter}"
            self.counter += 1
        else:
            alpha = fixed_alpha

        binding = _LexBinding(
            original=name,
            alpha=alpha,
            kind=kind,
            poolable=poolable,
            owner_function_id=self._owner_id(owner_function),
        )
        self.bindings.append(binding)

        if poolable and alpha not in self.poolable_names:
            self.poolable_names.append(alpha)

        if decl_node is not None and alpha != name:
            self._record(decl_node, alpha)

        return binding

    def _record(self, node, replacement: str) -> None:
        s = self.ctx.cs(node)
        e = self.ctx.ce(node) + 1
        key = (s, e)
        previous = self.replacement_by_span.get(key)
        if previous is not None and previous != replacement:
            raise RuntimeError(
                "lexical binding resolver produced conflicting replacement "
                f"at {s}:{e}: {previous!r} vs {replacement!r}"
            )
        self.replacement_by_span[key] = replacement

    def _record_reference(self, node, scope: _LexScope) -> None:
        name = self.ctx.text(node)
        binding = scope.resolve(name)
        if binding is not None and binding.alpha != name:
            self._record(node, binding.alpha)

    def _identifier_is_reference(self, node) -> bool:
        parent = node.parent
        if parent is None:
            return True

        field = _ts_field_name(parent, node)

        if parent.type == "dot_index_expression" and field == "field":
            return False
        if parent.type == "method_index_expression" and field == "method":
            return False

        if parent.type == "field" and field == "name":
            ptxt = self.ctx.text(parent).lstrip()
            if not ptxt.startswith("["):
                return False

        if parent.type in ("attribute", "goto_statement", "label_statement"):
            return False

        if parent.type == "parameters":
            return False

        return True

    def _walk_generic(
        self,
        node,
        scope: _LexScope,
        owner_function,
        cff_visible: bool,
    ) -> None:
        typ = node.type

        if typ == "identifier":
            if self._identifier_is_reference(node):
                self._record_reference(node, scope)
            return

        if typ == "function_definition":
            self._walk_function(node, scope, is_root=False)
            return

        if typ == "function_declaration":
            self._walk_function_declaration(
                node, scope, owner_function, cff_visible
            )
            return
        if typ == "variable_declaration":
            self._walk_variable_declaration(
                node, scope, owner_function, cff_visible
            )
            return

        if typ in ("string", "string_content", "comment", "comment_content"):
            return

        for child in node.children:
            if child.is_named:
                self._walk_generic(
                    child, scope, owner_function, cff_visible
                )

    def _declaration_names(self, varlist) -> list:
        """`variable_list`가 선언하는 identifier들을 source order로 반환.

        tree-sitter-lua의 `variable_list`는 변수 이름에 `name:` field를 붙이지
        않고 positional named child로 둔다. 따라서 field 기반으로 읽으면
        `local x`, `local a,b`, `for k,v in ...` 선언을 전부 놓친다.
        """
        if varlist is None:
            return []

        return [
            child
            for child in varlist.children
            if child.is_named and child.type == "identifier"
        ]

    def _walk_variable_declaration(
        self,
        node,
        scope: _LexScope,
        owner_function,
        cff_visible: bool,
    ) -> None:
        assignment = next(
            (c for c in node.children if c.type == "assignment_statement"),
            None,
        )

        if assignment is not None:
            exprlist = next(
                (c for c in assignment.children if c.type == "expression_list"),
                None,
            )
            if exprlist is not None:
                self._walk_generic(
                    exprlist, scope, owner_function, cff_visible
                )
            varlist = next(
                (c for c in assignment.children if c.type == "variable_list"),
                None,
            )
        else:
            varlist = next(
                (c for c in node.children if c.type == "variable_list"),
                None,
            )

        decl_names = self._declaration_names(varlist)

        # `local` declaration인데 identifier를 못 읽으면 조용히 계속하지 않는다.
        # 이 상태로 CFF를 만들면 선언 state 밖의 reference가 global/nil로 바뀌어
        # 문법검사는 통과하고 런타임에서만 깨진다.
        if varlist is not None and not decl_names:
            vtxt = self.ctx.text(varlist).strip()
            if re.search(r"[A-Za-z_]\\w*", vtxt):
                raise RuntimeError(
                    "function_obf lexical resolver could not read "
                    f"local variable_list: {vtxt!r}"
                )

        pending: list[_LexBinding] = []
        for name_node in decl_names:
            name = self.ctx.text(name_node)
            pending.append(self._new_binding(
                name,
                kind="local",
                poolable=cff_visible,
                owner_function=owner_function,
                decl_node=name_node,
            ))

        for binding in pending:
            scope.bind(binding)

    def _walk_function_target(
        self,
        node,
        scope: _LexScope,
        owner_function,
    ) -> None:
        if node is None:
            return
        if node.type == "identifier":
            self._record_reference(node, scope)
            return

        if node.type in ("dot_index_expression", "method_index_expression"):
            table_node = node.child_by_field_name("table")
            if table_node is not None:
                self._walk_generic(
                    table_node, scope, owner_function, False
                )
            return

        self._walk_generic(node, scope, owner_function, False)

    def _walk_function_declaration(
        self,
        node,
        scope: _LexScope,
        owner_function,
        cff_visible: bool,
    ) -> None:
        name_node = node.child_by_field_name("name")
        is_local = (
            bool(node.children)
            and node.children[0].type == "local"
        )

        if is_local and name_node is not None and name_node.type == "identifier":
            binding = self._new_binding(
                self.ctx.text(name_node),
                kind="local_function",
                poolable=cff_visible,
                owner_function=owner_function,
                decl_node=name_node,
            )
            scope.bind(binding)
        else:
            self._walk_function_target(
                name_node, scope, owner_function
            )

        self._walk_function(node, scope, is_root=False)

    def _walk_function(
        self,
        node,
        outer_scope: _LexScope,
        *,
        is_root: bool,
    ) -> None:
        fscope = _LexScope(outer_scope)

        name_node = (
            node.child_by_field_name("name")
            if node.type == "function_declaration"
            else None
        )

        if name_node is not None and name_node.type == "method_index_expression":
            fscope.bind(self._new_binding(
                "self",
                kind="implicit_param",
                poolable=False,
                owner_function=node,
                fixed_alpha="self",
            ))

        params = node.child_by_field_name("parameters")
        if params is not None:
            for pnode in _ts_field_children(params, "name"):
                if pnode.type != "identifier":
                    continue
                binding = self._new_binding(
                    self.ctx.text(pnode),
                    kind="param",
                    poolable=False,
                    owner_function=node,
                    decl_node=pnode,
                )
                fscope.bind(binding)
                if is_root:
                    self.root_param_names.append(binding.alpha)

        body = node.child_by_field_name("body")
        if body is not None:
            self._walk_block(
                body,
                fscope,
                owner_function=node,
                cff_visible=is_root,
            )

    def _walk_if(
        self,
        node,
        scope: _LexScope,
        owner_function,
        cff_visible: bool,
    ) -> None:
        cond = node.child_by_field_name("condition")
        if cond is not None:
            self._walk_generic(
                cond, scope, owner_function, cff_visible
            )

        consequence = node.child_by_field_name("consequence")
        if consequence is not None:
            self._walk_block(
                consequence,
                _LexScope(scope),
                owner_function,
                cff_visible,
            )

        for alt in _ts_field_children(node, "alternative"):
            if alt.type == "elseif_statement":
                acond = alt.child_by_field_name("condition")
                if acond is not None:
                    self._walk_generic(
                        acond, scope, owner_function, cff_visible
                    )
                abody = alt.child_by_field_name("consequence")
                if abody is not None:
                    self._walk_block(
                        abody,
                        _LexScope(scope),
                        owner_function,
                        cff_visible,
                    )
            elif alt.type == "else_statement":
                abody = alt.child_by_field_name("body")
                if abody is not None:
                    self._walk_block(
                        abody,
                        _LexScope(scope),
                        owner_function,
                        cff_visible,
                    )

    def _walk_for(
        self,
        node,
        scope: _LexScope,
        owner_function,
    ) -> None:
        clause = node.child_by_field_name("clause")
        body = node.child_by_field_name("body")

        if clause is None:
            if body is not None:
                self._walk_block(
                    body, _LexScope(scope), owner_function, False
                )
            return

        loop_scope = _LexScope(scope)

        if clause.type == "for_numeric_clause":
            for fname in ("start", "end", "step"):
                expr = clause.child_by_field_name(fname)
                if expr is not None:
                    self._walk_generic(
                        expr, scope, owner_function, False
                    )

            name_node = clause.child_by_field_name("name")
            if name_node is not None and name_node.type == "identifier":
                binding = self._new_binding(
                    self.ctx.text(name_node),
                    kind="for",
                    poolable=False,
                    owner_function=owner_function,
                    decl_node=name_node,
                )
                loop_scope.bind(binding)

        elif clause.type == "for_generic_clause":
            exprlist = next(
                (c for c in clause.children if c.type == "expression_list"),
                None,
            )
            if exprlist is not None:
                self._walk_generic(
                    exprlist, scope, owner_function, False
                )

            varlist = next(
                (c for c in clause.children if c.type == "variable_list"),
                None,
            )
            binder_nodes = self._declaration_names(varlist)
            if varlist is not None and not binder_nodes:
                vtxt = self.ctx.text(varlist).strip()
                if re.search(r"[A-Za-z_]\\w*", vtxt):
                    raise RuntimeError(
                        "function_obf lexical resolver could not read "
                        f"generic-for variable_list: {vtxt!r}"
                    )

            pending = []
            for name_node in binder_nodes:
                pending.append(self._new_binding(
                    self.ctx.text(name_node),
                    kind="for",
                    poolable=False,
                    owner_function=owner_function,
                    decl_node=name_node,
                ))
            for binding in pending:
                loop_scope.bind(binding)

        if body is not None:
            self._walk_block(
                body, loop_scope, owner_function, False
            )

    def _walk_statement(
        self,
        node,
        scope: _LexScope,
        owner_function,
        cff_visible: bool,
    ) -> None:
        typ = node.type

        if typ == "variable_declaration":
            self._walk_variable_declaration(
                node, scope, owner_function, cff_visible
            )
            return

        if typ == "function_declaration":
            self._walk_function_declaration(
                node, scope, owner_function, cff_visible
            )
            return

        if typ == "if_statement":
            self._walk_if(
                node, scope, owner_function, cff_visible
            )
            return

        if typ == "for_statement":
            self._walk_for(node, scope, owner_function)
            return

        if typ == "while_statement":
            cond = node.child_by_field_name("condition")
            if cond is not None:
                self._walk_generic(
                    cond, scope, owner_function, False
                )
            body = node.child_by_field_name("body")
            if body is not None:
                self._walk_block(
                    body, _LexScope(scope), owner_function, False
                )
            return

        if typ == "repeat_statement":
            repeat_scope = _LexScope(scope)
            body = node.child_by_field_name("body")
            if body is not None:
                self._walk_block(
                    body, repeat_scope, owner_function, False
                )
            cond = node.child_by_field_name("condition")
            if cond is not None:
                self._walk_generic(
                    cond, repeat_scope, owner_function, False
                )
            return

        if typ == "do_statement":
            body = node.child_by_field_name("body")
            if body is not None:
                self._walk_block(
                    body, _LexScope(scope), owner_function, False
                )
            return

        self._walk_generic(
            node, scope, owner_function, cff_visible
        )

    def _walk_block(
        self,
        block,
        scope: _LexScope,
        owner_function,
        cff_visible: bool,
    ) -> None:
        for stmt in _block_stmts(self.ctx, block):
            self._walk_statement(
                stmt, scope, owner_function, cff_visible
            )

    def build(self) -> _LexicalPlan:
        outer = _LexScope(None)
        self._walk_function(
            self.root_function,
            outer,
            is_root=True,
        )

        replacements = [
            (s, e, value)
            for (s, e), value in self.replacement_by_span.items()
        ]
        replacements.sort(key=lambda item: item[0])

        return _LexicalPlan(
            replacements=replacements,
            starts=[item[0] for item in replacements],
            root_param_names=list(self.root_param_names),
            poolable_names=list(self.poolable_names),
            bindings=list(self.bindings),
        )


def _build_lexical_plan(ctx, function_node) -> _LexicalPlan:
    return _LexicalPlanner(ctx, function_node).build()


def _rewrite_range_with_plan(
    ctx,
    start: int,
    end_exclusive: int,
    plan: _LexicalPlan,
) -> str:
    if not plan.replacements:
        return ctx.script[start:end_exclusive]

    idx = bisect_left(plan.starts, start)
    out: list[str] = []
    pos = start

    while idx < len(plan.replacements):
        rs, re_, replacement = plan.replacements[idx]
        if rs >= end_exclusive:
            break

        if rs < start or re_ > end_exclusive:
            raise RuntimeError(
                "lexical replacement crosses requested source range: "
                f"{rs}:{re_} outside {start}:{end_exclusive}"
            )

        out.append(ctx.script[pos:rs])
        out.append(replacement)
        pos = re_
        idx += 1

    out.append(ctx.script[pos:end_exclusive])
    return "".join(out)


def _rewrite_node_with_plan(ctx, node, plan: _LexicalPlan) -> str:
    return _rewrite_range_with_plan(
        ctx,
        ctx.cs(node),
        ctx.ce(node) + 1,
        plan,
    )


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
    masked = _strip_strings_only(text)
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
        param_text = m.group(1)
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
    """고유 lexical alpha-name들을 table slot에 배정한다.

    Phase 2에서는 names의 각 항목이 이미 하나의 lexical binding identity다.
    table field 이름도 source variable 이름을 재사용하지 않고 `_bN` slot으로
    만들어, name-based identity가 다시 의미를 갖지 않게 한다.

    반환:
      table_decl_lines: ["local _T0={}", "local _T1={}", ...]
      name_to_ref: {"__KLB0": "_T0._b0", "__KLB1": "_T0._b1", ...}
    """
    table_decls: list[str] = []
    name_to_ref: dict[str, str] = {}

    safe_names = [
        name for name in names
        if name not in _LUA_KEYWORDS
    ]

    for idx, name in enumerate(safe_names):
        tbl_idx = idx // _VARS_PER_TABLE
        slot_idx = idx % _VARS_PER_TABLE
        tbl = f"_T{tbl_idx}"

        if tbl_idx == len(table_decls):
            table_decls.append(f"local {tbl}={{}}")

        name_to_ref[name] = f"{tbl}._b{slot_idx}"

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


def _emit_dispatch_split(blocks, entry_id, c, param_vars, rich_junk, hoist_names,
                         boundary_stats=None):
    """일부 state block을 여러 helper closure로 분리한 평면 디스패처.

    helper는 outer 함수의 state/hoisted local을 upvalue로 공유한다. 원본 return
    block은 outer dispatcher에 남겨야 다중 반환과 trailing nil을 그대로 보존할
    수 있으므로 inline case로 emit하고, 나머지 real/dead block만 helper bank와
    outer inline case 사이에 무작위로 분산한다.

    helper들을 호출할 때 loop 진입 시점의 state snapshot을 넘긴다. 먼저 호출된
    helper가 state를 다음 값으로 바꾸더라도 뒤 helper가 같은 iteration에서 다음
    원본 block까지 연속 실행하지 않게 하는 의미 보존 장치다.
    """
    sv = _zv(c)
    ht = _zv(c)
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
        cur = blk["s"]
        if blk["kind"] == "return":
            updates = []
        elif blk["kind"] == "goto":
            updates = [f"{sv}={sv}~{enc.delta_expr(cur, sid[blk['succ']])}"]
        else:
            updates = _branch_updates_flat(
                blk["cond"], sv, enc, cur,
                sid[blk["t"]], sid[blk["e"]], c,
            )
        real_meta.append({
            "s": cur,
            "lines": blk["lines"],
            "updates": updates,
            "real": True,
            "returns": blk["kind"] == "return",
        })

    all_ids = [blk["id"] for blk in blocks]
    dead_meta: list[dict] = []
    for _ in range(random.randint(len(real_meta), len(real_meta) * 2 + 1)):
        ds = _new_state(used)
        jl = _junk_flow(c, rich_junk, live)
        sink = _last_zv(jl)
        weave = f"~{_zero_from(sink)}" if sink else ""
        update = (
            f"{sv}={sv}~"
            f"{enc.delta_expr(ds, _dead_target_single(sid, all_ids))}{weave}"
        )
        dead_meta.append({
            "s": ds,
            "lines": jl,
            "updates": _dead_realvar_entangle(hoist_names, sink) + [update],
            "real": False,
            "returns": False,
        })

    movable = [m for m in real_meta + dead_meta if not m["returns"]]
    return_metas = [m for m in real_meta if m["returns"]]
    random.shuffle(movable)

    # 일부 block은 outer dispatcher에 그대로 두어 split과 inline boundary가 한
    # 함수 안에 공존하게 한다. helper 쪽에는 항상 적어도 하나를 남긴다.
    inline_count = min(
        max(1, len(movable) // 3),
        max(0, len(movable) - 1),
    )
    inline_metas = return_metas + movable[:inline_count]
    helper_metas = movable[inline_count:]

    helper_count = min(3, max(1, len(helper_metas)))
    groups: list[list[dict]] = [[] for _ in range(helper_count)]
    for index, meta in enumerate(helper_metas):
        groups[index % helper_count].append(meta)
    groups = [group for group in groups if group]

    lines: list[str] = []

    def emit(level, text):
        lines.append("  " * level + text)

    emit(0, f"local {sv}={enc.enc_expr(entry_s)}")
    emit(0, f"local {ht}={{}}")

    helper_keys: list[int] = []
    for group in groups:
        key = _new_state(used)
        helper_keys.append(key)
        arg = _zv(c)
        emit(0, f"{ht}[{key}]=function({arg})")
        for index, meta in enumerate(group):
            kw = "if" if index == 0 else "elseif"
            emit(1, f"{kw} {enc.dec_expr(arg)}=={meta['s']} then")
            if rich_junk and meta["real"] and random.random() < 0.85:
                _emit_live_junk(emit, 2, c, rich_junk, live, sv)
            if random.random() < 0.35:
                _emit_absorbing_junk(emit, 2, c, rich_junk, live, sv)
            for line in meta["lines"]:
                emit(2, line)
            for update in meta["updates"]:
                emit(2, update)
        emit(1, "end")
        emit(0, "end")

    emit(0, f"while {sv}~={enc.enc_expr(0)} do")
    snap = _zv(c)
    emit(1, f"local {snap}={sv}")

    random.shuffle(inline_metas)
    for index, meta in enumerate(inline_metas):
        kw = "if" if index == 0 else "elseif"
        emit(1, f"{kw} {enc.dec_expr(snap)}=={meta['s']} then")
        if rich_junk and meta["real"] and random.random() < 0.85:
            _emit_live_junk(emit, 2, c, rich_junk, live, sv)
        if random.random() < 0.35:
            _emit_absorbing_junk(emit, 2, c, rich_junk, live, sv)
        for line in meta["lines"]:
            emit(2, line)
        for update in meta["updates"]:
            emit(2, update)

    if inline_metas:
        emit(1, "else")
        call_level = 2
    else:
        call_level = 1
    random.shuffle(helper_keys)
    for key in helper_keys:
        emit(call_level, f"{ht}[{key}]({snap})")
    if inline_metas:
        emit(1, "end")

    for _ in range(random.randint(1, 2)):
        _emit_absorbing_junk(emit, 1, c, rich_junk, live, sv)
    emit(0, "end")

    if boundary_stats is not None:
        boundary_stats["split_helpers"] = (
            boundary_stats.get("split_helpers", 0) + len(groups)
        )
        boundary_stats["inline_blocks"] = (
            boundary_stats.get("inline_blocks", 0) + len(inline_metas)
        )
    return lines


def _build_generic_cff(blocks: list[dict], entry_id: int, c: list[int],
                       extra_hoist_names: list[str] | None = None,
                       rich_junk: bool = True,
                       param_names: list[str] | None = None,
                       boundary_mode: str = "mixed",
                       boundary_stats=None) -> str:
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

    extra_hoist_names: Phase-2 AST resolver가 CFF로 실제 분해되는 scope에서
    수집한 lexical binding의 고유 alpha-name들. direct `local function`은
    prelift 과정에서도 이 목록에 보강된다. opaque loop/nested-function 내부
    local은 포함하지 않는다.

    hoist되는 local 변수 + CFF 자체가 생성하는 내부 변수(zv)의 총 개수가
    `_TABLE_THRESHOLD`를 넘으면, 개별 `local` 슬롯 대신 테이블 필드
    (`_T0.name`, `_T1.name`, ...)로 몰아넣어 Lua 5.3의 함수당 local 200개
    한도를 회피한다. 이 변환은 거대한 VM dispatcher처럼 hoist 대상이
    매우 많은 경우에만 활성화되며, 일반적인 작은 함수는 영향이 없다.
    """
    # Phase 2에서는 hoist 대상이 AST resolver에서 이미 확정되어 있다.
    # emitted text를 다시 `_scan_local_names()`로 훑으면 nested function/opaque loop
    # 내부 local까지 바깥 scope local로 오인해 hoist하는 옛 버그가 되살아난다.
    #
    # extra_hoist_names:
    #   - root function / flattened if branch에서 선언된 고유 alpha binding
    #   - prelift된 direct local function binding
    #
    # opaque statement 내부 local은 의도적으로 포함되지 않는다.
    hoist_names = list(dict.fromkeys(
        extra_hoist_names or []
    ))
    real_names: set[str] = set(hoist_names)

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
    split_eligible = rich_junk and len(blocks) >= 2
    if boundary_mode == "split" and split_eligible:
        emitter = _emit_dispatch_split
    else:
        if boundary_mode == "mixed" and split_eligible:
            emitters.append(_emit_dispatch_split)
        emitter = random.choice(emitters)
    if emitter is _emit_dispatch_split:
        lines = emitter(
            blocks, entry_id, c, param_vars, rich_junk, hoist_names,
            boundary_stats=boundary_stats,
        )
    else:
        lines = emitter(blocks, entry_id, c, param_vars, rich_junk, hoist_names)

    zv_names = [f"_z{i}" for i in range(zv_start, c[0])]

    # 4) hoist 대상(real_names ∪ extra_hoist_names) + CFF가 생성한 zv
    #    (sv1/sv2/junk 전부) 총 개수로 테이블화 여부를 결정한다.
    all_hoisted_names = set(hoist_names) | set(zv_names)
    use_tables = len(all_hoisted_names) > _TABLE_THRESHOLD

    # ------------------------------------------------------------------
    # Lua for-control variable 보호
    #
    # Lua:
    #
    #   for i = 1, n do ... end
    #   for k, v in pairs(t) do ... end
    #
    # 의 i/k/v는 assignment target이 아니라 새로운 lexical local 선언이다.
    #
    # 따라서 text-level pooling으로
    #
    #   i -> _T0.i
    #
    # 를 적용하면:
    #
    #   for _T0.i = 1, n do
    #
    # 가 되어 syntax error:
    #
    #   '=' or 'in' expected near '.'
    #
    # 가 발생한다.
    #
    # Header만 치환에서 제외하는 것도 충분하지 않다. 예를 들어
    #
    #   for i=1,n do
    #       out[i] = ...
    #   end
    #
    # 에서 header의 i만 남기고 body의 i를 `_T0.i`로 바꾸면 서로 다른
    # 변수가 되어 semantics가 깨진다.
    #
    # 따라서 for binder와 이름이 충돌하는 hoist local은 테이블화하지 않고
    # 실제 Lua local로 유지한다. 원래 분기 안의 local 선언은 아래에서
    # 제거하고 함수 prologue에 `local name`으로 다시 hoist한다.
    # ------------------------------------------------------------------

    emitted_text = "\n".join(lines)
    for_binding_names = _scan_for_binding_names(emitted_text)

    # 이 이름들은 CFF scope 간 공유가 필요한 hoisted local이면서 동시에
    # 어디선가 for의 lexical binder로 사용되는 이름이다.
    #
    # table field로 바꾸지 않고 실제 function-scope local로 유지한다.
    lexical_hoist_names = all_hoisted_names & for_binding_names

    # 실제 table field로 변환할 이름들.
    table_pool_names = all_hoisted_names - lexical_hoist_names

    prologue: list[str] = []

    if use_tables:
        # for binder와 충돌하지 않는 local들만 table slot으로 보낸다.
        table_decls, name_to_ref = _build_var_tables(list(table_pool_names))
        prologue.extend(table_decls)
    else:
        name_to_ref = {}

    # sv1/sv2 초기화 `local {sv}=...`는 emitter output에 이미 포함돼 있다.
    #
    # table mode:
    #   table_pool_names에 속하는 local은
    #       local x=...
    #           ↓
    #       x=...
    #           ↓
    #       _T0.x=...
    #
    # lexical_hoist_names는
    #       local i=...
    #           ↓ strip
    #       i=...
    #
    # 로 만든 후 맨 앞에 별도의 `local i`를 붙인다.
    #
    # 이렇게 해야 CFF의 서로 다른 state에서도 동일한 outer local을
    # 공유하면서, `for i=...`가 만드는 loop-local은 자연스럽게 outer i를
    # shadow한다.
    body = ("\n" + _IND).join(prologue + lines)

    if use_tables:
        # 실제 table substitution 대상과 충돌하는 nested function parameter만
        # rename하면 된다.
        #
        # lexical_hoist_names는 table substitution을 하지 않으므로
        # parameter와 같은 이름이어도 여기서 rename할 이유가 없다.
        body = _rename_colliding_params(body, table_pool_names)

        # 모든 CFF-hoisted local 선언을 제거한다.
        #
        # table_pool_names:
        #     이후 `_Tn.name`으로 치환됨.
        #
        # lexical_hoist_names:
        #     이후 function prologue에 실제 `local name` 선언을 추가함.
        #
        # 이렇게 하지 않고 lexical_hoist_names의 원래 local 선언을
        # state 내부에 남겨두면 CFF 분기 사이에서 scope가 끊어진다.
        _, body = _collect_and_strip_locals(
            body,
            only_names=all_hoisted_names,
        )

        # table에 들어가는 이름만 field reference로 치환.
        body = _replace_idents_outside_strings(
            body,
            name_to_ref,
        )

        # for binder 이름과 충돌한 hoisted local은 실제 function local로 유지.
        #
        # 중요:
        # 이 선언은 _collect_and_strip_locals() 이후에 붙여야 한다.
        # 이전에 붙이면 위 strip 단계가 이 선언까지 다시 지워버린다.
        if lexical_hoist_names:
            lexical_decl = (
                "local "
                + ",".join(sorted(lexical_hoist_names))
            )
            body = lexical_decl + "\n" + body

    else:
        # 비-table mode에서는 기존 방식 그대로.
        #
        # real chunk 본문 안의 `local NAME=...` -> `NAME=...`
        # `local NAME` -> 제거
        #
        # 한 뒤 function scope 맨 앞에서 한 번 hoist한다.
        _, body = _collect_and_strip_locals(
            body,
            only_names=set(hoist_names),
        )

        if hoist_names:
            body = (
                "local "
                + ",".join(hoist_names)
                + "\n"
                + body
            )

    return body


# ---------------------------------------------------------------------------
# 본문 변환
# ---------------------------------------------------------------------------

# tree-sitter-lua 함수 노드 타입: function_declaration = `[local] function NAME`,
# function_definition = 익명 `function(...)`.
_FUNC_NODE_TYPES = ("function_declaration", "function_definition")


@dataclass(frozen=True)
class _FunctionProvenance:
    """초기 입력 AST에서 확정한 함수 출처와 nesting 깊이.

    function_obf가 나중에 생성하는 closure/junk function은 이 레코드를 얻을 수
    없으므로 recursive transform 대상이 될 수 없다. 이름이나 생성 identifier
    패턴 대신 최초 AST node identity를 provenance로 사용한다.
    """

    node_id: int
    parent_id: int | None
    depth: int
    origin: str = "SOURCE"


def _ancestor_nodes(node):
    ancestor = node.parent
    while ancestor is not None:
        yield ancestor
        ancestor = ancestor.parent


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
    """alpha-renamed `local function NAME(...) ... end`를 prelift한다.

    Phase-2 lexical resolver가 declaration name을 이미 고유 alpha-name으로
    바꿨으므로, 반환되는 NAME도 rewritten text에서 읽는다.
    """
    if not _is_local_func(stmt):
        return None, text

    m = re.match(
        r'^\s*local\s+function\s+([A-Za-z_]\w*)',
        text,
    )
    if m is None:
        return None, text

    name = m.group(1)
    paren_pos = text.find("(", m.end())
    if paren_pos < 0:
        return None, text

    return name, f"{name}=function{text[paren_pos:]}"


def _plan_simple_function_inlines(ctx, block, lexical_plan: _LexicalPlan):
    """안전한 zero-argument local function을 단일값 식으로 inline할 계획을 만든다.

    허용 형태는 root block의 ``local function f() return EXPR end``뿐이다.
    EXPR은 정확히 하나이며 function_call/vararg가 아니어야 한다. 또한 binding의
    모든 사용처가 ``f()`` 직접 호출이어야 한다. lexical plan의 고유 alpha-name을
    기준으로 검사하므로 같은 철자의 shadow binding을 잘못 합치지 않는다.

    이 보수적 부분집합은 인자 평가 순서, 재귀, 함수값 identity, 다중 반환 및
    trailing nil을 건드리지 않으면서 실제 call boundary를 제거한다.
    """
    provisional: dict[str, tuple[str, int]] = {}

    for stmt in _block_stmts(ctx, block):
        if not _is_local_func(stmt):
            continue

        params = stmt.child_by_field_name("parameters")
        if params is None or any(child.is_named for child in params.children):
            continue

        body = stmt.child_by_field_name("body")
        body_stmts = _block_stmts(ctx, body) if body is not None else []
        if len(body_stmts) != 1 or body_stmts[0].type != "return_statement":
            continue

        expr_list = next(
            (child for child in body_stmts[0].children
             if child.type == "expression_list"),
            None,
        )
        expressions = (
            [child for child in expr_list.children if child.is_named]
            if expr_list is not None else []
        )
        if len(expressions) != 1:
            continue
        expression = expressions[0]
        if expression.type in ("function_call", "vararg_expression"):
            continue

        rewritten_decl = _rewrite_node_with_plan(ctx, stmt, lexical_plan)
        match = re.match(
            r'^\s*local\s+function\s+([A-Za-z_]\w*)',
            rewritten_decl,
        )
        if match is None:
            continue
        alpha = match.group(1)
        expression_text = _rewrite_node_with_plan(
            ctx, expression, lexical_plan
        ).strip()
        if re.search(rf'\b{re.escape(alpha)}\b', expression_text):
            continue  # direct/indirect self recursion
        provisional[alpha] = (expression_text, stmt.id)

    if not provisional:
        return {}, set()

    # Candidate declarations themselves are excluded. Remaining references must all
    # be exact zero-argument calls; assignment, passing as a value, method access,
    # argument-bearing calls and rebinding all reject the candidate.
    candidate_ids = {stmt_id for _, stmt_id in provisional.values()}
    usage_text = "\n".join(
        _rewrite_node_with_plan(ctx, stmt, lexical_plan)
        for stmt in _block_stmts(ctx, block)
        if stmt.id not in candidate_ids
    )

    candidate_names = set(provisional)
    inline_map: dict[str, str] = {}
    skipped_ids: set[int] = set()
    for alpha, (expression_text, stmt_id) in provisional.items():
        # Keep candidate-to-candidate dependencies out of this simple one-pass
        # inliner. They require topological expansion and recursion-cycle handling.
        if any(
            re.search(rf'\b{re.escape(other)}\b', expression_text)
            for other in candidate_names
        ):
            continue

        refs = re.findall(rf'\b{re.escape(alpha)}\b', usage_text)
        calls = re.findall(
            rf'\b{re.escape(alpha)}\s*\(\s*\)',
            usage_text,
        )
        if refs and len(refs) == len(calls):
            inline_map[alpha] = f"({expression_text})"
            skipped_ids.add(stmt_id)

    return inline_map, skipped_ids


def _apply_simple_function_inlines(text: str, inline_map: dict[str, str]) -> str:
    for name, expression in inline_map.items():
        text = re.sub(
            rf'\b{re.escape(name)}\s*\(\s*\)',
            lambda _match, value=expression: value,
            text,
        )
    return text


def _subtree_contains_type(node, types: set[str]) -> bool:
    stack = [node]
    while stack:
        current = stack.pop()
        if current.type in types:
            return True
        stack.extend(current.children)
    return False


def _static_integer(ctx, node) -> int | None:
    if node is None:
        return None
    text = ctx.text(node).strip()
    if not re.fullmatch(r"[+-]?(?:0[xX][0-9A-Fa-f]+|[0-9]+)", text):
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def _numeric_for_values(ctx, stmt, max_iterations: int) -> list[int] | None:
    clause = stmt.child_by_field_name("clause")
    if clause is None or clause.type != "for_numeric_clause":
        return None
    start = _static_integer(ctx, clause.child_by_field_name("start"))
    stop = _static_integer(ctx, clause.child_by_field_name("end"))
    step_node = clause.child_by_field_name("step")
    step = 1 if step_node is None else _static_integer(ctx, step_node)
    if start is None or stop is None or step is None or step == 0:
        return None

    values: list[int] = []
    current = start
    predicate = (lambda value: value <= stop) if step > 0 else (lambda value: value >= stop)
    while predicate(current):
        values.append(current)
        if len(values) > max_iterations:
            return None
        current += step
    return values


def _mini_cff_body(body_text: str, compound_options: dict,
                   transform_budget: dict, compound_depth: int) -> str | None:
    """compound body를 synthetic function body로 파싱해 독립 mini-CFG화한다."""
    if compound_depth >= compound_options["max_depth"]:
        return None
    from .ts_utils import parse as parse_ts

    wrapped = "return function()\n" + body_text + "\nend"
    mini_ctx = parse_ts(wrapped)
    generated_binding_prefix = _binding_prefix(wrapped)
    root = next(
        (node for node in mini_ctx.walk() if node.type == "function_definition"),
        None,
    )
    block = root.child_by_field_name("body") if root is not None else None
    if root is None or block is None:
        return None
    cost = max(1, len(_block_stmts(mini_ctx, block)))
    if transform_budget["blocks_left"] < cost:
        return None

    transformed, _ = _transform_body(
        mini_ctx, root, block,
        rich_junk=False,
        boundary_mode="cff",
        compound_options=compound_options,
        transform_budget=transform_budget,
        compound_depth=compound_depth + 1,
    )
    if transformed is None:
        return None
    limit = max(
        len(body_text) + 64,
        int(len(body_text) * compound_options["max_expansion_ratio"]),
    )
    if len(transformed) > limit:
        return None
    # Each mini-CFG starts its private `_z` counter at zero. Without a namespace,
    # parent table-pooling can mistake those names for its own generated locals and
    # rewrite references across lexical scopes. The lexical binding prefix is known
    # to be absent from the input body, so both generated families can be renamed
    # without touching captured outer identifiers.
    namespace = f"__KCM{random.randrange(1 << 30):x}_"
    transformed = re.sub(
        rf'\b{re.escape(generated_binding_prefix)}([A-Za-z0-9_]*)\b',
        lambda match: namespace + "b" + match.group(1),
        transformed,
    )
    transformed = re.sub(
        r'\b_z([0-9]+)\b',
        lambda match: namespace + "z" + match.group(1),
        transformed,
    )
    growth = max(0, len(transformed) - len(body_text))
    if growth > transform_budget["chars_left"]:
        return None
    transform_budget["blocks_left"] -= cost
    transform_budget["chars_left"] -= growth
    transform_budget["generated_chars"] += growth
    return transformed


def _compound_statement_chunks(ctx, stmt, lexical_plan: _LexicalPlan,
                               inline_map: dict[str, str] | None,
                               compound_options: dict | None,
                               transform_budget: dict | None,
                               compound_depth: int,
                               compound_stats: dict) -> list[str] | None:
    """loop/do를 iteration chunks 또는 native-header + mini-CFG body로 바꾼다."""
    if not compound_options or not transform_budget:
        return None
    if stmt.type not in ("for_statement", "while_statement", "repeat_statement", "do_statement"):
        return None
    body = stmt.child_by_field_name("body")
    if body is None or not _block_stmts(ctx, body):
        return None

    # A break moved into a mini dispatcher would break that dispatcher rather than
    # the source loop. Goto/label crossing a generated state boundary is also unsafe.
    if _subtree_contains_type(body, {"break_statement", "goto_statement", "label_statement"}):
        compound_stats["skipped_unsafe"] += 1
        return None
    if stmt.type == "repeat_statement" and _subtree_contains_type(
        body, {"variable_declaration", "function_declaration"}
    ):
        # repeat-body locals are visible in the until condition. Replanning only the
        # body would rename that binding independently from the suffix condition.
        compound_stats["skipped_unsafe"] += 1
        return None

    body_text = _apply_simple_function_inlines(
        _rewrite_node_with_plan(ctx, body, lexical_plan), inline_map or {}
    )
    if (stmt.type == "for_statement" and compound_options["unroll"]
            and random.random() < compound_options["unroll_rate"]):
        values = _numeric_for_values(ctx, stmt, compound_options["unroll_max_iterations"])
        # Conservatively preserve native numeric-for closure capture semantics.
        if values is not None and not _subtree_contains_type(body, set(_FUNC_NODE_TYPES)):
            clause = stmt.child_by_field_name("clause")
            name_node = clause.child_by_field_name("name") if clause is not None else None
            if name_node is not None:
                loop_name = _rewrite_node_with_plan(ctx, name_node, lexical_plan)
                chunks: list[str] = []
                for value in values:
                    mini = _mini_cff_body(
                        body_text, compound_options, transform_budget, compound_depth
                    )
                    chunks.append(
                        f"do local {loop_name}={value}\n"
                        f"{mini if mini is not None else body_text}\nend"
                    )
                compound_stats["unrolled_loops"] += 1
                compound_stats["unrolled_iterations"] += len(values)
                return chunks

    if not compound_options["split"]:
        return None
    mini = _mini_cff_body(
        body_text, compound_options, transform_budget, compound_depth
    )
    if mini is None:
        compound_stats["budget_fallbacks"] += 1
        return None
    prefix = _apply_simple_function_inlines(
        _rewrite_range_with_plan(ctx, ctx.cs(stmt), ctx.cs(body), lexical_plan),
        inline_map or {},
    )
    suffix = _apply_simple_function_inlines(
        _rewrite_range_with_plan(
            ctx, ctx.ce(body) + 1, ctx.ce(stmt) + 1, lexical_plan
        ),
        inline_map or {},
    )
    compound_stats["split_bodies"] += 1
    return [prefix + mini + suffix]


def _inline_chunk_helpers(script: str) -> tuple[str, int]:
    """Lua chunk 직계 local helper에 함수 내부와 같은 안전 인라인을 적용한다.

    lexical planner를 재사용하기 위해 chunk를 임시 vararg function body로 감싼다.
    반환 시 wrapper는 제거되며, 원본 chunk의 주석/statement 사이 텍스트는 그대로
    보존한다. 실제 inline이 하나도 없으면 입력 문자열 자체를 그대로 반환한다.
    """
    from .ts_utils import parse as parse_ts

    prefix = "return function(...)\n"
    wrapped = prefix + script + "\nend"
    ctx = parse_ts(wrapped)
    function_node = next(
        (node for node in ctx.walk() if node.type == "function_definition"),
        None,
    )
    if function_node is None:
        return script, 0
    block = function_node.child_by_field_name("body")
    if block is None:
        return script, 0

    lexical_plan = _build_lexical_plan(ctx, function_node)
    inline_map, skipped_ids = _plan_simple_function_inlines(
        ctx, block, lexical_plan
    )
    if not skipped_ids:
        return script, 0

    start = ctx.cs(block)
    end = ctx.ce(block) + 1
    out: list[str] = []
    pos = start
    for stmt in _block_stmts(ctx, block):
        stmt_start = ctx.cs(stmt)
        stmt_end = ctx.ce(stmt) + 1
        gap = _rewrite_range_with_plan(
            ctx, pos, stmt_start, lexical_plan
        )
        out.append(_apply_simple_function_inlines(gap, inline_map))
        if stmt.id not in skipped_ids:
            rewritten = _rewrite_node_with_plan(ctx, stmt, lexical_plan)
            out.append(_apply_simple_function_inlines(rewritten, inline_map))
        pos = stmt_end
    tail = _rewrite_range_with_plan(ctx, pos, end, lexical_plan)
    out.append(_apply_simple_function_inlines(tail, inline_map))

    transformed = "".join(out)
    # wrapper가 넣은 body 양끝 개행만 제거한다. 원본 자체의 선행/후행 개행은
    # 그 안쪽에 있으므로 보존된다.
    if transformed.startswith("\n"):
        transformed = transformed[1:]
    if transformed.endswith("\n"):
        transformed = transformed[:-1]
    return transformed, len(skipped_ids)


def _compile_stmts_to_blocks(
    ctx,
    stmts,
    extra_hoist_names: list[str],
    lexical_plan: _LexicalPlan | None = None,
    inline_map: dict[str, str] | None = None,
    skipped_statement_ids: set[int] | None = None,
    compound_options: dict | None = None,
    transform_budget: dict | None = None,
    compound_depth: int = 0,
    compound_stats: dict | None = None,
) -> tuple[list[dict], int]:
    """문장열을 상태 머신 블록 전이 그래프로 컴파일한다.

    lexical_plan이 있으면 statement/condition을 source에서 꺼낼 때
    AST-resolved alpha rename을 먼저 적용한다.
    """
    blocks: list[dict] = []
    counter = [0]
    compound_stats = compound_stats if compound_stats is not None else {
        "split_bodies": 0,
        "lowered_loops": 0,
        "unrolled_loops": 0,
        "unrolled_iterations": 0,
        "skipped_unsafe": 0,
        "budget_fallbacks": 0,
    }

    def _new_id() -> int:
        counter[0] += 1
        return counter[0]

    def _text(node) -> str:
        if node is None:
            return ""
        if lexical_plan is None:
            text = ctx.text(node)
        else:
            text = _rewrite_node_with_plan(ctx, node, lexical_plan)
        return _apply_simple_function_inlines(text, inline_map or {})

    def _stmts_of(block_node) -> list:
        return _block_stmts(ctx, block_node) if block_node is not None else []

    def _stmt_lines(stmt) -> list[str]:
        stmt_text = _text(stmt).strip()
        name, stmt_text = _prelift_local_function_stmt(
            ctx, stmt, stmt_text
        )
        if name is not None and name not in extra_hoist_names:
            extra_hoist_names.append(name)
        return [
            ln.strip()
            for ln in stmt_text.splitlines()
            if ln.strip()
        ]

    def _stmt_chunks(stmt) -> list[list[str]]:
        compound = (
            _compound_statement_chunks(
                ctx, stmt, lexical_plan, inline_map, compound_options,
                transform_budget, compound_depth, compound_stats,
            )
            if lexical_plan is not None else None
        )
        if compound is None:
            return [_stmt_lines(stmt)]
        return [
            [line.strip() for line in text.splitlines() if line.strip()]
            for text in compound
        ]

    def _branch(cond: str, then_entry: int, else_entry: int) -> int:
        bid = _new_id()
        blocks.append({
            "id": bid,
            "lines": [],
            "kind": "branch",
            "cond": cond,
            "t": then_entry,
            "e": else_entry,
        })
        return bid

    def _condition_branch(cond: str, then_entry: int, else_entry: int) -> int:
        """조건 계산과 branch 선택을 서로 다른 CFG state로 분리한다."""
        temp_serial = _new_id()
        temp = f"{_binding_prefix(ctx.script)}CF{temp_serial}"
        if temp not in extra_hoist_names:
            extra_hoist_names.append(temp)
        branch_id = _branch(temp, then_entry, else_entry)
        pre_id = _new_id()
        blocks.append({
            "id": pre_id,
            "lines": [f"local {temp}=({cond})"],
            "kind": "goto",
            "succ": branch_id,
        })
        return pre_id

    def _compile_if(node, after_id: int) -> int:
        alts = [
            ch for i, ch in enumerate(node.children)
            if node.field_name_for_child(i) == "alternative"
        ]
        elseifs = [
            a for a in alts
            if a.type == "elseif_statement"
        ]
        else_node = next(
            (a for a in alts if a.type == "else_statement"),
            None,
        )

        if else_node is not None:
            chain = _compile_seq(
                _stmts_of(
                    else_node.child_by_field_name("body")
                ),
                after_id,
            )
        else:
            chain = after_id

        for ei in reversed(elseifs):
            cond_node = ei.child_by_field_name("condition")
            ei_cond = _text(cond_node).strip()
            ei_then = _compile_seq(
                _stmts_of(
                    ei.child_by_field_name("consequence")
                ),
                after_id,
            )
            chain = _condition_branch(ei_cond, ei_then, chain)

        cond_node = node.child_by_field_name("condition")
        cond = _text(cond_node).strip()
        then_entry = _compile_seq(
            _stmts_of(
                node.child_by_field_name("consequence")
            ),
            after_id,
        )
        return _condition_branch(cond, then_entry, chain)

    def _compile_test_loop(node, after_id: int) -> int | None:
        """Safe while/repeat를 explicit test/body/backedge CFG로 내린다."""
        if node.type not in ("while_statement", "repeat_statement"):
            return None
        body_node = node.child_by_field_name("body")
        condition_node = node.child_by_field_name("condition")
        if body_node is None or condition_node is None:
            return None
        if _subtree_contains_type(body_node, {
            "break_statement", "goto_statement", "label_statement",
            "variable_declaration", "function_declaration", "function_definition",
        }):
            return None

        cond = _text(condition_node).strip()
        temp_serial = _new_id()
        temp = f"{_binding_prefix(ctx.script)}CF{temp_serial}"
        if temp not in extra_hoist_names:
            extra_hoist_names.append(temp)
        branch_id = _new_id()
        test_id = _new_id()

        if node.type == "while_statement":
            body_entry = _compile_seq(_stmts_of(body_node), test_id)
            true_target, false_target = body_entry, after_id
            entry = test_id
        else:
            # repeat executes body first; true condition exits, false loops back.
            body_entry = _compile_seq(_stmts_of(body_node), test_id)
            true_target, false_target = after_id, body_entry
            entry = body_entry

        blocks.append({
            "id": branch_id,
            "lines": [],
            "kind": "branch",
            "cond": temp,
            "t": true_target,
            "e": false_target,
        })
        blocks.append({
            "id": test_id,
            "lines": [f"local {temp}=({cond})"],
            "kind": "goto",
            "succ": branch_id,
        })
        compound_stats["lowered_loops"] += 1
        return entry

    def _compile_seq(stmt_list, after_id: int) -> int:
        next_id = after_id
        for stmt in reversed(stmt_list):
            if stmt.id in (skipped_statement_ids or set()):
                continue
            if stmt.type == "if_statement":
                next_id = _compile_if(stmt, next_id)
            else:
                lowered_loop = _compile_test_loop(stmt, next_id)
                if lowered_loop is not None:
                    next_id = lowered_loop
                    continue
                chunks = _stmt_chunks(stmt)
                for chunk_index, lines in reversed(list(enumerate(chunks))):
                    bid = _new_id()
                    blk = {"id": bid, "lines": lines}
                    if stmt.type == "return_statement" and chunk_index == len(chunks) - 1:
                        blk["kind"] = "return"
                    else:
                        blk["kind"] = "goto"
                        blk["succ"] = next_id
                    blocks.append(blk)
                    next_id = bid
        return next_id

    entry = _compile_seq(stmts, 0)
    return blocks, entry


def _transform_body(
    ctx,
    function_node,
    block,
    rich_junk: bool = True,
    boundary_mode: str = "mixed",
    compound_options: dict | None = None,
    transform_budget: dict | None = None,
    compound_depth: int = 0,
) -> tuple[str | None, dict]:
    """함수 본문을 Phase-2 lexical binding 보존 상태로 CFF 변환."""

    boundary_stats = {
        "split_helpers": 0,
        "inline_blocks": 0,
        "inlined_functions": 0,
        "split_bodies": 0,
        "lowered_loops": 0,
        "unrolled_loops": 0,
        "unrolled_iterations": 0,
        "skipped_unsafe": 0,
        "budget_fallbacks": 0,
    }

    if compound_options and transform_budget is None:
        transform_budget = {
            "blocks_left": compound_options["max_generated_blocks"],
            "chars_left": max(
                256,
                int(len(ctx.text(block)) * compound_options["max_expansion_ratio"]),
            ),
            "generated_chars": 0,
        }

    stmts = _block_stmts(ctx, block)
    if not stmts:
        return None, boundary_stats

    for stmt in stmts:
        if _subtree_has_goto_or_label(stmt):
            return None, boundary_stats

    lexical_plan = _build_lexical_plan(ctx, function_node)
    inline_map, skipped_statement_ids = _plan_simple_function_inlines(
        ctx, block, lexical_plan
    )
    boundary_stats["inlined_functions"] = len(skipped_statement_ids)

    # CFF가 실제로 분해하는 root/if scope local만 hoist 대상.
    # loop/do/repeat/nested-function local은 plan.poolable_names에 없다.
    extra_hoist_names: list[str] = list(
        name for name in lexical_plan.poolable_names
        if name not in inline_map
    )

    blocks, entry = _compile_stmts_to_blocks(
        ctx,
        stmts,
        extra_hoist_names,
        lexical_plan=lexical_plan,
        inline_map=inline_map,
        skipped_statement_ids=skipped_statement_ids,
        compound_options=compound_options,
        transform_budget=transform_budget,
        compound_depth=compound_depth,
        compound_stats=boundary_stats,
    )

    c: list[int] = [0]
    params = list(lexical_plan.root_param_names)

    prefix_lines: list[str] = []
    if params:
        prefix_lines.append(
            f"local {','.join(params)}=..."
        )

    # 단일 simple/return statement는 CFF 없이 alpha-renaming + vararg unpack만.
    if len(blocks) == 1 and blocks[0]["kind"] != "branch":
        lines = blocks[0]["lines"]

        # direct local function은 compiler가 prelift했으므로 simple path에서는
        # 원래 local-function syntax로 복원한다.
        if extra_hoist_names:
            restored = []
            for ln in lines:
                m = re.match(r'^(\w+)=function', ln)
                if m and m.group(1) in extra_hoist_names:
                    restored.append(
                        f"local function {m.group(1)}"
                        f"{ln[len(m.group(0)):]}"
                    )
                else:
                    restored.append(ln)
            lines = restored

        return "\n".join(prefix_lines + lines), boundary_stats

    compound_heavy = (
        boundary_stats["unrolled_iterations"] > 0
        or boundary_stats["split_bodies"] > 0
        or boundary_stats["lowered_loops"] > 0
    )
    cff = _build_generic_cff(
        blocks,
        entry,
        c,
        extra_hoist_names,
        # Compound mini-CFG/unroll already expands structure substantially. Layering
        # rich junk again can cross Lua's local limit/table-pooling threshold, so the
        # transformation budget deliberately falls back to conservative junk here.
        rich_junk=rich_junk and not compound_heavy,
        param_names=params,
        boundary_mode=boundary_mode,
        boundary_stats=boundary_stats,
    )
    return "\n".join(prefix_lines + [cff]), boundary_stats


# VM 디스패처(exec) 식별용 sentinel. exec의 dispatch 루프
# `for i in setmetatable({},{__call=function(t)return t end}) do` 에만 등장하며,
# `__call`은 VM 템플릿 전체에서 이 한 곳에서만 쓰이는 메타메서드 키다
# (사용자 코드는 bytecode로 blob에 들어가므로 VM 텍스트에 나타나지 않는다).
# rename/number/string 난독화에도 살아남는다(`__call`은 테이블 필드 키,
# `function`은 키워드).
_DISPATCH_SENTINEL = re.compile(r'__call\s*=\s*function')
_VM_HOT_LOOP_SENTINEL = re.compile(r'__VM_HOT_LOOP__')


class FunctionObfuscationPass(BasePass):
    """함수 리터럴에 가변인자 래퍼 + 함수 경계 변환 + 본문 CFF를 적용한다.

    - 외부 호출부는 건드리지 않는다 (`function(...) local a,b=... end`로 파라미터를
      다시 풀어주므로 밖에서 보이는 시그니처/호출 규약은 동일).
    - 다문장 함수의 CFF block 일부는 helper closure들로 분리하고 일부는 outer
      dispatcher에 inline해 한 원본 함수가 여러 실행 경계에 걸치게 한다.
    - 안전한 zero-argument/single-value local helper는 호출식에 직접 inline한다.
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

    def __init__(self, skip_vm_dispatcher: bool = False,
                 boundary_mode: str = "mixed",
                 nested: bool = True,
                 nested_max_depth: int = 4,
                 loop_split: bool = True,
                 loop_unroll: bool = True,
                 loop_unroll_rate: float = 0.65,
                 loop_unroll_max_iterations: int = 4,
                 loop_max_generated_blocks: int = 64,
                 loop_max_expansion_ratio: float = 128.0,
                 loop_max_depth: int = 3):
        if boundary_mode not in {"mixed", "split", "cff"}:
            raise ValueError(
                "boundary_mode must be 'mixed', 'split', or 'cff'"
            )
        self.skip_vm_dispatcher = skip_vm_dispatcher
        self.boundary_mode = boundary_mode
        self.nested = bool(nested)
        if (not isinstance(nested_max_depth, int)
                or isinstance(nested_max_depth, bool)
                or nested_max_depth < 0):
            raise ValueError("nested_max_depth must be a non-negative integer")
        self.nested_max_depth = nested_max_depth
        if (not isinstance(loop_unroll_max_iterations, int)
                or isinstance(loop_unroll_max_iterations, bool)
                or loop_unroll_max_iterations < 0):
            raise ValueError("loop_unroll_max_iterations must be a non-negative integer")
        if (not isinstance(loop_unroll_rate, (int, float))
                or isinstance(loop_unroll_rate, bool)
                or not 0.0 <= float(loop_unroll_rate) <= 1.0):
            raise ValueError("loop_unroll_rate must be between 0.0 and 1.0")
        if (not isinstance(loop_max_generated_blocks, int)
                or isinstance(loop_max_generated_blocks, bool)
                or loop_max_generated_blocks < 1):
            raise ValueError("loop_max_generated_blocks must be a positive integer")
        if (not isinstance(loop_max_expansion_ratio, (int, float))
                or isinstance(loop_max_expansion_ratio, bool)
                or float(loop_max_expansion_ratio) < 1.0):
            raise ValueError("loop_max_expansion_ratio must be >= 1.0")
        if (not isinstance(loop_max_depth, int)
                or isinstance(loop_max_depth, bool)
                or loop_max_depth < 0):
            raise ValueError("loop_max_depth must be a non-negative integer")
        self.compound_options = {
            "split": bool(loop_split),
            "unroll": bool(loop_unroll),
            "unroll_rate": float(loop_unroll_rate),
            "unroll_max_iterations": loop_unroll_max_iterations,
            "max_generated_blocks": loop_max_generated_blocks,
            "max_expansion_ratio": float(loop_max_expansion_ratio),
            "max_depth": loop_max_depth,
        }
        self.last_transformed_count = 0
        self.last_split_helper_count = 0
        self.last_inline_block_count = 0
        self.last_inlined_function_count = 0
        self.last_nested_candidate_count = 0
        self.last_nested_transformed_count = 0
        self.last_depth_limited_count = 0
        self.last_processed_source_count = 0
        self.last_loop_split_body_count = 0
        self.last_loop_lowered_count = 0
        self.last_loop_unrolled_count = 0
        self.last_loop_unrolled_iteration_count = 0
        self.last_loop_unsafe_skip_count = 0
        self.last_loop_budget_fallback_count = 0

    @staticmethod
    def _apply_replacements(source: str, replacements: list[Replacement]) -> str:
        if not replacements:
            return source
        parts: list[str] = []
        pos = 0
        for replacement in sorted(replacements, key=lambda item: item.start):
            parts.append(source[pos:replacement.start])
            parts.append(replacement.new_text)
            pos = replacement.end + 1
        parts.append(source[pos:])
        return "".join(parts)

    def _transform_source_function(
        self,
        source_ctx,
        source_node,
        children_by_id: dict[int, list],
        provenance: dict[int, _FunctionProvenance],
        processed_ids: set[int],
    ) -> tuple[str, bool]:
        """초기 SOURCE 함수 subtree를 bottom-up으로 정확히 한 번 변환한다."""
        source_id = source_node.id
        record = provenance[source_id]
        if source_id in processed_ids:
            raise RuntimeError(
                f"function_obf source node processed twice: {source_id}"
            )
        processed_ids.add(source_id)

        node_start = source_ctx.cs(source_node)
        fragment = source_ctx.text(source_node)
        child_replacements: list[Replacement] = []

        can_descend = self.nested and record.depth < self.nested_max_depth
        for child in children_by_id.get(source_id, []):
            child_record = provenance[child.id]
            if not can_descend:
                self.last_depth_limited_count += 1
                continue
            child_text, _ = self._transform_source_function(
                source_ctx,
                child,
                children_by_id,
                provenance,
                processed_ids,
            )
            child_replacements.append(Replacement(
                start=source_ctx.cs(child) - node_start,
                end=source_ctx.ce(child) - node_start,
                new_text=child_text,
            ))

        fragment = self._apply_replacements(fragment, child_replacements)

        from .ts_utils import parse as parse_ts

        fragment_ctx = parse_ts(fragment)
        candidates = [
            node for node in fragment_ctx.walk()
            if node.type in _FUNC_NODE_TYPES
            and not any(
                ancestor.type in _FUNC_NODE_TYPES
                for ancestor in _ancestor_nodes(node)
            )
        ]

        if len(candidates) != 1:
            raise RuntimeError(
                "function_obf could not recover reconstructed source function "
                f"root (found {len(candidates)})"
            )
        root = candidates[0]
        block = root.child_by_field_name("body")
        params_node = root.child_by_field_name("parameters")
        if block is None or params_node is None:
            return fragment, False

        # vararg source 함수 자체는 기존 safety 정책대로 건드리지 않되, 위에서
        # 이미 처리한 SOURCE nested 함수 결과는 fragment 안에 유지한다.
        if any(
            child.type == "vararg_expression"
            for child in params_node.children
        ):
            return fragment, False

        params = [
            fragment_ctx.text(child)
            for child in params_node.children
            if child.type == "identifier"
        ]
        new_body, boundary_stats = _transform_body(
            fragment_ctx,
            root,
            block,
            rich_junk=True,
            boundary_mode=self.boundary_mode,
            compound_options=self.compound_options,
        )
        if new_body is None:
            return fragment, False

        local_replacements = [Replacement(
            start=fragment_ctx.cs(block),
            end=fragment_ctx.ce(block),
            new_text=new_body,
        )]
        if params:
            local_replacements.append(Replacement(
                start=fragment_ctx.cs(params_node) + 1,
                end=fragment_ctx.ce(params_node) - 1,
                new_text="...",
            ))
        fragment = self._apply_replacements(fragment, local_replacements)

        self.last_split_helper_count += boundary_stats["split_helpers"]
        self.last_inline_block_count += boundary_stats["inline_blocks"]
        self.last_inlined_function_count += boundary_stats["inlined_functions"]
        self.last_loop_split_body_count += boundary_stats["split_bodies"]
        self.last_loop_lowered_count += boundary_stats["lowered_loops"]
        self.last_loop_unrolled_count += boundary_stats["unrolled_loops"]
        self.last_loop_unrolled_iteration_count += boundary_stats["unrolled_iterations"]
        self.last_loop_unsafe_skip_count += boundary_stats["skipped_unsafe"]
        self.last_loop_budget_fallback_count += boundary_stats["budget_fallbacks"]
        self.last_transformed_count += 1
        if record.depth > 0:
            self.last_nested_transformed_count += 1
        return fragment, True

    def run(self, script: str, ctx) -> list[Replacement]:
        self.last_transformed_count = 0
        self.last_split_helper_count = 0
        self.last_inline_block_count = 0
        self.last_inlined_function_count = 0
        self.last_nested_candidate_count = 0
        self.last_nested_transformed_count = 0
        self.last_depth_limited_count = 0
        self.last_processed_source_count = 0
        self.last_loop_split_body_count = 0
        self.last_loop_lowered_count = 0
        self.last_loop_unrolled_count = 0
        self.last_loop_unrolled_iteration_count = 0
        self.last_loop_unsafe_skip_count = 0
        self.last_loop_budget_fallback_count = 0
        original_script = script
        chunk_rewritten = False
        if not self.skip_vm_dispatcher:
            script, chunk_inline_count = _inline_chunk_helpers(script)
            if chunk_inline_count:
                from .ts_utils import parse as parse_ts

                ctx = parse_ts(script)
                chunk_rewritten = True
                self.last_inlined_function_count += chunk_inline_count
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

        if not self.skip_vm_dispatcher:
            # Provenance는 function_obf가 어떤 코드를 생성하기 *전*의 AST에서 한
            # 번만 만든다. 이후 reconstructed fragment에 나타난 helper/junk 함수는
            # 이 map에 node id가 없으므로 recursive input이 될 수 없다.
            provenance: dict[int, _FunctionProvenance] = {}
            children_by_id: dict[int, list] = {}
            top_level_nodes: list = []

            for node in func_nodes:
                function_ancestors = [
                    ancestor for ancestor in _ancestor_nodes(node)
                    if ancestor.type in _FUNC_NODE_TYPES
                ]
                parent = function_ancestors[0] if function_ancestors else None
                parent_id = parent.id if parent is not None else None
                provenance[node.id] = _FunctionProvenance(
                    node_id=node.id,
                    parent_id=parent_id,
                    depth=len(function_ancestors),
                )
                if parent_id is None:
                    top_level_nodes.append(node)
                else:
                    children_by_id.setdefault(parent_id, []).append(node)

            # Source order 고정은 같은 seed에서 재현 가능한 random consumption 순서를
            # 보장한다. ctx.walk()/body-size 정렬 순서에 기대지 않는다.
            for children in children_by_id.values():
                children.sort(key=ctx.cs)
            top_level_nodes.sort(key=ctx.cs)

            self.last_nested_candidate_count = sum(
                1 for record in provenance.values()
                if 0 < record.depth <= self.nested_max_depth
            ) if self.nested else 0

            processed_ids: set[int] = set()
            for node in top_level_nodes:
                transformed_text, _ = self._transform_source_function(
                    ctx,
                    node,
                    children_by_id,
                    provenance,
                    processed_ids,
                )
                if transformed_text != ctx.text(node):
                    replacements.append(Replacement(
                        start=ctx.cs(node),
                        end=ctx.ce(node),
                        new_text=transformed_text,
                    ))

            self.last_processed_source_count = len(processed_ids)
            expected_processed = {
                node_id for node_id, record in provenance.items()
                if record.depth <= self.nested_max_depth
                and (self.nested or record.depth == 0)
            }
            if processed_ids != expected_processed:
                raise RuntimeError(
                    "function_obf SOURCE provenance processing mismatch: "
                    f"processed={len(processed_ids)} expected={len(expected_processed)}"
                )

            self.last_transform_elapsed = time.perf_counter() - transform_start
            if chunk_rewritten:
                final_script = self._apply_replacements(script, replacements)
                return [Replacement(
                    start=0,
                    end=max(-1, len(original_script) - 1),
                    new_text=final_script,
                )]
            return replacements

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
            new_body, boundary_stats = _transform_body(
                ctx,
                node,
                block,
                rich_junk=not self.skip_vm_dispatcher,
                boundary_mode=(
                    "cff" if self.skip_vm_dispatcher
                    else self.boundary_mode
                ),
            )
            if new_body is None:
                continue

            self.last_split_helper_count += boundary_stats["split_helpers"]
            self.last_inline_block_count += boundary_stats["inline_blocks"]
            self.last_inlined_function_count += boundary_stats["inlined_functions"]

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
        if chunk_rewritten:
            parts: list[str] = []
            pos = 0
            for replacement in sorted(replacements, key=lambda item: item.start):
                parts.append(script[pos:replacement.start])
                parts.append(replacement.new_text)
                pos = replacement.end + 1
            parts.append(script[pos:])
            final_script = "".join(parts)
            return [Replacement(
                start=0,
                end=max(-1, len(original_script) - 1),
                new_text=final_script,
            )]
        return replacements

if __name__ == "__main__":
    # --- function_obfuscation lexical-pooling smoke tests ---
    # 이 테스트는 전체 obfuscation pipeline을 돌리는 게 아니라, table-pooling의
    # 텍스트 치환이 Lua의 lexical binder 문법을 깨뜨리지 않는지만 빠르게 확인한다.
    def _assert_no_pooled_binders(label: str, out: str) -> None:
        bad_for = re.search(
            r'\bfor\s+_T\d+\.[A-Za-z_]\w*\s*(?:=|\bin\b)',
            out,
        )
        bad_param = re.search(
            r'\bfunction(?:\s+[A-Za-z_]\w*(?:[.:][A-Za-z_]\w*)*)?'
            r'\s*\([^)]*_T\d+\.[A-Za-z_]\w*',
            out,
        )
        if bad_for:
            raise AssertionError(
                f"{label}: pooled field leaked into for binder: {bad_for.group(0)!r}"
            )
        if bad_param:
            raise AssertionError(
                f"{label}: pooled field leaked into function parameter: "
                f"{bad_param.group(0)!r}"
            )

    # anonymous function parameter collision
    _src = "local x=1; local f=function(x)return x+1 end; return x+f(2)"
    _out = _rename_colliding_params(_src, {"x"})
    assert "function(_p0)" in _out, _out
    assert "return _p0+1" in _out, _out
    _assert_no_pooled_binders("anonymous-param", _out)

    # named local function parameter collision
    _src = "local function bits(n) return n+1 end; local n=3; return bits(n)"
    _out = _rename_colliding_params(_src, {"n"})
    assert re.search(r'local function bits\(_p\d+\)', _out), _out
    assert re.search(r'return _p\d+\+1', _out), _out
    _assert_no_pooled_binders("local-function-param", _out)

    # dotted / method-style named function parameter collision
    _src = (
        "function obj.method(x,y) return x+y end "
        "function obj:other(y) return y end"
    )
    _out = _rename_colliding_params(_src, {"x", "y"})
    assert re.search(r'function obj\.method\(_p\d+,_p\d+\)', _out), _out
    assert re.search(r'function obj:other\(_p\d+\)', _out), _out
    _assert_no_pooled_binders("named-method-param", _out)

    # local declaration scanner must never treat Lua keyword `function` as a local name.
    _locals = _scan_local_names(
        "local function foo(a) return a end; local x=1; local y,z=2,3"
    )
    assert "function" not in _locals, _locals
    assert {"x", "y", "z"} <= _locals, _locals

    # for-control variables are lexical binders and must be discoverable for exclusion.
    _for_names = _scan_for_binding_names(
        "for i=1,n do end; for k,v in pairs(t) do end"
    )
    assert {"i", "k", "v"} <= _for_names, _for_names

    # Regression: protected function signatures must not bridge `local`
    # to the first keyword/token in the nested function body.
    _locals = _scan_local_names(
        "local function foo(a)\n"
        "    while a do\n"
        "        local x=1\n"
        "        break\n"
        "    end\n"
        "end\n"
        "local y=2"
    )
    assert _locals == {"x", "y"}, _locals
    assert not (_locals & _LUA_KEYWORDS), _locals

    # Same regression with another local declaration immediately after
    # a protected named-function signature.
    _locals = _scan_local_names(
        "local function foo(a)\n"
        "local z=1\n"
        "end"
    )
    assert _locals == {"z"}, _locals

    # Reserved words must never be substituted even if a corrupted mapping
    # is deliberately supplied.
    _guarded = _subst_var_refs(
        "local x=1 while x<2 do x=x+1 end",
        {
            "local": "_T0.local",
            "while": "_T0.while",
            "x": "_T0.x",
        },
        _STRING_LIT_RE,
    )
    assert "_T0.local" not in _guarded, _guarded
    assert "_T0.while" not in _guarded, _guarded
    assert "_T0.x" in _guarded, _guarded

    # Table builder also discards impossible keyword names defensively.
    _decls, _mapping = _build_var_tables(["x", "local", "while", "y"])
    assert "local" not in _mapping and "while" not in _mapping, _mapping
    assert {"x", "y"} <= set(_mapping), _mapping

    # Phase-2 AST lexical binding regression:
    # same spelling in root / if branch / nested function must become distinct
    # bindings, while only root/flattened-if bindings are poolable.
    from .ts_utils import parse as _ts_parse

    _lex_src = """
return function(c)
    local v = c

    if c then
        local v = 99
        c = v
    end

    local function decode(e)
        local v = e
        v = v ~ 1
        return v
    end

    return decode(c) ~ v
end
"""
    _lex_ctx = _ts_parse(_lex_src)
    _lex_fn = next(
        n for n in _lex_ctx.walk()
        if n.type == "function_definition"
    )
    _lex_block = _lex_fn.child_by_field_name("body")
    _lex_plan = _build_lexical_plan(_lex_ctx, _lex_fn)

    _v_bindings = [
        b for b in _lex_plan.bindings
        if b.original == "v"
    ]
    assert len(_v_bindings) == 3, _v_bindings
    assert len({b.alpha for b in _v_bindings}) == 3, _v_bindings

    _pool_v = [b for b in _v_bindings if b.poolable]
    _nested_v = [b for b in _v_bindings if not b.poolable]
    assert len(_pool_v) == 2, _v_bindings
    assert len(_nested_v) == 1, _v_bindings
    assert _nested_v[0].alpha not in _lex_plan.poolable_names

    _rewritten = _rewrite_node_with_plan(
        _lex_ctx, _lex_block, _lex_plan
    )
    for _b in _v_bindings:
        assert _b.alpha in _rewritten, (_b, _rewritten)

    _decode_binding = next(
        b for b in _lex_plan.bindings
        if b.original == "decode"
    )
    assert _decode_binding.poolable

    # Local shadowing RHS: `local x=x`의 RHS x는 새 binding이 아니라 parameter.
    _shadow_src = """
return function(x)
    local x = x
    return x
end
"""
    _shadow_ctx = _ts_parse(_shadow_src)
    _shadow_fn = next(
        n for n in _shadow_ctx.walk()
        if n.type == "function_definition"
    )
    _shadow_plan = _build_lexical_plan(
        _shadow_ctx, _shadow_fn
    )
    _xb = [
        b for b in _shadow_plan.bindings
        if b.original == "x"
    ]
    assert len(_xb) == 2 and _xb[0].alpha != _xb[1].alpha, _xb

    _shadow_block = _shadow_fn.child_by_field_name("body")
    _shadow_text = _rewrite_node_with_plan(
        _shadow_ctx, _shadow_block, _shadow_plan
    )
    assert (
        f"local {_xb[1].alpha} = {_xb[0].alpha}"
        in _shadow_text
    ), _shadow_text

    # tree-sitter-lua grammar regression:
    # variable_list의 변수들은 positional identifier child다.
    _locals_src = """
return function(seed)
    local x = seed
    local a,b = x,2
    if seed then
        local y = a+b
        x = y
    end
    return x
end
"""
    _locals_ctx = _ts_parse(_locals_src)
    _locals_fn = next(
        n for n in _locals_ctx.walk()
        if n.type == "function_definition"
    )
    _locals_plan = _build_lexical_plan(
        _locals_ctx, _locals_fn
    )
    _local_bindings = [
        b for b in _locals_plan.bindings
        if b.kind == "local"
    ]
    _local_originals = [b.original for b in _local_bindings]
    assert _local_originals.count("x") == 1, _local_originals
    assert _local_originals.count("a") == 1, _local_originals
    assert _local_originals.count("b") == 1, _local_originals
    assert _local_originals.count("y") == 1, _local_originals
    assert all(b.poolable for b in _local_bindings), _local_bindings

    # generic-for 역시 variable_list positional children을 사용하지만
    # loop binder는 CFF-hoisted local이 아니어야 한다.
    _for_src = """
return function(t)
    local sum = 0
    for k,v in pairs(t) do
        sum = sum + k + v
    end
    return sum
end
"""
    _for_ctx = _ts_parse(_for_src)
    _for_fn = next(
        n for n in _for_ctx.walk()
        if n.type == "function_definition"
    )
    _for_plan = _build_lexical_plan(
        _for_ctx, _for_fn
    )
    _for_bindings = [
        b for b in _for_plan.bindings
        if b.kind == "for"
    ]
    assert [b.original for b in _for_bindings] == ["k", "v"], _for_bindings
    assert not any(b.poolable for b in _for_bindings), _for_bindings

    # separate CFF statements 사이에서 ordinary local binding identity가
    # 유지되는지 확인.
    _cross_src = """
return function(t)
    local x = t
    local y = x
    return y[1]
end
"""
    _cross_ctx = _ts_parse(_cross_src)
    _cross_fn = next(
        n for n in _cross_ctx.walk()
        if n.type == "function_definition"
    )
    _cross_block = _cross_fn.child_by_field_name("body")
    _cross_plan = _build_lexical_plan(
        _cross_ctx, _cross_fn
    )
    _cross_text = _rewrite_node_with_plan(
        _cross_ctx, _cross_block, _cross_plan
    )
    _cross_locals = [
        b for b in _cross_plan.bindings
        if b.kind == "local"
    ]
    assert len(_cross_locals) == 2, _cross_locals
    for _b in _cross_locals:
        assert _b.alpha in _cross_text, (_b, _cross_text)

    print("function_obfuscation smoke tests: OK")

