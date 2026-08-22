"""
tree-sitter 기반 scope-aware identifier rename.

이 구현은 기존 rename_ts.py의 의미를 최대한 유지하면서 대형 VM 출력에서의
성능 병목을 제거한다.

기존 구현의 주요 병목:
- 선언마다 모든 scope를 선형 탐색해서 closest scope 계산
- 모든 scope 쌍을 비교해 child interval subtraction 수행 (O(S^2))
- scope segment마다 regex tokenizer로 소스를 다시 스캔
- segment마다 거대한 문자열을 반복 재조립

새 구현:
1. tree-sitter AST를 한 번 순회하며 함수 scope tree와 local 선언을 수집
2. 부모 scope map을 상속해 rename map 생성
3. AST를 다시 한 번 순회하며 실제 identifier node만 rename 대상으로 판정
4. replacement들을 원본 source 기준으로 한 번만 join

중요:
- 기존 구현처럼 scope 경계는 "함수" 단위로 유지한다.
  do/if/for block별 lexical scope로 세분화하지 않는다.
- local function 이름은 부모 함수 scope에 속한다.
- 함수 파라미터 / local 변수 / numeric-for / generic-for 변수를 rename한다.
- table field key, dot field, method name 등 변수 참조가 아닌 identifier는 건드리지 않는다.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .ts_utils import parse as _ts_parse


_FUNC_TYPES = {"function_declaration", "function_definition"}


@dataclass
class _Scope:
    sid: int
    node: object | None
    parent: int | None
    names: set[str] = field(default_factory=set)
    rename_map: dict[str, str] = field(default_factory=dict)


def _first_child(node, typ: str):
    for child in node.children:
        if child.type == typ:
            return child
    return None


def _identifier_children(node):
    for child in node.children:
        if child.type == "identifier":
            yield child


def _is_local_function_declaration(node) -> bool:
    return (
        node.type == "function_declaration"
        and bool(node.children)
        and node.children[0].type == "local"
    )


def _function_decl_name_node(node):
    """
    local function foo(...) / function foo(...) 에서 단순 identifier 이름을 반환.
    function a.b:c(...) 같은 복합 이름은 None을 반환해 field/method 이름을
    변수 rename 대상으로 오인하지 않는다.
    """
    if node.type != "function_declaration":
        return None

    # function_declaration의 직접 identifier child만 허용한다.
    # parameters 내부 identifier는 직접 child가 아니므로 섞이지 않는다.
    for child in node.children:
        if child.type == "identifier":
            return child
    return None


def _collect_scopes_and_decls(ctx):
    """
    AST를 한 번 DFS해서:
    - 함수마다 scope id 할당
    - 부모 함수 scope 연결
    - 각 scope의 local declaration 이름 수집

    기존 rename_ts.py와 동일하게 함수 단위 scope만 사용한다.
    """
    root = ctx.root
    text = ctx.text

    scopes: list[_Scope] = [_Scope(0, None, None)]
    node_scope: dict[int, int] = {}

    # stack entry:
    #   (node, current_scope, entering)
    # entering=False는 현재 구현에서는 필요 없지만 재귀 없이 DFS하기 위해
    # 구조를 명시적으로 유지한다.
    stack: list[tuple[object, int]] = [(root, 0)]

    while stack:
        node, current_sid = stack.pop()
        typ = node.type

        # 함수 노드 자체는 새 scope를 만든다.
        if typ in _FUNC_TYPES:
            parent_sid = current_sid

            # local function foo() 의 foo는 새 함수 scope가 아니라
            # 선언이 위치한 부모 scope의 local이다.
            if _is_local_function_declaration(node):
                name_node = _function_decl_name_node(node)
                if name_node is not None:
                    scopes[parent_sid].names.add(text(name_node))

            sid = len(scopes)
            scopes.append(_Scope(sid, node, parent_sid))
            node_scope[node.id] = sid
            current_sid = sid

            # 함수 parameters는 함수 자신의 scope local.
            params = _first_child(node, "parameters")
            if params is not None:
                for child in params.children:
                    if child.type == "identifier":
                        scopes[current_sid].names.add(text(child))

        elif typ == "variable_declaration":
            # local x
            # local x,y = ...
            # grammar에 따라 assignment_statement 아래 variable_list가 있거나
            # variable_list가 직접 자식일 수 있다.
            asgn = _first_child(node, "assignment_statement")
            if asgn is not None:
                vlist = _first_child(asgn, "variable_list")
            else:
                vlist = _first_child(node, "variable_list")

            if vlist is not None:
                for child in vlist.children:
                    if child.type == "identifier":
                        scopes[current_sid].names.add(text(child))

        elif typ == "for_statement":
            num = _first_child(node, "for_numeric_clause")
            if num is not None:
                ident = _first_child(num, "identifier")
                if ident is not None:
                    scopes[current_sid].names.add(text(ident))

            gen = _first_child(node, "for_generic_clause")
            if gen is not None:
                vlist = _first_child(gen, "variable_list")
                if vlist is not None:
                    for child in vlist.children:
                        if child.type == "identifier":
                            scopes[current_sid].names.add(text(child))

        # DFS. 함수 node를 만난 경우 current_sid가 새 scope로 바뀌었으므로
        # 그 children은 자연스럽게 새 scope로 들어간다.
        for child in reversed(node.children):
            stack.append((child, current_sid))

    return scopes, node_scope


def _build_scope_maps(scopes: list[_Scope]) -> None:
    """
    부모 scope의 map을 상속한 뒤 현재 scope local 이름을 새 _vN으로 덮어쓴다.

    scope id는 DFS에서 부모보다 항상 나중에 생성되므로 단순 순차 처리 가능.
    """
    counter = 0

    for scope in scopes:
        if scope.parent is None:
            current: dict[str, str] = {}
        else:
            current = scopes[scope.parent].rename_map.copy()

        # 기존 구현처럼 이름 길이 내림차순으로 deterministic allocation.
        for name in sorted(scope.names, key=len, reverse=True):
            current[name] = f"_v{counter}"
            counter += 1

        scope.rename_map = current


def _is_table_field_key(node) -> bool:
    """
    { foo = value } 의 foo는 변수 참조가 아니라 literal field key.
    """
    parent = node.parent
    if parent is None or parent.type != "field":
        return False

    children = parent.children
    return (
        len(children) >= 2
        and children[0].id == node.id
        and children[1].type == "="
    )


def _is_dot_or_method_name(node) -> bool:
    """
    obj.foo / obj:foo() 에서 foo는 변수명이 아니라 field/method 이름.
    base 쪽 identifier(obj)는 정상 rename 대상이다.
    """
    parent = node.parent
    if parent is None:
        return False

    if parent.type not in {"dot_index_expression", "method_index_expression"}:
        return False

    # 해당 expression에서 마지막 identifier가 field/method name이다.
    id_children = [c for c in parent.children if c.type == "identifier"]
    return bool(id_children) and id_children[-1].id == node.id


def _is_label_or_goto_name(node) -> bool:
    """
    label/goto 이름은 local variable이 아니므로 rename map과 이름이 우연히
    같아도 건드리지 않는다.
    """
    parent = node.parent
    if parent is None:
        return False
    return parent.type in {
        "label_statement",
        "goto_statement",
    }


def _is_function_declaration_name(node) -> bool:
    """
    function foo(...)에서 foo 자체.

    local function foo는 부모 scope local이므로 rename해야 한다.
    global function foo는 기존 local rename 대상이 아니므로 rename하지 않는다.
    복합 function a.b:c는 이 함수에서 단순 identifier declaration으로
    판정하지 않고 dot/method 규칙에 맡긴다.
    """
    parent = node.parent
    if parent is None or parent.type != "function_declaration":
        return False

    name_node = _function_decl_name_node(parent)
    return name_node is not None and name_node.id == node.id


def _should_skip_identifier(node) -> bool:
    if _is_table_field_key(node):
        return True
    if _is_dot_or_method_name(node):
        return True
    if _is_label_or_goto_name(node):
        return True

    # non-local function declaration 이름은 global symbol.
    if _is_function_declaration_name(node):
        parent = node.parent
        if not _is_local_function_declaration(parent):
            return True

    return False


def _collect_identifier_replacements(ctx, scopes: list[_Scope], node_scope: dict[int, int]):
    """
    AST를 두 번째 DFS하면서 현재 함수 scope의 rename map으로 identifier node만
    직접 치환한다.

    문자열/주석/숫자는 애초에 identifier node가 아니므로 별도 regex 보호가
    필요 없다.
    """
    text = ctx.text
    cs = ctx.cs
    ce = ctx.ce

    replacements: list[tuple[int, int, str]] = []
    stack: list[tuple[object, int]] = [(ctx.root, 0)]

    while stack:
        node, current_sid = stack.pop()
        typ = node.type

        if typ in _FUNC_TYPES:
            current_sid = node_scope[node.id]

        if typ == "identifier" and not _should_skip_identifier(node):
            original = text(node)
            renamed = scopes[current_sid].rename_map.get(original)
            if renamed is not None and renamed != original:
                replacements.append((cs(node), ce(node), renamed))

        for child in reversed(node.children):
            stack.append((child, current_sid))

    return replacements


def _apply_replacements_once(script: str, replacements: list[tuple[int, int, str]]) -> str:
    """
    원본 source 좌표 기준 replacement를 한 번만 조립한다.

    기존 구현처럼 각 scope segment마다 15MB+ 문자열을 재복사하지 않는다.
    """
    if not replacements:
        return script

    replacements.sort(key=lambda item: item[0])

    parts: list[str] = []
    pos = 0

    for start, end, new_text in replacements:
        # identifier node들은 서로 겹치지 않아야 한다.
        # 혹시 grammar/버그로 겹치면 조용히 source를 깨뜨리지 말고 실패시킨다.
        if start < pos:
            raise RuntimeError(
                f"overlapping rename replacement at {start}:{end}, previous end={pos - 1}"
            )

        parts.append(script[pos:start])
        parts.append(new_text)
        pos = end + 1

    parts.append(script[pos:])
    return "".join(parts)


def rename_script_ts(script: str) -> str:
    """standalone 진입점: 직접 tree-sitter parse 후 rename."""
    return rename_with_ctx(_ts_parse(script))


def rename_with_ctx(ctx) -> str:
    """
    Pipeline이 이미 만든 TSContext를 재사용하는 메인 진입점.

    Complexity는 대략:
      O(AST nodes + declarations + identifiers + output size)

    기존의 scope-pair O(S^2), segment regex 재스캔, 반복 문자열 재조립을 제거한다.
    """
    scopes, node_scope = _collect_scopes_and_decls(ctx)
    _build_scope_maps(scopes)

    replacements = _collect_identifier_replacements(
        ctx,
        scopes,
        node_scope,
    )

    return _apply_replacements_once(
        ctx.script,
        replacements,
    )
