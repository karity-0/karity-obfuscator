"""
tree-sitter 기반 scope-aware identifier rename.

AST 분석(scope/선언 이름/테이블 키)을 tree-sitter로 수행하고, 실제 치환은
기존 regex 로직(_rename_segment/_TOKEN_RE)을 재사용한다. luaparser 파싱이
전체 난독화 시간의 ~90%를 차지하던 병목을 제거한다.

byte/char offset 변환은 TSContext가 처리하므로 멀티바이트(주석 등) 입력에도
안전하다.
"""
from __future__ import annotations

from .rename_obfuscation import (
    subtract_interval, _rename_segment,
)
from .ts_utils import parse as _ts_parse

_FUNC_TYPES = ("function_declaration", "function_definition")
_CHUNK = 0  # scope id 0 = 최상위 chunk


def _first_child(node, typ):
    for c in node.children:
        if c.type == typ:
            return c
    return None


def rename_script_ts(script: str) -> str:
    """standalone 진입점: 직접 파싱 후 rename."""
    return rename_with_ctx(_ts_parse(script))


def rename_with_ctx(ctx) -> str:
    """파이프라인이 제공한 TSContext를 재사용해 rename (이중 파싱 방지)."""
    script = ctx.script
    root = ctx.root
    n = len(script)
    b2c = ctx.b2c
    cs = ctx.cs
    ce = ctx.ce
    text = ctx.text

    # --- 1. DFS: scope 노드 수집 + 테이블 field-key skip 범위 ---
    scope_nodes = []          # function 노드들
    skip: list[tuple[int, int]] = []
    stack = [root]
    while stack:
        node = stack.pop()
        t = node.type
        if t in _FUNC_TYPES:
            scope_nodes.append(node)
        elif t == "field":
            ch = node.children
            if len(ch) >= 2 and ch[0].type == "identifier" and ch[1].type == "=":
                k = ch[0]
                skip.append((cs(k), ce(k)))
        for c in node.children:
            stack.append(c)
    skip.sort()

    # --- 2. scope id 부여 + 범위 계산 ---
    # scopes[0] = None(chunk), scopes[i>=1] = function 노드
    scopes = [None] + scope_nodes
    nscopes = len(scopes)

    def scope_range(idx) -> tuple[int, int]:
        node = scopes[idx]
        if node is None:
            return (0, n - 1)
        # local function: 이름은 부모 scope 소속 → 범위를 parameters('(')부터 시작
        is_local_fn = (node.type == "function_declaration"
                       and node.children and node.children[0].type == "local")
        if is_local_fn:
            params = _first_child(node, "parameters")
            start = cs(params) if params else cs(node)
        else:
            start = cs(node)
        return (start, ce(node))

    ranges = {i: scope_range(i) for i in range(nscopes)}

    def size(i):
        s, e = ranges[i]
        return float("inf") if i == _CHUNK else e - s

    ids = list(range(nscopes))
    ids_asc = sorted(ids, key=size)
    ids_desc = sorted(ids, key=size, reverse=True)

    def closest(tstart, tstop) -> int:
        for i in ids_asc:
            if i == _CHUNK:
                return _CHUNK
            s, e = ranges[i]
            if s <= tstart and tstop <= e:
                return i
        return _CHUNK

    def parent_scope_of(node) -> int:
        ns, ne = cs(node), ce(node)
        for i in ids_asc:
            if i == _CHUNK:
                continue
            if scopes[i].id == node.id:
                continue
            s, e = ranges[i]
            if s <= ns and ne <= e:
                return i
        return _CHUNK

    # --- 3. 선언 이름 수집 (scope별) ---
    scope_names: dict[int, set[str]] = {i: set() for i in ids}

    # 함수 파라미터는 해당 함수 자신의 scope에
    for i in range(1, nscopes):
        params = _first_child(scopes[i], "parameters")
        if params:
            for c in params.children:
                if c.type == "identifier":
                    scope_names[i].add(text(c))

    stack = [root]
    while stack:
        node = stack.pop()
        t = node.type
        if t == "variable_declaration":
            # local x        → variable_list 가 직접 자식
            # local x = ...   → assignment_statement > variable_list
            asgn = _first_child(node, "assignment_statement")
            if asgn:
                vlist = _first_child(asgn, "variable_list")
            else:
                vlist = _first_child(node, "variable_list")
            if vlist:
                sid = closest(cs(node), ce(node))
                for c in vlist.children:
                    if c.type == "identifier":
                        scope_names[sid].add(text(c))
        elif t == "function_declaration":
            if node.children and node.children[0].type == "local":
                name = _first_child(node, "identifier")
                if name:
                    scope_names[parent_scope_of(node)].add(text(name))
        elif t == "for_statement":
            sid = closest(cs(node), ce(node))
            num = _first_child(node, "for_numeric_clause")
            if num:
                idn = _first_child(num, "identifier")
                if idn:
                    scope_names[sid].add(text(idn))
            gen = _first_child(node, "for_generic_clause")
            if gen:
                vlist = _first_child(gen, "variable_list")
                if vlist:
                    for c in vlist.children:
                        if c.type == "identifier":
                            scope_names[sid].add(text(c))
        for c in node.children:
            stack.append(c)

    # --- 4. scope별 rename map (부모 맵 상속) — 큰 scope부터 ---
    counter = [0]
    scope_maps: dict[int, dict[str, str]] = {}
    for i in ids_desc:
        parent_map: dict[str, str] = {}
        if i != _CHUNK:
            s_s, s_e = ranges[i]
            for pj in ids_asc:
                if pj != i and pj != _CHUNK:
                    p_s, p_e = ranges[pj]
                    if p_s <= s_s and s_e <= p_e:
                        parent_map = scope_maps[pj]
                        break
            if not parent_map:
                parent_map = scope_maps[_CHUNK]
        current = parent_map.copy()
        for name in sorted(scope_names[i], key=len, reverse=True):
            current[name] = f"_v{counter[0]}"
            counter[0] += 1
        scope_maps[i] = current

    # --- 5. scope 구간에서 자식 scope 구간을 빼서 겹치지 않게 ---
    scope_intervals = {i: [ranges[i]] for i in ids}
    for pj in ids:
        p_s, p_e = ranges[pj]
        for cj in ids:
            if pj == cj:
                continue
            c_s, c_e = ranges[cj]
            if p_s <= c_s and c_e <= p_e:
                scope_intervals[pj] = subtract_interval(scope_intervals[pj], c_s, c_e)

    # --- 6. 구간별 regex 치환 (뒤에서부터) ---
    all_ops = []
    for i in ids:
        for s, e in scope_intervals[i]:
            if s <= e:
                all_ops.append((s, e, scope_maps[i]))
    all_ops.sort(key=lambda x: x[0], reverse=True)

    result = script
    for s, e, name_map in all_ops:
        new_seg = _rename_segment(result[s:e + 1], name_map, s, skip)
        result = result[:s] + new_seg + result[e + 1:]
    return result
