"""
전역 표준 라이브러리/내장 함수 접근을 `_ENV` 체인 로컬로 hoist하는 패스.

문제: `string_obf`는 문자열 리터럴을 `string.char(...)`로 인코딩하고
(string_obfuscation._encode), VM junk/mutation은 `math.max`, `type`,
`tostring`, `error` 같은 raw 전역을 주입한다(vm_mutation/junk_injection/
anti_debug). 그 결과 최종 출력에 `string.char`/`math.*`/`type`/`tostring`
등 raw 전역 접근이 대량으로 노출된다.

이 패스가 그것들을 한곳에 모아, 그 접근들을 모두 감싸는 가장 바깥 함수
본문 최상단에 아래 형태의 `_ENV` 체인으로 단 한 번씩 선언하고 모든
사용처를 별칭으로 치환한다(사용자가 요청한 스타일):

    local _E   = _ENV
    local _L0  = _E["string"]     -- 라이브러리 테이블
    local _L1  = _L0["char"]      -- string.char
    local _L2  = _E["math"]
    local _L3  = _L2["max"]       -- math.max
    local _L4  = _E["type"]       -- bare 전역
    local _L5  = _E["tostring"]
    ...

이 패스가 *유일한* 로컬화 지점이다(vm.lua의 수동 별칭 블록은 제거되어
본문이 raw 전역을 쓰며, 그것을 여기서 일괄 로컬화한다).

VM 출력 재난독화(vm_output_passes)에서 `string_obf`/`rename_obf` 이후,
그리고 minify/dump 이전(마지막 base 패스)에 실행해야 한다:
- string_obf가 생성한 `string.char`까지 잡으려면 그 *뒤*여야 하고,
- 이 패스가 emit하는 `_E["string"]` 같은 문자열 키가 다시 인코딩되지
  않으려면(순환 방지) string_obf 뒤여야 하며,
- dump 이후 본문을 바꾸면 `_vmf` 무결성 crc가 깨지므로 dump 전이어야 한다.
별칭을 바깥 함수 본문 *안*에 선언하는 이유: dump/load되는 것은 그 함수
자신이므로, 함수 밖(chunk) local이면 load 후 upvalue가 nil이 된다.
"""
from __future__ import annotations

import re

from .base import BasePass, Replacement


# `lib.method` 형태로 등장하는 표준 라이브러리 테이블.
_KNOWN_LIBS = {
    "string", "math", "table", "os", "io",
    "coroutine", "utf8", "bit32", "debug",
}

# bare 식별자로 등장하는 표준 전역 함수/값. 이 패스는 rename_obf *이후*에
# 돌기 때문에, 사용자/VM의 모든 로컬은 이미 `_vN`으로 개명되어 있다. 따라서
# 이 이름들과 일치하는 bare 식별자는 (필드/메서드/테이블키가 아닌 한) 반드시
# 전역이다.
_KNOWN_GLOBAL_FUNCS = {
    "type", "tostring", "tonumber", "pairs", "ipairs", "next", "select",
    "setmetatable", "getmetatable", "rawget", "rawset", "rawequal", "rawlen",
    "error", "assert", "pcall", "xpcall", "print", "load", "loadstring",
    "require", "collectgarbage", "unpack",
}


def _alloc_names(script: str, count: int) -> list[str]:
    """script에 아직 없는 `_v` 계열 이름 count개. rename_obf의 `_v<digits>`와
    충돌하지 않도록 기존 이름을 피한다."""
    existing = set(re.findall(r'_v\d+', script))
    names: list[str] = []
    n = 900000
    while len(names) < count:
        cand = f"_v{n}"
        n += 1
        if cand not in existing:
            names.append(cand)
    return names


def _is_global_ref(node) -> bool:
    """bare 식별자 node가 전역 *참조*인지(필드/메서드명/테이블키/할당대상/
    파라미터가 아닌지) 판정한다."""
    p = node.parent
    if p is None:
        return False
    pt = p.type
    # `a.type` / `a:type()` 의 필드·메서드명, 혹은 인덱스 베이스 → 스킵.
    if pt in ("dot_index_expression", "method_index_expression"):
        return False
    # `{ type = ... }` 의 테이블 키(=가 있는 name 필드의 첫 자식) → 스킵.
    if pt == "field":
        if p.children and p.children[0] is node and len(p.children) > 1:
            return False
    # 할당 대상(LHS), 함수 선언 이름, 파라미터 → 스킵.
    if pt in ("variable_list", "function_declaration", "function_definition", "parameters"):
        return False
    return True


class LocalizeGlobalsPass(BasePass):
    """전역 lib.method / bare 전역 함수를 `_ENV` 체인 로컬로 hoist."""

    parser = "treesitter"

    def run(self, script: str, ctx) -> list[Replacement]:
        # (lib, method) -> [(start,end), ...]    /    func -> [(start,end), ...]
        lib_spans: dict[tuple[str, str], list[tuple[int, int]]] = {}
        func_spans: dict[str, list[tuple[int, int]]] = {}

        for node in ctx.walk():
            if node.type == "dot_index_expression":
                base = node.children[0] if node.children else None
                field = node.children[-1] if node.children else None
                if (base is None or field is None
                        or base.type != "identifier" or field.type != "identifier"):
                    continue
                lib = ctx.text(base)
                if lib not in _KNOWN_LIBS:
                    continue
                lib_spans.setdefault((lib, ctx.text(field)), []).append(
                    (ctx.cs(node), ctx.ce(node)))

            elif node.type == "identifier":
                name = ctx.text(node)
                if name not in _KNOWN_GLOBAL_FUNCS:
                    continue
                if not _is_global_ref(node):
                    continue
                func_spans.setdefault(name, []).append((ctx.cs(node), ctx.ce(node)))

        if not lib_spans and not func_spans:
            return []

        # --- 이름 배정 ---------------------------------------------------
        libs_used = sorted({lib for (lib, _m) in lib_spans})
        leaves    = sorted(lib_spans.keys())
        funcs     = sorted(func_spans.keys())

        # 1(_E) + libs + leaves + funcs 개수만큼 이름이 필요.
        names = _alloc_names(script, 1 + len(libs_used) + len(leaves) + len(funcs))
        it = iter(names)
        env_name  = next(it)
        lib_name  = {lib: next(it) for lib in libs_used}
        leaf_name = {key: next(it) for key in leaves}
        func_name = {fn: next(it) for fn in funcs}

        # --- 선언 블록 (의존 순서: _E -> lib 테이블 -> leaf/func) --------
        decls = [f"local {env_name}=_ENV "]
        for lib in libs_used:
            decls.append(f'local {lib_name[lib]}={env_name}["{lib}"] ')
        for (lib, method) in leaves:
            decls.append(f'local {leaf_name[(lib, method)]}={lib_name[lib]}["{method}"] ')
        for fn in funcs:
            decls.append(f'local {func_name[fn]}={env_name}["{fn}"] ')
        decl_text = "".join(decls)

        # --- 치환 + 삽입 -------------------------------------------------
        replacements: list[Replacement] = []
        all_starts: list[int] = []
        all_ends: list[int] = []
        for key, spans in lib_spans.items():
            nm = leaf_name[key]
            for s, e in spans:
                replacements.append(Replacement(start=s, end=e, new_text=nm))
                all_starts.append(s); all_ends.append(e)
        for fn, spans in func_spans.items():
            nm = func_name[fn]
            for s, e in spans:
                replacements.append(Replacement(start=s, end=e, new_text=nm))
                all_starts.append(s); all_ends.append(e)

        insert_pos = self._outermost_body_start(ctx, min(all_starts), max(all_ends))
        replacements.append(Replacement(start=insert_pos, end=insert_pos - 1, new_text=decl_text))
        return replacements

    @staticmethod
    def _outermost_body_start(ctx, amin: int, amax: int) -> int:
        """[amin, amax]를 모두 포함하는 가장 바깥 함수 본문 block의 시작 char
        위치. 그런 함수가 없으면 chunk 최상단(0)."""
        best_start = 0
        best_span = -1
        for n in ctx.walk():
            if n.type not in ("function_definition", "function_declaration"):
                continue
            b = ctx.first_child(n, "block")
            if b is None:
                continue
            bs, be = ctx.cs(b), ctx.ce(b)
            if bs <= amin and amax <= be and (be - bs) > best_span:
                best_span = be - bs
                best_start = bs
        return best_start
