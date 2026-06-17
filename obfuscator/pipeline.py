from __future__ import annotations

import time
from typing import Union

from luaparser import ast
from .verbosity import Verbosity
from .passes.base import BasePass, PrePass, PostPass, Replacement


PassType = Union[BasePass, PrePass, PostPass]
def info_message(step: str, p: PassType, message: str):
    print(f"[{step}] {p.__class__.__name__}: {message}")


class Pipeline:
    HEADER = "-- obfuscated using karity obfuscator!\n"

    def __init__(self, show_header: bool = True):
        self._pre_passes: list[PrePass] = []
        self._passes: list[BasePass] = []
        self._post_passes: list[PostPass] = []

        self.show_header = show_header

    def add(self, pass_: BasePass | PrePass) -> Pipeline:
        if isinstance(pass_, PrePass):
            self._pre_passes.append(pass_)
        elif isinstance(pass_, PostPass):
            self._post_passes.append(pass_)
        else:
            self._passes.append(pass_)
        return self

    def run(self, script: str, verbose: int = 0) -> str:
        for pre in self._pre_passes:
            start = time.perf_counter()
            script = pre.run(script)
            elapsed = time.perf_counter() - start
            if verbose >= Verbosity.NORMAL:
                info_message("PRE", pre, f"{elapsed:.3f}s")

        for pass_ in self._passes:
            start = time.perf_counter()
            # 패스별 파서 선택: parser="treesitter"면 tree-sitter(빠름),
            # 아니면 기존 luaparser. 큰 VM 출력을 다루는 패스는 tree-sitter로
            # 파싱 비용(~90%)을 줄인다.
            if getattr(pass_, "parser", "luaparser") == "treesitter":
                from .passes.ts_utils import parse as _ts_parse
                tree = _ts_parse(script)
            else:
                tree = ast.parse(script)
            replacements = pass_.run(script, tree)
            elapsed = time.perf_counter() - start
            if verbose >= Verbosity.NORMAL:
                info_message("BASE", pass_, f"{elapsed:.3f}s")

            script = self._apply(script, replacements)
            if verbose >= Verbosity.DEBUG:
                #sep = "-" * 40
                #print(f"\n{sep} {pass_.__class__.__name__} {sep}")
                #print(script)
                new_tree = ast.parse(script)
                print(ast.to_pretty_str(new_tree))


        for post in self._post_passes:
            start = time.perf_counter()
            script = post.run(script)
            elapsed = time.perf_counter() - start
            if verbose >= Verbosity.NORMAL:
                info_message("POST", post, f"{elapsed:.3f}s")

        return f"{self.HEADER}{script}" if self.show_header else script
    
    def _apply(self, src: str, replacements: list[Replacement]) -> str:
        # 치환들은 서로 겹치지 않으므로 한 번만 순회하며 세그먼트를 모아
        # join한다 (치환마다 전체 문자열을 재생성하면 O(n²)이라, 큰 VM
        # 출력에서 빌드 시간을 지배했다 — 여기서 O(n)으로 만든다).
        if not replacements:
            return src
        parts: list[str] = []
        pos = 0
        for r in sorted(replacements, key=lambda r: r.start):
            parts.append(src[pos:r.start])
            parts.append(r.new_text)
            pos = r.end + 1
        parts.append(src[pos:])
        return "".join(parts)