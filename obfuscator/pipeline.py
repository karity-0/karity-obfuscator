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
    HEADER = "-- obfuscated!\n"

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
            info_message("PRE", pre, f"{elapsed:.3f}s")

        for pass_ in self._passes:
            tree = ast.parse(script)
            start = time.perf_counter()
            replacements = pass_.run(script, tree)
            elapsed = time.perf_counter() - start
            info_message("BASE", pass_, f"{elapsed:.3f}s")

            script = self._apply(script, replacements)
            if verbose >= Verbosity.NORMAL:
                sep = "-" * 40
                print(f"\n{sep} {pass_.__class__.__name__} {sep}")
                print(script)
                if verbose >= Verbosity.DEBUG:
                    new_tree = ast.parse(script)
                    print(ast.to_pretty_str(new_tree))


        for post in self._post_passes:
            start = time.perf_counter()
            script = post.run(script)
            elapsed = time.perf_counter() - start
            info_message("POST", post, f"{elapsed:.3f}s")

        return f"{self.HEADER}{script}" if self.show_header else script
    
    def _apply(self, src: str, replacements: list[Replacement]) -> str:
        for r in sorted(replacements, key=lambda r: r.start, reverse=True):
            src = src[: r.start] + r.new_text + src[r.end + 1 :]
        return src