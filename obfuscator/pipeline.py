from __future__ import annotations
from luaparser import ast
from .passes.base import BasePass, PrePass, PostPass, Replacement


class Pipeline:
    HEADER = "-- obfuscated!\n"

    def __init__(self):
        self._pre_passes: list[PrePass] = []
        self._passes: list[BasePass] = []
        self._post_passes: list[PostPass] = []

    def add(self, pass_: BasePass | PrePass) -> Pipeline:
        if isinstance(pass_, PrePass):
            self._pre_passes.append(pass_)
        elif isinstance(pass_, PostPass):
            self._post_passes.append(pass_)
        else:
            self._passes.append(pass_)
        return self

    def run(self, script: str, verbose: bool = False) -> str:
        for pre in self._pre_passes:
            script = pre.run(script)

        for pass_ in self._passes:
            tree = ast.parse(script)
            if verbose:
                print("tree:", ast.to_pretty_str(tree))
                print("source:", ast.to_lua_source(tree))

            replacements = pass_.run(script, tree)
            script = self._apply(script, replacements)

        for post in self._post_passes:
            script = post.run(script)

        return f"{self.HEADER}{script}"
    
    def _apply(self, src: str, replacements: list[Replacement]) -> str:
        for r in sorted(replacements, key=lambda r: r.start, reverse=True):
            src = src[: r.start] + r.new_text + src[r.end + 1 :]
        return src