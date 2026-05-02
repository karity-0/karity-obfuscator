from luaparser import ast
from .passes.base import BasePass, Replacement


class Pipeline:
    HEADER = "-- obfuscated!\n"

    def __init__(self):
        self._passes: list[BasePass] = []

    def add(self, pass_: BasePass) -> "Pipeline":
        self._passes.append(pass_)
        return self

    def run(self, script: str, verbose: bool = False) -> str:
        tree = ast.parse(script)

        if verbose:
            print("tree:", ast.to_pretty_str(tree))

        all_replacements: list[Replacement] = []
        for pass_ in self._passes:
            all_replacements.extend(pass_.run(script, tree))

        return self._apply(script, all_replacements)

    # ------------------------------------------------------------------

    # ------------------------------------------------------------------

    def _apply(self, src: str, replacements: list[Replacement]) -> str:
        for r in sorted(replacements, key=lambda r: r.start, reverse=True):
            src = src[: r.start] + r.new_text + src[r.end + 1 :]
        return self.HEADER + src