"""Public rename pass; all backends share the lexical name planner."""
from .base import BasePass, Replacement
from .rename_ts import rename_with_ctx, rename_script_ts


class RenameObfuscationPass(BasePass):
    parser = "treesitter"

    def __init__(self, *, seed=None, readable=None):
        self.options = {"seed": seed, "readable": readable}

    def run(self, script, tree):
        return [Replacement(0, len(script) - 1, rename_with_ctx(tree, **self.options))]

    def _run_luaparser(self, script, tree):
        return [Replacement(0, len(script) - 1, rename_script_ts(script, **self.options))]
