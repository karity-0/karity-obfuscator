import random

from luaparser import astnodes
from .base import BasePass, Replacement

class NumberObfuscationPass(BasePass):
    """
    x = 10
    print(x, 30)

    ->

    x = (1+5-3+7)
    print(x, (20+15-5))
    """
    
    def run(self, script: str, tree) -> list[Replacement]:
        replacements: list[Replacement] = []

        for node in self.walk(tree):
            if isinstance(node, astnodes.Number):
                rand    = random.randint(10000, 999999999)
                xor     = rand ^ node.n
                replacements.append(Replacement(
                    start    = node.start_char,
                    end      = node.stop_char,
                    new_text = f"({xor}~{rand})",
                ))

        return replacements