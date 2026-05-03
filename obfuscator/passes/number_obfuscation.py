import random

from luaparser import astnodes
from .base import BasePass, Replacement

class NumberObfuscationPass(BasePass):
    """
    a = 10
    
    to

    a = (203292562~203292568)
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