import random

from luaparser import astnodes
from .base import BasePass, Replacement


randint = random.randint
def generate_rand_xor():
    first   = randint(-54271900, 59183000)
    second  = randint(-8102000, 8102000)
    xor     = first ^ second
    return first, second, xor


class BooleanObfuscationPass(BasePass):
    def run(self, script: str, tree) -> list[Replacement]:
        replacements: list[Replacement] = []

        for node in self.walk(tree):
            if isinstance(node, astnodes.TrueExpr):
                first, second, xor = generate_rand_xor()

                replacements.append(Replacement(
                    start    = node.start_char,
                    end      = node.stop_char,
                    new_text = f"(({first}~{second})=={xor})"
                ))

            elif isinstance(node, astnodes.FalseExpr):
                first, second, xor = generate_rand_xor()

                replacements.append(Replacement(
                    start    = node.start_char,
                    end      = node.stop_char,
                    new_text = f"(({first}~{second})=={xor+1})"
                ))

        return replacements