import random

from .base import BasePass, Replacement


randint = random.randint
def generate_rand_xor():
    first   = randint(-54271900, 59183000)
    second  = randint(-8102000, 8102000)
    xor     = first ^ second
    return first, second, xor


class BooleanObfuscationPass(BasePass):
    parser = "treesitter"

    def run(self, script: str, tree) -> list[Replacement]:
        replacements: list[Replacement] = []

        for node in tree.walk():
            if node.type == "true":
                first, second, xor = generate_rand_xor()
                replacements.append(Replacement(
                    start    = tree.cs(node),
                    end      = tree.ce(node),
                    new_text = f"(({first}~{second})=={xor})"
                ))
            elif node.type == "false":
                first, second, xor = generate_rand_xor()
                replacements.append(Replacement(
                    start    = tree.cs(node),
                    end      = tree.ce(node),
                    new_text = f"(({first}~{second})=={xor+1})"
                ))

        return replacements