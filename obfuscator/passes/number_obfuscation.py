import random

from .base import BasePass, Replacement
from .number_expressions import NumberExpressionEngine
from .numeric_provenance import protected_number, number_origin


class NumberObfuscationPass(NumberExpressionEngine, BasePass):
    parser = "treesitter"

    def run(
        self,
        script: str,
        tree,
    ) -> list[Replacement]:
        replacements: list[Replacement] = []
        self.last_skipped_generated_count = 0
        from .literal_mosaic import ACTIVE
        mosaic = ACTIVE.get()

        for node in tree.walk():
            if node.type != "number":
                continue
            if protected_number(script, tree.cs(node), tree.ce(node)+1):
                self.last_skipped_generated_count += 1
                continue
            token = tree.text(node)

            expr = mosaic.original_number(token,engine=self,origin=number_origin(script,tree.cs(node),tree.ce(node)+1)) if mosaic is not None else self.obfuscate_token(token)

            replacements.append(
                Replacement(
                    start=tree.cs(node),
                    end=tree.ce(node),
                    new_text=expr,
                )
            )

        if mosaic is not None:
            mosaic.metrics.skip(mosaic.policy.phase+':number_obf',self.last_skipped_generated_count)
        self.last_profile = [{"phase": "number_origins", "elapsed": 0.0,
                              "protected_generated_numbers": self.last_skipped_generated_count,
                              "source_replacements": len(replacements)}]
        return replacements
