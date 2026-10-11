"""Replace a random subset of numeric literals with fun string arithmetic."""
import random

from .base import BasePass, Replacement
from .numeric_provenance import protected_number, number_origin
from .meme_expressions import MemeExpressionEngine, MEME_STRINGS, STRINGS_BY_LENGTH


class MemeStringsPass(MemeExpressionEngine, BasePass):
    parser = "treesitter"
    replacement_rate = 0.35

    def run(self, script: str, tree) -> list[Replacement]:
        replacements = []
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
            if random.random() >= self.replacement_rate:
                continue
            # Parentheses preserve precedence in powers and adjacent unary ops.
            replacements.append(Replacement(
                tree.cs(node), tree.ce(node), mosaic.original_meme(token,engine=self,origin=number_origin(script,tree.cs(node),tree.ce(node)+1))
                if mosaic is not None else self.obfuscate_token(token),
            ))
        if mosaic is not None:
            mosaic.metrics.skip(mosaic.policy.phase+':meme_strings',self.last_skipped_generated_count)
        self.last_profile = [{'phase':'meme_origins','elapsed':0.0,
                              'protected_generated_numbers':self.last_skipped_generated_count,
                              'source_replacements':len(replacements)}]
        return replacements
