import random
import time
from collections import Counter
from contextlib import nullcontext

from ..names import NameAllocator
from .base import BasePass, Replacement
from .boolean_expressions import BooleanExpressionEngine, validate_options


def generate_rand_xor():
    """Legacy helper retained for callers; new emitters use the shared engine."""
    first = random.randint(-54271900, 59183000)
    second = random.randint(-8102000, 8102000)
    return first, second, first ^ second


class BooleanObfuscationPass(BasePass):
    parser = "treesitter"

    def __init__(self, **options):
        validate_options(options)
        self.options = options
        self.engine = BooleanExpressionEngine()

    def run(self, script, tree):
        started = time.perf_counter()
        from .literal_mosaic import ACTIVE
        mode = self.options.get('mode', 'expression')
        allocator = NameAllocator.for_source(script, seed=random.getrandbits(64)) if mode != 'expression' else None
        mosaic = ACTIVE.get()
        replacements, strategies = [], Counter()
        dataflow_count = 0
        for node in tree.walk():
            if node.type not in {'true', 'false'}:
                continue
            dataflow = mode == 'dataflow' or (mode == 'mixed' and bool(random.getrandbits(1)))
            with mosaic.at(tree.cs(node), tree.ce(node)+1) if mosaic is not None else nullcontext():
                expression = self.engine.generate(node.type == 'true', allocator=allocator, dataflow=dataflow)
            strategies[self.engine.last_strategy] += 1
            dataflow_count += dataflow
            replacements.append(Replacement(tree.cs(node), tree.ce(node), expression))
        self.last_profile = [{'phase': 'boolean_generation', 'elapsed': time.perf_counter()-started,
                              'boolean_literals': len(replacements), 'dataflow_programs': dataflow_count,
                              'strategies': dict(strategies)}]
        return replacements
