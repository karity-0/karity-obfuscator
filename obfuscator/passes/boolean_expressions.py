"""Bounded boolean programs shared by source and generated VM output."""
from __future__ import annotations

import random

from .number_expressions import NumberExpressionEngine
from .numeric_provenance import CodeText, join_code


def validate_options(options):
    if not isinstance(options, dict) or set(options) - {'mode'}:
        raise ValueError('boolean_obf_options accepts only mode')
    if options.get('mode', 'expression') not in ('expression', 'dataflow', 'mixed'):
        raise ValueError('boolean_obf_options.mode must be expression, dataflow, or mixed')


class BooleanExpressionEngine:
    def __init__(self):
        self.numbers = NumberExpressionEngine()
        self.last_strategy = ''

    def number(self, value):
        from .literal_mosaic import ACTIVE
        mosaic = ACTIVE.get()
        fallback = lambda: self.numbers.generated_int(value, max_chars=80, max_operations=1)
        if mosaic is not None:
            expression = mosaic.number(value, context='boolean_constant', hot=True,
                                       max_chars=80, max_operations=1, fallback=fallback)
        else:
            expression = fallback()
        return CodeText(expression, protected=[(0, len(expression))],
                        origins=getattr(expression, 'origins', ()) or [(0, len(expression), 'boolean_constant')])

    def generate(self, value: bool, *, allocator=None, dataflow=False):
        # Intermediates fit in exact binary64 integers and signed Lua words.
        a, b = random.randint(1, 65535), random.randint(1, 255)
        family = random.choice(('sum', 'difference', 'product', 'xor', 'mask', 'mba'))
        self.last_strategy = family
        left, right = self.number(a), self.number(b)
        expressions = {'sum': ('+', a+b), 'difference': ('-', a-b),
                       'product': ('*', a*b), 'xor': ('~', a^b)}
        if dataflow:
            if allocator is None:
                raise ValueError('boolean dataflow requires a source name allocator')
            x, y = allocator.allocate('boolean_state'), allocator.allocate('boolean_key')
            prefix = join_code(('(function() local ', x, '=', left, ';local ', y, '=', right, ';'))
            left, right = x, y
        else:
            prefix = ''
        if family in expressions:
            operator, expected = expressions[family]
            calculation = join_code(('(', left, operator, right, ')'))
        elif family == 'mask':
            calculation = join_code(('((', left, '|', right, ')&', left, ')'))
            expected = a
        else:
            factor = CodeText('2', protected=[(0, 1)], origins=[(0, 1, 'boolean_constant')])
            calculation = join_code(('((', left, '~', right, ')+', factor, '*(', left, '&', right, '))'))
            expected = a+b
        inequality = bool(random.getrandbits(1))
        comparison = self.number(expected if value != inequality else expected+1)
        operator = '~=' if inequality else '=='
        if dataflow:
            body = join_code((prefix, x, '=', calculation, ';', y, '=', comparison,
                              ';return ', x, operator, y, ' end)()'))
            return CodeText(body, getattr(body, 'protected', ()), [(0, len(body))],
                            getattr(body, 'origins', ()))
        return join_code(('(', calculation, operator, comparison, ')'))
