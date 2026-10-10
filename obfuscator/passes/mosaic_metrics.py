"""Metrics on generated expressions, never a reparse of the final Lua file."""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import re

_TOKENS = re.compile(
    r'(?P<string>"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')'
    r'|(?P<number>0[xX](?:[\da-fA-F]+(?:\.[\da-fA-F]*)?|\.[\da-fA-F]+)(?:[pP][+-]?\d+)?'
    r'|(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)'
    r'|(?P<name>[a-zA-Z_]\w*)|(?P<op>//|<<|>>|[+*/%^&|~#-])|(?P<paren>[()])'
)


def expression_summary(expression):
    literals, families = Counter(), Counter()
    operators = 0
    operand = True
    for match in _TOKENS.finditer(expression):
        token, kind = match.group(), match.lastgroup
        if kind == 'number':
            lowered = token.lower()
            if lowered.startswith('0x'):
                family = 'hex_float' if '.' in lowered or 'p' in lowered else 'hex_integer'
            else:
                family = 'decimal_scientific' if 'e' in lowered else ('decimal_float' if '.' in lowered else 'decimal_integer')
            literals[family] += 1
            if token.startswith('0X'): literals['uppercase_hex_prefix'] += 1
            if 'P' in token: literals['uppercase_hex_exponent'] += 1
            if not lowered.startswith('0x') and 'E' in token: literals['uppercase_decimal_exponent'] += 1
            if token.startswith('.'): literals['leading_dot'] += 1
            if token.lower().startswith('0x.'): literals['leading_hex_dot'] += 1
            operand = False
        elif kind in ('name', 'string'):
            operand = False
        elif kind == 'op':
            operators += 1
            family = ('string_length' if token == '#' else 'floor_division' if token == '//'
                      else 'modulo' if token == '%' else 'shift' if token in ('<<','>>')
                      else 'bitwise' if token in ('&','|','~') else 'arithmetic')
            families[family] += 1
            if operand and token in ('-', '~', '#'): families['unary'] += 1
            operand = True
        else:
            operand = token == '('
    return literals, families, operators


def structural_fingerprint(expression):
    from .ts_utils import parse
    ctx = parse('return ' + expression)
    if ctx.root.has_error:
        raise RuntimeError('Literal Mosaic metric received an invalid generated expression')
    root = next(n for n in ctx.walk() if n.type == 'return_statement')

    def normalized(node):
        if node.type in ('number', 'string', 'identifier'):
            return {'number':'N','string':'S','identifier':'I'}[node.type], 0
        children = [n for n in node.children if n.type != 'comment']
        if node.type == 'parenthesized_expression':
            return normalized(next(n for n in children if n.is_named))
        named = [normalized(n) for n in children if n.is_named]
        operators = ''.join(ctx.text(n) for n in children if not n.is_named
                            and ctx.text(n) not in ('(',')','return',','))
        shape = node.type + operators + '(' + ','.join(n[0] for n in named) + ')'
        return shape, max((n[1] for n in named), default=-1) + 1

    shape, depth = normalized(root.named_children[0])
    return hashlib.sha256(shape.encode()).hexdigest()[:20], shape[:256], depth


class DiversityMetrics:
    # Detailed AST work is bounded per phase/strategy; all lexical counts are
    # complete. No random sampling touches the obfuscator's PRNG sequence.
    STRUCTURAL_SAMPLE_LIMIT = 128

    def __init__(self, enabled=False):
        self.enabled = enabled
        self.total = self.length = self.operators = 0
        self.length_max = self.operators_max = 0
        self.strategies, self.origins, self.phases = Counter(), Counter(), Counter()
        self.literals, self.families, self.classes = Counter(), Counter(), Counter()
        self.skips, self.fallbacks = Counter(), Counter()
        self.costs = defaultdict(lambda: [0,0,0])
        self.samples = Counter()
        self.fingerprints, self.shapes = Counter(), {}
        self.depth_sum = self.depth_max = 0

    def record(self, expression, strategy, origin, phase, *, fallback=False):
        if not self.enabled: return
        self.total += 1
        self.length += len(expression)
        self.length_max = max(self.length_max,len(expression))
        literals, families, count = expression_summary(expression)
        self.operators += count
        self.operators_max = max(self.operators_max,count)
        self.literals.update(literals); self.families.update(families)
        self.strategies[strategy] += 1; self.origins[origin] += 1; self.phases[phase] += 1
        if fallback: self.fallbacks[strategy] += 1
        costs = self.costs[strategy]
        # Conservative load/operator estimate, not a Lua compiler measurement.
        costs[0] += 1; costs[1] += count; costs[2] += sum(literals[k] for k in
            ('hex_float','hex_integer','decimal_float','decimal_scientific','decimal_integer')) + 2*count
        if not count: category = 'single_literal'
        elif families['string_length']: category = 'meme_strings'
        elif families['bitwise'] or families['shift']: category = 'mixed_bitwise'
        elif count == 1: category = 'unary_expression' if families['unary'] else 'simple_binary'
        else: category = 'nested_arithmetic'
        self.classes[category] += 1
        if len(set(families)-{'unary'}) > 1: self.classes['mixed_operators'] += 1
        if any(literals[k] for k in ('decimal_float','decimal_scientific','hex_float')) and any(
                literals[k] for k in ('decimal_integer','hex_integer')):
            self.classes['integer_float_mixed'] += 1
        if count >= 5: self.classes['complex_expression_tree'] += 1
        sample_key = (phase, strategy)
        if self.samples[sample_key] < self.STRUCTURAL_SAMPLE_LIMIT:
            fingerprint, shape, depth = structural_fingerprint(expression)
            self.samples[sample_key] += 1
            self.fingerprints[fingerprint] += 1; self.shapes[fingerprint] = shape
            self.depth_sum += depth; self.depth_max = max(self.depth_max,depth)

    def skip(self, phase, count):
        if self.enabled: self.skips[phase] += count

    def report(self):
        samples = sum(self.samples.values())
        return {
            'purpose': 'visual style diagnostics, not protection strength',
            'expressions': self.total, 'strategies': dict(self.strategies),
            'strategy_ratios': {k:v/self.total for k,v in self.strategies.items()} if self.total else {},
            'origins': dict(self.origins), 'phases': dict(self.phases),
            'literal_notation': dict(self.literals), 'operator_families': dict(self.families),
            'expression_classes': dict(self.classes),
            'average_operators': self.operators/self.total if self.total else 0,
            'average_characters': self.length/self.total if self.total else 0,
            'max_operators': self.operators_max, 'max_characters': self.length_max,
            'sampled_average_depth': self.depth_sum/samples if samples else 0,
            'sampled_max_depth': self.depth_max, 'structural_samples': samples,
            'structural_sample_limit_per_phase_strategy': self.STRUCTURAL_SAMPLE_LIMIT,
            'unique_sampled_structures': len(self.fingerprints),
            'sample_status': 'insufficient' if samples < 32 else 'bounded_sample',
            'repeated_sampled_patterns': [{'fingerprint':k,'shape':self.shapes[k],'count':v}
                for k,v in self.fingerprints.most_common(10)],
            'estimated_costs': {k:{'expressions':v[0],'average_operators':v[1]/v[0],
                'average_instructions':v[2]/v[0]} for k,v in self.costs.items()},
            'budget_fallbacks': dict(self.fallbacks), 'duplicate_prevention':dict(self.skips),
        }
