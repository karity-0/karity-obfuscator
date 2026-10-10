"""Scoped literal generation policy over the existing numeric/meme engines.

This is an internal service, not a pass. Policy scopes carry actual pass names,
target, source selections and phase; nested output stages never inherit flags.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import math
import random

from .number_expressions import NumberExpressionEngine
from .meme_expressions import MemeExpressionEngine
from .mosaic_metrics import DiversityMetrics, expression_summary

ACTIVE: ContextVar[LiteralMosaic | None] = ContextVar('literal_mosaic', default=None)


@dataclass(frozen=True)
class MosaicPolicy:
    passes: frozenset[str] = frozenset()
    lua_version: str = '5.3'
    phase: str = 'source'
    style: str = 'balanced'
    cost: str = 'auto'
    generated_meme_rate: float = 0.15
    max_chars: int = 192
    max_operations: int = 12


class LiteralMosaic:
    def __init__(self, passes=(), *, lua_version='5.3', phase='source', options=None,
                 metrics=None, selection=None):
        options = options or {}
        self.options = options
        self.policy = MosaicPolicy(frozenset(passes), lua_version, phase,
            options.get('style','balanced'), options.get('cost','auto'),
            options.get('generated_meme_rate',0.15), options.get('max_chars',192),
            options.get('max_operations',12))
        self.metrics = metrics or DiversityMetrics(options.get('diversity_metrics',False))
        self.selection = selection
        self.engine = NumberExpressionEngine()
        self.memes = MemeExpressionEngine()
        self._allowed = None

    def enabled(self, name):
        if self.policy.phase == 'vm_internal': return False
        if self.selection is not None and self._allowed is None: return False
        return name in self.policy.passes and (self._allowed is None or name in self._allowed)

    @contextmanager
    def at(self, start, end):
        previous = self._allowed
        self._allowed = {name for name in ('number_obf','meme_strings')
                         if name in self.policy.passes and (self.selection is None
                         or self.selection.selected(name,start,end))}
        try:
            yield self
        finally:
            self._allowed = previous

    def original_number(self, token, *, engine=None, origin='source_number'):
        # Existing explicit Number/Meme stages retain their seeded generation
        # and layering. Only generated Mosaic expressions become protected.
        expression = (engine or self.engine).obfuscate_token(token)
        self.metrics.record(expression,'number_full',origin,self.policy.phase)
        from .numeric_provenance import CodeText
        return CodeText(expression,origins=[(0,len(expression),origin)])

    def original_meme(self, token, *, engine=None, origin='source_number'):
        expression = (engine or self.memes).obfuscate_token(token)
        self.metrics.record(expression,'meme_original',origin,self.policy.phase)
        from .numeric_provenance import CodeText
        return CodeText(expression,origins=[(0,len(expression),'meme_expression')])

    def number(self, value, *, context='function_constant', hot=False,
               max_chars=None, max_operations=None, fallback=None):
        policy = self.policy
        self._plain(value)  # Validate before selecting any strategy.
        if isinstance(value,int) and policy.lua_version == '5.3' and not -(1 << 63) <= value < (1 << 63):
            raise ValueError('Literal Mosaic integer outside Lua 5.3 signed integer domain')
        chars = min(policy.max_chars, max_chars if max_chars is not None else policy.max_chars)
        operations = min(policy.max_operations, max_operations if max_operations is not None else policy.max_operations)
        cost_limit = {'low':3,'medium':12,'high':20}.get(policy.cost,3 if hot else 12)
        operations = min(operations,cost_limit)
        number_on, meme_on = self.enabled('number_obf'), self.enabled('meme_strings')
        if not number_on and not meme_on:
            return fallback() if fallback is not None else '(' + self._plain(value) + ')'

        strategy = 'number_literal' if number_on else 'mandatory_literal'
        expression = None
        if meme_on and random.random() < policy.generated_meme_rate:
            if isinstance(value,int):
                expression = self.memes.generated_int(value,lua_version=policy.lua_version,depth=1)
            else:
                expression = self.memes.float_zero(self._plain(value))
                if value == 0 and math.copysign(1,value)<0:
                    expression = '-(' + self.memes.float_zero('0.0') + ')'
            strategy = 'meme_generated'
        if expression is None and number_on:
            if isinstance(value,int):
                if (operations >= 12 and policy.style != 'compact' and not hot
                        and policy.lua_version == '5.3' and abs(value) <= (1 << 53)-1-8_000_000):
                    expression = self.engine.obfuscate_token(str(value))
                    strategy = 'number_full'
                elif policy.style != 'compact' and operations >= 1 and random.getrandbits(1):
                    portable = self.engine.portable
                    self.engine.portable = policy.lua_version == '5.1'
                    try:
                        if abs(value) <= (1 << 53)-1-2_000_000:
                            expression = self.engine.mosaic_int(value,1 if hot or operations < 3 else 2)
                            strategy = 'number_bounded'
                    finally:
                        self.engine.portable = portable
            if expression is None:
                expression = self._literal(value,exotic=policy.style != 'compact' or random.getrandbits(1))
        if expression is None:
            expression = fallback() if fallback is not None else '(' + self._plain(value) + ')'
        over_budget = len(expression) > chars or expression_summary(expression)[2] > operations
        if over_budget:
            expression = self._literal(value,exotic=policy.lua_version == '5.3') if number_on else '(' + self._plain(value) + ')'
            if len(expression) > chars or expression_summary(expression)[2] > operations:
                expression = '(' + self._plain(value) + ')'
            strategy = 'number_literal' if number_on else 'mandatory_literal'
        if len(expression) > chars or expression_summary(expression)[2] > operations:
            raise RuntimeError(f'Literal Mosaic budget cannot represent {context}: {chars} chars, {operations} operations')
        self.metrics.record(expression,strategy,context,policy.phase,fallback=over_budget)
        from .numeric_provenance import CodeText
        return CodeText(expression,[(0,len(expression))],
                        origins=[(0,len(expression),context+'/mosaic:'+strategy)])

    def _plain(self, value):
        if isinstance(value,bool) or not isinstance(value,(int,float)):
            raise TypeError('Literal Mosaic supports numeric values, not booleans')
        if isinstance(value,int):
            # Decimal 9223372036854775808 is parsed as float before unary
            # minus in Lua 5.3. Hex preserves the signed integer bit pattern.
            if self.policy.lua_version == '5.3' and value == -(1 << 63):
                return '0x8000000000000000'
            return str(value)
        if math.isnan(value): return '(0.0/0.0)'
        if math.isinf(value): return '(-1.0/0.0)' if value < 0 else '(1.0/0.0)'
        return repr(value)

    def _literal(self, value, *, exotic):
        plain = self._plain(value)
        if isinstance(value,float):
            if not math.isfinite(value) or (value == 0 and math.copysign(1,value)<0):
                return '(' + plain + ')'
            expression = (self.engine._fmt_decimal_short(value) if self.policy.style == 'compact'
                          else self.engine._fmt_float(value) if self.policy.lua_version == '5.3'
                          else random.choice((self.engine._fmt_decimal_short,self.engine._fmt_decimal_scientific))(value))
        elif self.policy.lua_version == '5.3':
            if not -(1 << 63) <= value < (1 << 63):
                raise ValueError('Literal Mosaic integer outside Lua 5.3 signed integer domain')
            if value == -(1 << 63):
                expression = self.engine._random_hex_case(plain)
            elif exotic and abs(value) <= (1 << 39)-1 and random.randrange(3) < (2 if self.policy.style == 'exotic' else 1):
                expression = self.engine._wrap_floor_to_int(self.engine._fmt_integral_float(value))
            else:
                expression = self.engine._fmt_plain_int(value)
        else:
            # Decimal is universally portable; 5.1 does not parse hex floats.
            expression = self.engine._fmt_plain_int(value) if 0 <= value < (1 << 31) else plain
        return '(' + expression + ')'

    def transform_generated(self, expression, *, context='string_constant', hot=True):
        from .numeric_provenance import CodeText, join_code
        from .ts_utils import parse
        if not self.enabled('number_obf') and not self.enabled('meme_strings'):
            return expression
        ctx = parse(expression)
        parts, spans, origins, pos, offset = [], [], [], 0, 0
        for node in sorted((n for n in ctx.walk() if n.type == 'number'),key=ctx.cs):
            a,b = ctx.cs(node),ctx.ce(node)+1
            token = ctx.text(node)
            # All current reconstruction operands are positive working-word
            # integer tokens; no user source is scanned by this operation.
            value = int(token,16 if token.lower().startswith('0x') else 10)
            before = expression[pos:a]
            replacement = self.number(value,context=context,hot=hot)
            parts.extend((before,replacement)); offset += len(before)
            spans.append((offset,offset+len(replacement)))
            from .numeric_provenance import number_origin
            origins.append((offset,offset+len(replacement),number_origin(replacement,0,len(replacement),context)))
            offset += len(replacement); pos=b
        parts.append(expression[pos:])
        text = join_code(parts)
        return CodeText(text,spans,origins=origins)


@contextmanager
def use_mosaic(service):
    token = ACTIVE.set(service)
    try:
        yield service
    finally:
        ACTIVE.reset(token)


def boundary(passes, *, lua_version='5.3', phase='vm_output', options=None):
    parent = ACTIVE.get()
    return LiteralMosaic(passes,lua_version=lua_version,phase=phase,
        options=options if options is not None else (parent.options if parent else None),
        metrics=parent.metrics if parent else None)
