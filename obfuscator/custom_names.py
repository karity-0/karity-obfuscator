"""A source-managed naming budget for the final visible output stage."""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from functools import wraps
import random
import re
import time


CUSTOM_NAMES = {
    "function": [
        "computeRicinLethalDosageForWaterSupply",
        "calculateFentanylPrecursorSynthesisYield",
        "calculateDeadlyLethalSuicideAspirinDosage",
        "calculateANFOBlastOverpressureRadius",
        "validatePrecursorMoleculeStructure",
        "simulateBioaerosolTransport",
        "assessChemicalExposureRisk",
        "validateBiohazardContainment",
        "auditControlledMaterialAccess",
        "classifyToxicologySample",
    ],
    "integer": [
        "exposureThreshold",
        "transmissionRate",
        "toxicityScore",
        "pathogenTransmissionRate",
        "lethalDosePerKg",
        "sampleViabilityPercentage",
        "biohazardContainmentLevel",
        "restrictedSampleCount",
        "radiologicalAlertCode",
        "quarantineBatchCount",
    ],
    "string": [
        "pathogenSampleIdentifier",
        "chemicalHazardClassification",
        "toxicologyReport",
        "radiologicalAssessment",
        "biosecurityReviewNotice",
        "controlledMaterialLabel",
        "chemicalExposureReport",
        "toxicologyCaseReference",
    ],
    "default": [
        "biosecurityReviewContext",
        "restrictedMaterialContext",
        "controlledSubstanceContext",
        "radiologicalReviewState",
        "toxicologyAssessmentContext",
        "hazardContainmentState",
        "sensitiveSampleContext",
        "quarantineReviewState",
    ],
}
CUSTOM_NAME_COUNT = 4  # Zero disables custom naming; no extra locals are created.


@dataclass
class NamingScope:
    owner: object
    target: object
    reserved: set[str]
    enabled: bool = False
    active: bool = False
    applied: bool = False
    names: tuple[str, ...] = ()
    categories: dict[str, str] = field(default_factory=dict)
    requested: int = 0
    seed: int | None = None
    reason: str = ''
    elapsed: float = 0.0
    original_source: str | None = None
    kept_names: set[str] = field(default_factory=set)


ACTIVE: ContextVar[NamingScope | None] = ContextVar('custom_names', default=None)


@contextmanager
def build_scope(owner, source, *, enabled=False):
    current = ACTIVE.get()
    token = None
    if current is None:
        current = NamingScope(owner, owner, set(), original_source=source)
        token = ACTIVE.set(current)
        configure(owner, enabled=enabled)
    try:
        yield current
    finally:
        if token is not None:
            ACTIVE.reset(token)


def configure(target, *, enabled, seed=None, readable=None, opaque_input=False):
    from .names import RENAME_OPTIONS
    scope = ACTIVE.get()
    if scope is None:
        return
    options = RENAME_OPTIONS.get()
    scope.target = target
    scope.seed = options.get('seed') if seed is None else seed
    readable = options.get('readable', False) if readable is None else readable
    scope.enabled = enabled and not readable
    scope.reason = 'readable mode' if readable else ''
    if opaque_input:
        scope.reserved.clear()
        scope.original_source = None


@contextmanager
def stage(owner):
    scope = ACTIVE.get()
    previous = scope.active if scope else False
    if scope is not None:
        scope.active = previous or scope.target is owner
    try:
        yield
    finally:
        if scope is not None:
            scope.active = previous


@contextmanager
def keep_bindings(names):
    scope = ACTIVE.get()
    previous = scope.kept_names if scope else set()
    if scope is not None:
        scope.kept_names = previous | set(names)
    try:
        yield
    finally:
        if scope is not None:
            scope.kept_names = previous


def apply(source, *, keep=None, render=None, reserved=()):
    scope = ACTIVE.get()
    if scope is None or not scope.enabled or not scope.active or scope.applied:
        return source
    from .names import KEYWORDS
    from .passes.rename_ts import Binding, resolve_bindings, _apply_replacements_once
    from .passes.ts_utils import parse
    from .passes.base import Replacement
    count = CUSTOM_NAME_COUNT
    if type(count) is not int or count < 0:
        raise ValueError('CUSTOM_NAME_COUNT must be a nonnegative integer')
    scope.requested = count
    if count == 0:
        scope.applied = True
        return source
    kinds = ('function', 'string', 'integer', 'default')
    if not isinstance(CUSTOM_NAMES, dict) or set(CUSTOM_NAMES) != set(kinds):
        raise ValueError('CUSTOM_NAMES must define function, string, integer and default categories')
    if any(not isinstance(names, (list, tuple)) or any(
           not isinstance(n, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', n)
           or n in KEYWORDS | {'_ENV', 'self'} for n in names) for names in CUSTOM_NAMES.values()):
        raise ValueError('CUSTOM_NAMES must contain valid non-reserved Lua identifiers')
    pools = {kind: tuple(dict.fromkeys(CUSTOM_NAMES[kind])) for kind in kinds}
    all_names = [n for names in pools.values() for n in names]
    if len(set(all_names)) != len(all_names):
        raise ValueError('CUSTOM_NAMES identifiers must belong to only one category')
    if count > len(all_names):
        raise ValueError('CUSTOM_NAME_COUNT exceeds the distinct CUSTOM_NAMES candidates')
    started = time.perf_counter()
    ctx = parse(source)
    bindings, free, _, _, _ = resolve_bindings(ctx, collect_literals=False)
    if scope.original_source is not None:
        original_ctx = ctx if scope.original_source == source else parse(scope.original_source)
        if original_ctx.root.has_error:
            from .kes import lower_source
            version = getattr(getattr(scope.owner, 'target_profile', None), 'lua_version', '5.3')
            original_ctx = parse(lower_source(scope.original_source, version).source)
        original_bindings, original_free, _, _, _ = resolve_bindings(original_ctx, collect_literals=False)
        scope.reserved = original_free | {b.original for b in original_bindings}
    eligible = [b for b in bindings if b.original != '_ENV' and b.original not in scope.kept_names
                and not (keep and keep(ctx, b))]
    unavailable = free | scope.reserved | set(reserved) | {b.original for b in bindings}
    from collections import Counter
    from .passes.binding_kinds import classify_bindings
    categories = classify_bindings(ctx, bindings)
    populations = Counter(categories[id(b)] for b in eligible)
    candidates = {kind: [n for n in pools[kind] if n not in unavailable] for kind in kinds}
    capacity = sum(min(populations[kind], len(pools[kind])) for kind in kinds)
    actual = min(count, capacity)
    if sum(min(populations[kind], len(candidates[kind])) for kind in kinds) < actual:
        raise ValueError('not enough collision-free CUSTOM_NAMES candidates')
    rng = random if scope.seed is None else random.Random(scope.seed)
    for names in candidates.values():
        rng.shuffle(names)
    # Long custom names belong on the least referenced bindings.
    eligible.sort(key=lambda b: len(b.nodes))
    chosen: list[tuple[Binding, str]] = []
    for binding in eligible:
        if len(chosen) == actual:
            break
        kind = categories[id(binding)]
        if candidates[kind]:
            chosen.append((binding, candidates[kind].pop()))
            scope.categories[chosen[-1][1]] = kind
    selected = tuple(name for _, name in chosen)
    edits = [Replacement(ctx.cs(n), ctx.ce(n), name)
             for b, name in chosen for n in b.nodes]
    result = render(edits) if render else _apply_replacements_once(source,
        [(r.start, r.end, r.new_text) for r in edits])
    scope.names, scope.applied = selected, True
    scope.reason = ('insufficient eligible bindings' if len(eligible) < count
                    else 'insufficient category candidates') if actual < count else ''
    scope.elapsed = time.perf_counter() - started
    return result


def finish(owner, source):
    scope = ACTIVE.get()
    if scope is None or scope.owner is not owner:
        return
    if scope.names:
        from collections import Counter
        from .passes.rename_ts import collect_named_identifiers, resolve_bindings
        from .passes.ts_utils import parse
        ctx = parse(source)
        bindings, free, _, _, _ = resolve_bindings(ctx, collect_literals=False,
            captures=collect_named_identifiers(ctx, scope.names))
        counts = Counter(b.original for b in bindings)
        if counts != Counter(scope.names) or set(scope.names) & free:
            raise ValueError('custom names were lost, duplicated or captured after final naming')
    setattr(owner, 'last_custom_names', {'requested': scope.requested, 'applied': len(scope.names),
                                       'names': list(scope.names), 'categories': dict(scope.categories),
                                       'reason': scope.reason})


def output_scope(attribute):
    def decorate(function):
        @wraps(function)
        def run(owner, source, *args, **kwargs):
            passes = getattr(owner, attribute, ())
            enabled = any(name in passes for name in ('rename_obf', 'strip_info'))
            with build_scope(owner, source, enabled=enabled) as scope:
                if scope.owner is owner and 'strip_info' in passes and 'rename_obf' not in passes:
                    configure(owner, enabled=enabled, readable=False)
                if scope.owner is owner and attribute == 'packer_output_passes':
                    scope.reserved.clear()
                    scope.original_source = None
                with stage(owner):
                    result = function(owner, source, *args, **kwargs)
                finish(owner, result)
                return result
        return run
    return decorate
