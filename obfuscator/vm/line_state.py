"""Dispersed source-location observations bound to the final runtime layout."""
from __future__ import annotations

import hashlib
import random
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..names import NameAllocator


_U32_MASK = 0xFFFFFFFF


def _line_state_mix(lines: list[int], steps: list[tuple[int, int, int]]) -> int:
    state = 0
    for line, (mul, add, shift) in zip(lines, steps):
        state = ((state ^ ((line * mul) & _U32_MASK)) + add) & _U32_MASK
        state = (state ^ (state >> shift)) & _U32_MASK
    return state


def _initialization_sites(source: str, start: int, state_name: str) -> list[int]:
    """Use actual outer-body statement boundaries, including minified output.

    Never enter executor/graph/loop bodies or insert after an early state read.
    Nested functions may capture the state before all observations have run.
    """
    from ..passes.ts_utils import parse
    ctx = parse(source)
    if ctx.root.has_error:
        raise ValueError("cannot distribute line state in invalid VM source")
    returned = next((n for n in ctx.root.named_children if n.type == 'return_statement'), None)
    expressions = returned.named_children if returned is not None else ()
    function = next((n for expression in expressions for n in expression.named_children
                     if n.type == 'function_definition'), None)
    body = function.child_by_field_name('body') if function is not None else None
    if body is None:
        raise ValueError("VM source must return its runtime function")
    sites = []
    for statement in body.named_children:
        position = ctx.cs(statement)
        if position < start or statement.type == 'comment':
            continue
        sites.append(position)
        stack = [statement]
        reads_state = False
        while stack:
            node = stack.pop()
            if node.type in {'function_definition', 'function_declaration'}:
                continue
            if node.type == 'identifier' and ctx.plain_text(node) == state_name:
                reads_state = True
                break
            stack.extend(node.named_children)
        if reads_state or statement.type == 'return_statement':
            break
    return sites or [start]


def _parser_source(kind: int, bank: str, slot: int, allocator: NameAllocator,
                   environment: str) -> str:
    """Three independent readers of the rightmost native ':line: ' location.

    Probe faults contain only allocator-owned identifiers, so their native
    diagnostic cannot introduce a competing location after the real header.
    The byte reader uses neither patterns nor tonumber/sub/find.
    """
    names = [allocator.allocate('location') for _ in range(10)]
    message, fallback, a, b, c, d, e, f, g, h = names
    if kind == 0:
        captures = f'local {a},{b}={environment}["string"]["match"],{environment}["tonumber"]'
        body = f'return {b}({a}({message},"^.*:(%d+): ")) or {fallback}'
    elif kind == 1:
        captures = f'local {a}={environment}["string"]["byte"]'
        body = f'''for {b}=#{message}-1,2,-1 do
 if {a}({message},{b})==58 and {a}({message},{b}+1)==32 then
  local {c},{d},{e}={b}-1,0,1
  while {c}>0 do
   local {f}={a}({message},{c})
   if {f}<48 or {f}>57 then break end
   {d}={d}+({f}-48)*{e};{e}={e}*10;{c}={c}-1
  end
  if {c}<{b}-1 and {a}({message},{c})==58 then return {d} end
 end
end
return {fallback}'''
    else:
        captures = (f'local {a},{b},{c}={environment}["string"]["find"],'
                    f'{environment}["string"]["sub"],{environment}["tonumber"]')
        body = f'''local {d},{e}=1,{fallback}
while true do
 local {f}={a}({message},":",{d},true)
 if not {f} then break end
 local {g}={a}({message},": ",{f}+1,true)
 if {g} then
  local {h}={c}({b}({message},{f}+1,{g}-1))
  if {h} then {e}={h} end
 end
 {d}={f}+1
end
return {e}'''
    return (f'do {captures}\n{bank}[{slot}]=function({message},{fallback})\n'
            f'{body}\nend end')


def apply_line_state(
    vm_func_src: str,
    output_prefix: str = '',
    finalizer=None,
    output_passes: list[str] | tuple[str, ...] | None = None,
    insertion_anchor: str = 'return function(...)',
    native_u32: bool = False,
    qualify_globals: bool = False,
    environment_source: str | None = None,
) -> tuple[str, int, list[int]]:
    """Scatter token-free faults/readers/observations through VM initialization.

    Each build uses all three reader families and multiple independently mixed
    observations of some faults. There is no reader-selection or recovery gate
    which can discard a conflicting result. Only the small new fragments go
    through literal/final emission; the existing runtime is never re-minified.
    """
    anchor_pos = vm_func_src.find(insertion_anchor)
    if anchor_pos < 0:
        raise ValueError('VM function source is missing its return-function anchor')
    seed = hashlib.sha256(repr(random.getstate()).encode('utf-8')).digest()
    rng = random.Random(int.from_bytes(seed, 'big'))
    from ..names import NameAllocator, RENAME_OPTIONS
    options = RENAME_OPTIONS.get()
    allocator = NameAllocator.for_source(vm_func_src, seed=options.get('seed'),
                                         readable=options.get('readable', False))
    state, bank = allocator.allocate('state'), allocator.allocate('initializers')
    vm_func_src = re.sub(r'\b_LS\b', state, vm_func_src)
    start = vm_func_src.find(insertion_anchor) + len(insertion_anchor)
    sites = _initialization_sites(vm_func_src, start, state)
    slots = iter(rng.sample(range(17, 4096), 13))
    call_slot, type_slot = next(slots), next(slots)
    environment_slot = next(slots)
    environment = f'{bank}[{environment_slot}]'
    parser_slots = [next(slots) for _ in range(3)]
    count = rng.randint(3, 5)
    probe_slots = [next(slots) for _ in range(count)]
    xor_slot, multiply_slot = next(slots), next(slots)
    jobs: dict[str, tuple[set[str], str]] = {}
    for kind, slot in enumerate(parser_slots):
        jobs[f'p{kind}'] = (set(), _parser_source(kind, bank, slot, allocator, environment))

    arithmetic_deps: set[str] = set()
    if native_u32:
        # Keep exact 32-bit products on binary64 hosts; no generic translator.
        floor = allocator.allocate('floor')
        jobs['xor'] = (set(), f'''do local {floor}={environment}["math"]["floor"]
{bank}[{xor_slot}]=function(a,b)
 a=a%4294967296;b=b%4294967296
 local result,place=0,1
 while a>0 or b>0 do
  local left,right=a%2,b%2
  if left~=right then result=result+place end
  a={floor}(a/2);b={floor}(b/2);place=place*2
 end
 return result
end end''')
        jobs['multiply'] = (set(), f'''do local {floor}={environment}["math"]["floor"]
{bank}[{multiply_slot}]=function(a,b)
 a=a%4294967296;b=b%4294967296
 local al=a%65536;local ah={floor}(a/65536)
 local bl=b%65536;local bh={floor}(b/65536)
 return (al*bl+((al*bh+ah*bl)%65536)*65536)%4294967296
end end''')
        arithmetic_deps = {'xor', 'multiply'}

    forms = ['index', 'call', 'length', 'add', 'concat']
    rng.shuffle(forms)
    markers = []
    for index, (slot, form) in enumerate(zip(probe_slots, forms)):
        value = allocator.allocate('value')
        expression = {'index': f'{value}[{value}]', 'call': f'{value}()',
                      'length': f'#{value}', 'add': f'{value}+{value}',
                      'concat': f'{value}..{value}'}[form]
        # No literals in the failing expression: literal lowering cannot move
        # its fault onto a different line within this single-line definition.
        declaration = f'{bank}[{slot}]=function({value}) return {expression} end'
        jobs[f'f{index}'] = (set(), declaration)
        markers.append(f'function({value})')

    kinds = [0, 1, 2]
    rng.shuffle(kinds)
    observations: list[int] = []
    steps: list[tuple[int, int, int]] = []
    for index in range(count):
        readers = [kinds[index % 3]]
        if index < 2 or rng.random() < 0.5:
            readers.append(rng.choice([kind for kind in kinds if kind not in readers]))
        ok, message, value = [allocator.allocate('result') for _ in range(3)]
        lines = [f'do local {ok},{message}={bank}[{call_slot}]({bank}[{probe_slots[index]}])']
        for kind in readers:
            fallback = rng.getrandbits(24) | 1
            mul, add, shift = rng.getrandbits(32) | 1, rng.getrandbits(32), rng.randint(5, 17)
            observations.append(index)
            steps.append((mul, add, shift))
            lines.extend([
                f'local {value}={fallback}',
                f'if not {ok} and {bank}[{type_slot}]({message})=="string" then '
                f'{value}={bank}[{parser_slots[kind]}]({message},{fallback}) end',
            ])
            if native_u32:
                lines.extend([
                    f'{state}=({bank}[{xor_slot}]({state},{bank}[{multiply_slot}]({value},{mul}))+{add})%4294967296',
                    # Quotient/remainder is exact and avoids another global
                    # math.floor lookup in each observation.
                    f'{state}={bank}[{xor_slot}]({state},({state}-{state}%{2**shift})/{2**shift})',
                ])
            else:
                lines.extend([
                    f'{state}=(({state}~(({value}*0x{mul:08X})&0xFFFFFFFF))+0x{add:08X})&0xFFFFFFFF',
                    f'{state}=({state}~({state}>>{shift}))&0xFFFFFFFF',
                ])
        lines.append('end')
        dependencies = {f'f{index}', *(f'p{kind}' for kind in readers)} | arithmetic_deps
        if index:
            dependencies.add(f'c{index-1}')
        jobs[f'c{index}'] = (dependencies, '\n'.join(lines))

    scheduled = []
    done: set[str] = set()
    while len(done) < len(jobs):
        ready = [key for key, (dependencies, _) in jobs.items()
                 if key not in done and dependencies <= done]
        key = rng.choice(ready)
        scheduled.append(jobs[key][1])
        done.add(key)

    selected = list(output_passes or ())
    literal_passes = [name for name in selected
                      if name in {'number_obf', 'string_obf', 'boolean_obf'}]

    # Literal emitters use the module PRNG; keep the build stream unchanged.
    random_state = random.getstate()
    try:
        random.setstate(rng.getstate())
        # Target 5.1 supplies a lexical _ENV in its prelude. The fallback also
        # supports standalone portable-arithmetic fragments on stock Lua 5.1.
        globals_source = environment_source or ('(_ENV or getfenv(1))' if native_u32 else '_ENV')
        initial = (f'local {state}=0;local {bank}={{[{environment_slot}]={globals_source}}};'
                   f'{bank}[{call_slot}]={environment}["pcall"];'
                   f'{bank}[{type_slot}]={environment}["type"]')
        # Analyze new fragments together so generated literal helpers reserve
        # every fault parameter and cannot imitate a location marker elsewhere.
        # These temporary comment boundaries never reach the emitted runtime.
        boundaries = [f'--[[LINE_FRAGMENT_{allocator.allocate("boundary")}]]'
                      for _ in range(len(scheduled)+1)]
        fragments = [initial, *scheduled]
        combined = '\n'.join(marker+fragment for marker, fragment in zip(boundaries, fragments))
        if literal_passes:
            from .output_emitter import emit_vm_literals
            combined, _ = emit_vm_literals(combined, literal_passes)
        if qualify_globals:
            from ..passes.rename_ts import qualify_runtime_globals
            # The environment bank is declared outside these late fragments.
            # Keep its lexical reference while qualifying actual global reads.
            lexical_names = (environment_source.split('[', 1)[0],) if environment_source else ()
            combined = qualify_runtime_globals(combined, lexical_names=lexical_names)
        # Splitting precedes minification, which intentionally removes comments.
        for index in range(len(boundaries)-1, -1, -1):
            combined, found, fragments[index] = combined.rpartition(boundaries[index])
            if not found:
                raise AssertionError('line-state fragment boundary disappeared')
        if combined:
            raise AssertionError('unexpected line-state fragment prefix')

        def render(fragment: str) -> str:
            return (' ' + finalizer(fragment) + ' ') if finalizer else '\n' + fragment + '\n'

        insertions: dict[int, list[str]] = {start: [render(fragments[0])]}
        for index, fragment in enumerate(fragments[1:]):
            position = sites[min(len(sites)-1, (index+1)*len(sites)//(len(scheduled)+1))]
            insertions.setdefault(position, []).append(render(fragment))
    finally:
        random.setstate(random_state)
    parts = []
    previous = 0
    for position, fragments in sorted(insertions.items()):
        parts.extend([vm_func_src[previous:position], *fragments])
        previous = position
    parts.append(vm_func_src[previous:])
    result = ''.join(parts)
    prefix_lines = output_prefix.count('\n')
    probe_lines = []
    for marker in markers:
        # Minify retains the function keyword/parameter boundary, while it
        # may remove the space before '('. No probe token enters Lua data.
        position = result.find(marker)
        if position < 0:
            raise AssertionError('line observation disappeared during rendering')
        probe_lines.append(prefix_lines + result[:position].count('\n') + 1)
    observed_lines = [probe_lines[index] for index in observations]
    return result, _line_state_mix(observed_lines, steps), probe_lines
