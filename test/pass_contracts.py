"""Small reusable source cases and pass-order contracts, with native oracles.

Reuse the existing bounded explorer for execution/timeouts and its generated
expression grammar. Lua prints bytes/arity explicitly, avoiding lossy comparison
of arbitrary binary output or conflating no return values with one nil.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from itertools import permutations
import hashlib
import json
from pathlib import Path
import random
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'test')]

from tools.explore_vm_semantics import execute, expression_source


@dataclass(frozen=True)
class Case:
    name: str
    source: str
    features: frozenset[str]
    versions: tuple[str, ...] = ('5.1', '5.3')


@dataclass(frozen=True)
class PassContract:
    features: frozenset[str]
    versions: tuple[str, ...] = ('5.1', '5.3')


def contract(features, lua53_only=False):
    return PassContract(frozenset(features.split()), ('5.3',) if lua53_only else ('5.1', '5.3'))


PASSES = {
    'strip_info': contract('naming formatting'),
    'remove_comment': contract('formatting'),
    'string_encode': contract('strings'),
    'string_obf': contract('strings', True),
    'string_flow_obf': contract('strings', True),
    'boolean_obf': contract('numbers', True),
    'number_obf': contract('numbers', True),
    'meme_strings': contract('numbers strings', True),
    'table_obf': contract('tables'),
    'function_obf': contract('functions'),
    'rename_obf': contract('naming'),
    'localize_globals': contract('naming', True),
    'minify': contract('formatting'),
    'semicolon': contract('formatting'),
}
# These passes need dedicated execution/security/VM contexts, already owned by
# named feature suites. They are not silently omitted from source contracts.
DEDICATED = frozenset({'anti_debug', 'anti_env', 'anti_decompile', 'vm', 'pack'})

MIXED = Case('arity-closure-table',
    """-- A comment boundary for Remove Comment and Strip Info.
local empty="";local text=[=[
한글 ]==] \"quotes\"
]=];print(#empty,#text,string.byte(text,1,#text))
local function f(x,...)
 local function g() x=x+1;return x end
 local t={name="Karity",value=false};print(t.name,g(),g(),t.value)
 local function observe(...) print(select('#',...),...) end
 observe(nil,false,...);return g(),nil,false,...
end
local function observe(...) print(select('#',...),...) end
observe(f(2,nil,7,nil))
""", frozenset({'strings', 'numbers', 'tables', 'functions', 'naming', 'formatting'}))


def cases():
    # Byte values are printed as ASCII integers, not decoded with replacement.
    data = bytes(range(256))
    literal = '"' + ''.join('\\' + str(b).zfill(3) for b in data) + '"'
    return (
        MIXED,
        Case('string-byte-boundaries',
             'local a=' + literal + ';local b=[=[\n\nbrackets ]==] and "quotes"\n]=];'
             'print(#a,string.byte(a,1,#a));print(#b,string.byte(b,1,#b));'
             'local c="한글🙂";print(#c,string.byte(c,1,#c))',
             frozenset({'strings', 'formatting'})),
        Case('numeric-types',
             """local values={0,-0.0,1,1.5,0x10,.5,2^20,-7,1e20,1e-20}
for i,v in ipairs(values)do print(i,v,1/v,math.type and math.type(v)or type(v))end
print(true,false,not false)""", frozenset({'numbers'})),
        Case('table-effects',
             """local trace={};local function tap(v)trace[#trace+1]=v;return v,nil end
local function values()return 3,nil,5 end
local t={[tap("k")]=tap(2),tap(1),values()}
local p=setmetatable({},{__index=function(_,k)trace[#trace+1]=k;return false end})
print(t.k,t[1],t[2],t[3],t[4],p.missing,table.concat(trace,","))""",
             frozenset({'tables', 'functions'})),
        Case('control-error-effects',
             """local x=0;local function test(v) x=x+1;return v end
for i=1,6 do if test(i%2==0)then x=x+i else x=x-1 end end
local ok,err=pcall(function()error("contract-error",0)end)
local function many(...) print(select('#',...),...)end
many();many(nil);many(nil,false,nil)
print(x,ok,err,test(false)and test(true)or "fallback")""",
             frozenset({'functions', 'naming', 'formatting'})),
        Case('integer-domain',
             'local t={0x7fffffffffffffff,0x8000000000000000,-1,255};'
             'for i,v in ipairs(t)do print(i,v,math.type(v),v~255,v//3)end',
             frozenset({'numbers'}), ('5.3',)),
    )


def recipes(*, quick=False, features=()):
    """Every ordered pair on small cases; explicit chains for coupled triples."""
    recipes_ = [(name,) for name in PASSES]
    if quick:
        return tuple(recipes_)
    wanted = frozenset(features)
    relevant = {name for name, spec in PASSES.items() if not wanted or spec.features & wanted}
    # A VM/host-only change still gets basic source contracts, without running
    # the entire source composition matrix merely because a quick check exists.
    if not relevant:
        return tuple(recipes_)
    recipes_ += [pair for pair in permutations(PASSES, 2) if set(pair) & relevant]
    chains = (
        ('string_encode', 'string_flow_obf', 'function_obf'),
        ('string_flow_obf', 'function_obf', 'number_obf'),
        ('string_obf', 'meme_strings', 'number_obf'),
        ('table_obf', 'string_encode', 'rename_obf'),
        ('function_obf', 'strip_info', 'minify'),
        ('semicolon', 'rename_obf', 'minify'),
    )
    recipes_ += [chain for chain in chains if set(chain) & relevant]
    return tuple(recipes_)


def config_for(passes, version, context='source', backend=None):
    config = {'passes': list(passes), 'target': {'lua_version': version},
              'signature': {'mode': 'none'},
              'function_obf_options': {'junk': False, 'inline': False, 'wrapper': False}}
    if context == 'vm_output':
        config.update(passes=['vm'], vm_output_passes=list(passes),
                      vm_options={'backend': backend, 'vm_count': 1, 'fake_handlers': False,
                                  'mutate_handlers': False, 'junk_instructions': False,
                                  'opcode_synthesis': False, 'integrity_constants': True})
    elif context == 'packer_output':
        if version != '5.3':
            raise ValueError('The packer output contract requires Lua 5.3')
        config.update(passes=['pack'], packer_output_passes=list(passes))
    elif context != 'source':
        raise ValueError('Unknown contract context')
    return config


def normalized(result):
    return result['returncode'], result['stdout']


class Oracle:
    def __init__(self, folder):
        self.folder = Path(folder)

    @lru_cache(maxsize=256)
    def expected(self, source, version):
        path = self.folder / ('native-' + hashlib.sha256(source.encode()).hexdigest()[:16] + '.lua')
        path.write_text(source, encoding='utf-8')
        result = execute(path, version, timeout=30)
        if result['returncode']:
            raise AssertionError(f'Native case is invalid: {result}')
        return normalized(result)

    def compare(self, case, passes, version, seed, *, context='source', backend=None):
        from obfuscator import Pipeline, build_pipeline_from_config
        config = config_for(passes, version, context, backend)
        tag = f'{case.name}-{version}-{seed}-{context}-{backend}-' + '-'.join(passes)
        expected = self.expected(case.source, version)
        output, actual = None, None
        try:
            random.seed(seed)
            output = build_pipeline_from_config(config, Pipeline, show_header=False).run(case.source)
            path = self.folder / 'protected.lua'
            path.write_text(output, encoding='utf-8')
            actual = execute(path, version, timeout=30)
            if actual['returncode'] or normalized(actual) != expected:
                raise AssertionError(f'{tag}: expected {expected!r}; actual {actual!r}')
        except Exception as error:
            # Persist replay inputs only on failure. No local machine paths in
            # this record; the complete configuration and seed are sufficient.
            failures = ROOT / 'local/verification/failures'
            failures.mkdir(parents=True, exist_ok=True)
            record = {'case': case.name, 'source': case.source, 'version': version,
                      'passes': list(passes), 'seed': seed, 'config': config,
                      'context': context, 'backend': backend,
                      'expected': expected, 'actual': actual, 'error': repr(error)}
            artifact = failures / (hashlib.sha256(tag.encode()).hexdigest()[:16] + '.json')
            artifact.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding='utf-8')
            if output is not None:
                artifact.with_suffix('.lua').write_text(output, encoding='utf-8')
            raise AssertionError(f'{tag}; replay: python test/run_pass_contract_regression.py '
                                 f'--replay {artifact.relative_to(ROOT).as_posix()}') from error


def run_contracts(oracle, *, quick=False, features=(), generated=0):
    count = 0
    corpus = cases()
    for index, passes in enumerate(recipes(quick=quick, features=features)):
        family = set().union(*(PASSES[p].features for p in passes))
        eligible = [c for c in corpus if c.features & family]
        # Each ordered pair gets a boundary case, not a Cartesian product of
        # every seed/corpus/backend. Dedicated suites retain the deep matrices.
        chosen = (MIXED,) if quick else (MIXED if len(passes) == 1 else eligible[index % len(eligible)],)
        for version in ('5.1', '5.3'):
            if not all(version in PASSES[p].versions for p in passes):
                continue
            for case in chosen:
                if version not in case.versions:
                    continue
                oracle.compare(case, passes, version, 9021)
                count += 1
    if not quick:
        from obfuscator.vm.backends import backend_names
        output_passes = ('string_encode', 'strip_info', 'rename_obf', 'semicolon', 'minify')
        # A compact common case crosses the real source/output boundary and
        # integrity binding on every registered backend, including future ones.
        for backend in backend_names():
            for version in ('5.1', '5.3'):
                oracle.compare(MIXED, output_passes, version, 9021,
                               context='vm_output', backend=backend)
                count += 1
        oracle.compare(MIXED, output_passes, '5.3', 9021, context='packer_output')
        count += 1
    # Reuse the explorer's seeded effect-order grammar for optional fuzzing.
    for seed in range(generated):
        case = Case(f'generated-effects-{seed}', expression_source(seed), MIXED.features)
        for passes in (('rename_obf', 'minify'), ('number_obf', 'string_encode'),
                       ('string_flow_obf', 'function_obf')):
            oracle.compare(case, passes, '5.3', seed)
            count += 1
    return count
