"""Closed-runtime dependency pruning must preserve dynamic protection routes."""
from pathlib import Path
import random
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tools'))

from obfuscator.vm import VMPass
from obfuscator.vm.targets.profile import TargetProfile
from obfuscator.vm.backends import karity_graphs as graphs
from obfuscator.vm.backends.karity_runtime_usage import (
    specialize_runtime, graph_requirements, _SEMANTIC_TOKENS,
)
from profile_vm_runtime import FIXTURES, SETTINGS, execute


def dependency_checks():
    source = '''local function _int1(x) return _int1(x) end
    local function _arith1(x) return _int1(x) end
    local function _int2(a,b) return a+b end
    local function _branch() return 1 end
    local callback={fn=_int2}; local t={_branch=42}; return callback,t'''
    result, stats = specialize_runtime(source)
    assert set(stats['removed_helpers']) == {'_int1', '_arith1', '_branch'}
    assert 'local function _int2' in result
    assert execute(result.replace('return callback,t', 'print(callback.fn(3,4),t._branch)'))[0] == b'7\t42'
    escaped = 'local function _sem(tag,x) return x end; local t={_sem}; return t'
    assert graph_requirements(escaped)[1] == set(_SEMANTIC_TOKENS)
    computed = 'local function _sem(tag,x) return x end; return _sem(dynamic_tag,5)'
    assert graph_requirements(computed)[1] == set(_SEMANTIC_TOKENS)
    dynamic_slot = 'local function _arith2(a,b,av,slot) return a+b end; return _arith2(3,4,{},dynamic_slot)'
    assert len(graph_requirements(dynamic_slot)[0] & {s[0] for s in graphs._ARITH_SPECS.values()}) == 10
    combined = computed.replace('return _sem(dynamic_tag,5)',
        'local function _arith2(a,b,av,slot)return a+b end;return _sem(dynamic_tag,5),_arith2(3,4,{},dynamic_slot)')
    assert len(graph_requirements(combined)[0] & {s[0] for s in graphs._ARITH_SPECS.values()}) == 10
    shadowed = 'local function _branch() return 1 end; local function f(_branch) return _branch end; return f(4)'
    assert specialize_runtime(shadowed)[1]['removed_helpers'] == ['_branch']
    fake = 'local function _sem(tag,x) return x end; local function fake() return _sem(__VM_OP_POW__,3) end'
    assert graph_requirements(fake)[1] == {'__VM_OP_POW__'}
    invalid = 'local function unfinished('
    assert specialize_runtime(invalid)[0] == invalid
    assert {s[0] for s in graphs._ARITH_SPECS.values()} <= graph_requirements(invalid)[0]
    assert '__VM_LOOP_FORLOOP__' in graph_requirements(invalid)[0]
    free = graph_requirements('return _sem(tag,x),_arith2(x,y,{},slot)')
    assert len(free[0] & {s[0] for s in graphs._ARITH_SPECS.values()}) == 10
    assert free[1] == set(_SEMANTIC_TOKENS)
    from obfuscator.vm.synthesis.register_local import helper_source
    template=(ROOT/'obfuscator/vm/vm.lua').read_text(encoding='utf-8')
    derived='''local function _arith2(a,b,av,slot) return a*b end
local function _arith1(a,av,slot) return -a end
'''+helper_source(template,{1,2})
    finite=derived+'return _syn_arith2r(0,1,2,{},__VM_SLOT_MUL__,nil,3,4)'
    assert graph_requirements(finite)[0]=={'__VM_SLOT_MUL__'},'derived forwarding must not keep the whole bank'
    pruned,stats=specialize_runtime(finite)
    assert {'_arith1','_syn_arith1r'}<=set(stats['removed_helpers'])
    assert 'local function _syn_arith2r' in pruned and 'local function _arith2(' in pruned
    finite=derived+'return _syn_arith1r(0,1,{},__VM_SLOT_UNM__,nil,3)'
    assert graph_requirements(finite)[0]=={'__VM_SLOT_UNM__'}
    for suffix in ('return {_syn_arith2r}',
                   'return _syn_arith2r(0,1,2,{},dynamic_slot,nil,3,4)'):
        assert len(graph_requirements(derived+suffix)[0])==10,'escapes/computed slots must remain conservative'


def graph_checks():
    # Native and graph banks keep their original randomized dense keys. An
    # occurrence router can choose any of the four DAGs in either epoch.
    source = '''local _AR=__VM_ARITH_BUNDLE__;local _DG=__VM_SEMANTIC_GRAPHS__
    local _OG=__VM_OCCURRENCE_GRAPHS__;local _LG=__VM_LOOP_GRAPHS__
    local function _sem(tag,x) return x end
    local function _arith2(a,b,av,slot) return a+b end
    return _arith2(3,4,{},__VM_SLOT_ADD__),_sem(__VM_DATA_VALUE__,5)'''
    routes = (('arithmetic', tuple((k, True) for k in graphs._ARITH_ROUTE_NAMES.values())),
              ('semantic', tuple((k, True) for k in graphs._SEMANTIC_ROUTE_NAMES.values())))
    baseline_functions, optimized_functions = [], []
    compile_graph = graphs._compile_integer_graph_func
    def capture(target):
        def compile(*args, **kwargs):
            result = compile_graph(*args, **kwargs)
            target.append((args[0], result))
            return result
        return compile
    all_slots = {spec[0] for spec in graphs._ARITH_SPECS.values()}
    random.seed(9921)
    with patch.object(graphs, '_compile_integer_graph_func', capture(baseline_functions)), \
         patch('obfuscator.vm.backends.karity_runtime_usage.graph_requirements',
               return_value=(all_slots, set(_SEMANTIC_TOKENS))):
        before = graphs._apply_handler_graphs(source, representation_routes=routes)
    state = random.getstate()
    random.seed(9921)
    stats = {}
    with patch.object(graphs, '_compile_integer_graph_func', capture(optimized_functions)), \
         patch.object(graphs, '_compile_semantic_ir_func', wraps=graphs._compile_semantic_ir_func) as semantic, \
         patch.object(graphs, '_compile_loop_ir_func', wraps=graphs._compile_loop_ir_func) as loops:
        after = graphs._apply_handler_graphs(source, representation_routes=routes, stats=stats)
        assert semantic.call_count == 2 and loops.call_count == 0
    assert random.getstate() == state
    assert [(kind,code) for kind,code in baseline_functions if kind=='ADD'] == optimized_functions
    assert len(baseline_functions)==80 and len(optimized_functions)==8
    assert stats['arithmetic_dags_after'] == 8
    assert stats['arithmetic_dags_generated'] == 8
    assert stats['semantic_variants_after'] == 4
    assert stats['semantic_variants_generated'] == 4
    assert stats['occurrence_families'] == 8
    assert stats['loop_graphs_after'] == 0
    assert stats['loop_graphs_generated'] == 0
    for kind, function in baseline_functions:
        assert function in before
        assert (function in after) == (kind == 'ADD')
    assert len(after) < len(before)
    random.seed(9921)
    off = {}
    with patch.object(graphs, '_compile_integer_graph_func', wraps=compile_graph) as compile:
        graphs._apply_handler_graphs(source, graph_family_count=0, representation_routes=routes, stats=off)
        assert compile.call_count == 0
    assert off['arithmetic_dags_after'] == 0
    assert off['native_arithmetic_variants_per_kind'] == 4
    context_before = graphs._GRAPH_ENCODING_RNG.get()
    def fail():
        raise ValueError('candidate failure')
    try:
        graphs._graph_candidate(True, fail)
    except ValueError:
        pass
    else:
        raise AssertionError('candidate exception was swallowed')
    assert graphs._GRAPH_ENCODING_RNG.get() is context_before


def main():
    dependency_checks()
    graph_checks()
    builds = 0
    for version in ('5.1', '5.3'):
        for fixture in ('loops', 'closures'):
            source = FIXTURES[fixture]
            expected, _ = execute(source, version)
            for setting in SETTINGS:
                random.seed(9921)
                p = VMPass(vm_options={'backend': 'karity', **SETTINGS[setting]},
                           target=TargetProfile(version, 'karity'))
                output = p.run(source)
                actual, _ = execute(output, version)
                assert actual == expected, (version, fixture, setting, actual, expected)
                stats = p.last_lowered_ir.backend_data['runtime_emission']
                assert stats['occurrence_families'] == (0 if setting == 'graphs_off' else 8)
                assert stats['arithmetic_dags_after'] % 8 == 0
                assert stats['semantic_variants_after'] % 4 == 0
                assert stats['audited_helpers_after'] <= stats['audited_helpers_before']
                builds += 1
                print('vm-runtime-size-ok', version, fixture, setting, flush=True)
    for fixture in ('arithmetic', 'metamethods'):
        source = FIXTURES[fixture]
        expected, _ = execute(source)
        random.seed(9921)
        p = VMPass(vm_options={'backend': 'karity', **SETTINGS['protected']})
        actual, _ = execute(p.run(source))
        assert actual == expected, (fixture, actual, expected)
        if fixture == 'arithmetic':
            assert p.last_lowered_ir.backend_data['runtime_emission']['arithmetic_dags_after'] == 80
        builds += 1
    print(f'vm-runtime-size-regression-ok builds={builds}')


if __name__ == '__main__':
    main()
