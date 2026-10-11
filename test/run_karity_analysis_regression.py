"""The state fixed point must not depend on worklist traversal order."""
from collections import deque
from dataclasses import replace
from pathlib import Path
import random
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lupa.lua53 import LuaRuntime
from obfuscator.parser import parse_bytes
from obfuscator.vm.semantic_ir import build_semantic_ir
from obfuscator.vm.protection import ProtectionPlanner, protect
from obfuscator.vm.backends import get_backend, BackendContext
from obfuscator.vm.backends import karity_state
from obfuscator.vm.backends.runtime_layout import iter_functions


class ReverseQueue(deque):
    def popleft(self):
        return self.pop()


SOURCES = (
    'local x=0;for i=1,5 do if i%2==0 then x=x+i else x=x*2 end end;return x',
    'local function f(x) local function g() return x end;for i=1,3 do x=x+i end;return g end;return f(4)()',
    'local t={};for i=1,3 do local x=i;t[i]=function() x=x+1;return x end end;return t[1](),t[2]()',
    'local x=0;repeat x=x+1; if x==2 then x=x+1 end until x>4;return x',
    'local function f(...) local t={...};local x,y=1,2;while x<8 do '
    'x=x+y;if x%2==0 then y=y+1 else y=y*2 end end;return x,y,t[1],nil end;return f(3,nil)',
    'local t={};for i=1,4 do local a,b=i,i+1;t[i]=function()a=a+b;return a,b end;'
    'if i%2==0 then b=b*2 end end;return t[1](),t[4]()',
    'local co=coroutine.create(function(x)coroutine.yield(x,nil);'
    'local ok,e=pcall(function()error("expected")end);return ok,e,x,nil end);'
    'coroutine.resume(co,3);return coroutine.resume(co)',
)


def eager_records(function, mapping):
    """Compare final projection to the old per-wave recording behavior.

    The observer keeps the full record at every propagation visit, including
    transient pending/box/graph states. Only the last visit should survive.
    """
    transfer = karity_state._transfer
    last = {}
    light_seen = set()

    def observe(transition, state, boxes, *, record=True):
        result = transfer(transition, state, boxes, record=record)
        if not record:
            light_seen.add(transition.pc)
            full = transfer(transition, state, boxes)
            assert (result[0], result[-1]) == (full[0], full[-1])
            assert result[4] == result[5] == result[6] == result[8] == ()
        else:
            full = result
        if not record or transition.pc not in light_seen:
            (_, resolved, materialized, maybe, native, captures, graphs,
             closed, closing, close_materialized, _) = full
            last[transition.pc] = replace(
                transition, resolved_pending=resolved, materialized=materialized,
                maybe_materialized=maybe, native_inputs=native, capture_states=captures,
                graph_dependencies=graphs, open_boxes=tuple(sorted(boxes)),
                closed_registers=closed, close_states=closing,
                close_materialized=close_materialized, reachable=True,
            )
        return result

    with patch.object(karity_state, '_transfer', observe):
        result = karity_state._function_state(function, mapping)
    assert {t.pc for t in result.transitions if t.reachable} == last.keys()
    for pc, expected in last.items():
        assert result.transitions[pc] == expected, (function.source.id, pc)
    return result


def main():
    lua = LuaRuntime(encoding=None)
    dump = lua.eval(b'function(s) return string.dump(assert(load(s))) end')
    checks = 0
    for index, source in enumerate(SOURCES * 2):
        seed = 4900 + index
        random.seed(seed)
        ir = build_semantic_ir(parse_bytes(dump(source.encode())))
        options = {'graph_execution_rate':0.5 if index < len(SOURCES) else 0.0,
                   'cross_instruction_rate':1.0, 'runtime_polymorphism_rate':1.0,
                   'block_variant_rate':1.0, 'vm_count':1}
        backend = get_backend('karity')
        lowered = backend.lower(protect(ir,ProtectionPlanner(options).build(ir)),BackendContext(options))
        layout = lowered.backend_data['layout']
        for function in iter_functions(layout.functions):
            mapping = layout.vm_maps[function.vm_id]
            forward = eager_records(function,mapping)
            with patch.object(karity_state, 'deque', ReverseQueue):
                reverse = eager_records(function,mapping)
            assert forward == reverse, (source,function.source.id)
            checks += 1
    print(f'karity-analysis-regression-ok eager records and schedule independence functions={checks}')


if __name__ == '__main__':
    main()
