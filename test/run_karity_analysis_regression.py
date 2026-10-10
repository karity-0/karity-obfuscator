"""The state fixed point must not depend on worklist traversal order."""
from collections import deque
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
)


def main():
    lua = LuaRuntime(encoding=None)
    dump = lua.eval(b'function(s) return string.dump(assert(load(s))) end')
    checks = 0
    for seed, source in enumerate(SOURCES, 4900):
        random.seed(seed)
        ir = build_semantic_ir(parse_bytes(dump(source.encode())))
        options = {'graph_execution_rate':0.5, 'cross_instruction_rate':1.0,
                   'block_variant_rate':1.0, 'vm_count':1}
        backend = get_backend('karity')
        lowered = backend.lower(protect(ir,ProtectionPlanner(options).build(ir)),BackendContext(options))
        layout = lowered.backend_data['layout']
        for function in iter_functions(layout.functions):
            mapping = layout.vm_maps[function.vm_id]
            forward = karity_state._function_state(function,mapping)
            with patch.object(karity_state, 'deque', ReverseQueue):
                reverse = karity_state._function_state(function,mapping)
            assert forward == reverse, (source,function.source.id)
            checks += 1
    print(f'karity-analysis-regression-ok fixed-point schedule independence functions={checks}')


if __name__ == '__main__':
    main()
