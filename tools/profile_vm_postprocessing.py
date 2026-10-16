"""Warm, seeded built-in preset measurements against another checkout.

Run serially with PYTHONHASHSEED=0. Hash generated expressions and serialized
protected IR to audit unchanged protection separately from renamed Lua output.
"""
from pathlib import Path
import argparse
import hashlib
import json
import random
import subprocess
import sys
import time
from unittest.mock import patch

FIXTURES = {
    'hi': 'print("hi")',
    'loops': 'local x=0;for i=1,80 do for j=1,4 do if i%2==0 then x=x+i*j else x=x-j end end end;print(x)',
    'closures': 'local fs={};for i=1,3 do local n=i;fs[i]=function(...)n=n+1;return n,... end end;for i=1,3 do print(fs[i](nil,9,nil))end;local co=coroutine.create(function()coroutine.yield("yield",nil);return "done" end);print(coroutine.resume(co));print(coroutine.resume(co));print(pcall(function()error("expected",0)end))',
    'macro': 'print(STRING_OBF("🌸한글"))',
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tree', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--fixtures', nargs='+', choices=FIXTURES, default=list(FIXTURES))
    parser.add_argument('--preset', choices=['fast', 'balanced', 'strong', 'maximum'], default='fast')
    parser.add_argument('--backend', choices=['karity', 'classic', 'mov'], default='karity')
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--seed', type=int, default=8471)
    args = parser.parse_args()
    if args.repeats < 1: parser.error('repeats must be positive')
    root = args.tree.resolve()
    sys.path.insert(0, str(root))
    import obfuscator_gui as gui
    from obfuscator.presets import resolve_user_preset
    from obfuscator.passes.literal_mosaic import LiteralMosaic
    from obfuscator.vm.backends.base import VMBackend
    from obfuscator.toolchain import LuaToolchain
    api = gui.Api()
    config = gui._complete_config(resolve_user_preset(args.preset, {'vm_options': {'backend': args.backend}}))
    lua = LuaToolchain.from_config(config).lua()
    random.seed(args.seed)
    warm = api.run_obfuscation({'script': FIXTURES['hi'], 'config': config})
    assert warm['ok'], warm.get('error')
    number, serialize = LiteralMosaic.number, VMBackend.serialize_program
    records = []
    for repeat in range(args.repeats):
        for fixture in args.fixtures:
            digest, count, blobs = hashlib.sha256(), [0], []
            def observe_number(self, *a, **kw):
                expression = number(self, *a, **kw)
                digest.update(str(expression).encode('utf-8') + b'\0')
                count[0] += 1
                return expression
            def observe_blob(self, *a, **kw):
                blob = serialize(self, *a, **kw)
                blobs.append(hashlib.sha256(blob).hexdigest())
                return blob
            random.seed(args.seed)
            with patch.object(LiteralMosaic, 'number', observe_number), patch.object(VMBackend, 'serialize_program', observe_blob):
                started, cpu = time.perf_counter(), time.process_time()
                result = api.run_obfuscation({'script': FIXTURES[fixture], 'config': config})
                wall, cpu = time.perf_counter()-started, time.process_time()-cpu
            assert result['ok'], result.get('error')
            script = 'local _clock=os.clock();local _run=function() ' + result['output'] + ' end;_run();io.stderr:write("BENCH:",os.clock()-_clock)'
            executed = subprocess.run([str(lua), '-'], input=script.encode('utf-8'), capture_output=True, timeout=120)
            assert executed.returncode == 0, executed.stderr.decode(errors='replace')
            record = {'fixture': fixture, 'repeat': repeat, 'wall': wall, 'cpu': cpu,
                      'bytes': len(result['output'].encode('utf-8')), 'profile': result['profile'],
                      'expressions': count[0], 'expression_sha256': digest.hexdigest(), 'blob_sha256': blobs,
                      'stdout': executed.stdout.decode('utf-8'), 'execution_cpu': float(executed.stderr.rsplit(b'BENCH:',1)[1])}
            records.append(record)
            print(json.dumps({k:v for k,v in record.items() if k not in ('profile','stdout')}), flush=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({'seed': args.seed, 'python': sys.version, 'config': config, 'records': records}, indent=2, ensure_ascii=False), encoding='utf-8')
    api._execution.close()


if __name__ == '__main__': main()
