from __future__ import annotations

import random
import re
from unittest.mock import patch

from run_vm_backend_regression import options
from run_vm_output_emitter_regression import run_source, vm_config
from obfuscator.vm import VMPass
from obfuscator.vm import vm_pass
from obfuscator.vm.backend import VM_BACKENDS
from obfuscator.vm.runtime_trace import apply_runtime_trace


TRACE_NAMES = re.compile(r"\b(?:_PTRACE|_PX|_PBC|_PBH)\b")


def main() -> int:
    for malformed in (
        "--<<RUNTIME_TRACE>>\n", "--<<ENDRUNTIME_TRACE>>\n",
        "--<<RUNTIME_TRACE>>\n--<<RUNTIME_TRACE>>\n",
    ):
        try:
            apply_runtime_trace(malformed, False)
        except ValueError:
            pass
        else:
            raise AssertionError("malformed trace section accepted")

    source = ('local function f(x) local y=x+1; return y*3 end; '
              'local s=0; for i=1,12 do s=s+f(i) end; print(s); '
              'io.stderr:write("user diagnostic\\n")')
    expected = run_source(source)
    assert expected[0] == 0
    builds = 0
    for backend in VM_BACKENDS:
        for enabled in (False, True):
            for optimized in (False, True):
                settings = options(backend)
                settings.update(runtime_trace=enabled, vm_count=2,
                                runtime_polymorphism_rate=1.0,
                                graph_execution_rate=1.0,
                                block_variant_rate=1.0,
                                semantic_state_threading=True,
                                argument_virtualization=True)
                instrumented = backend == "karity" and enabled
                inspected = []
                original = vm_pass._obfuscate_vm_output

                def inspect(script, passes):
                    assert "RUNTIME_TRACE>>" not in script
                    assert "__VM_POLY_TRACE__" not in script
                    assert "_PTRACE" not in script
                    if instrumented:
                        assert "karity-vm-trace:" in script
                    else:
                        assert not TRACE_NAMES.search(script)
                        assert "karity-vm-trace:" not in script
                        assert "blocktrace:" not in script
                    inspected.append(script)
                    return original(script, passes)

                random.seed(8500 + builds)
                passes = vm_config()["vm_output_passes"] if optimized else []
                with patch.object(vm_pass, "_obfuscate_vm_output", side_effect=inspect):
                    output = VMPass(vm_options=settings, vm_output_passes=passes).run(source)
                assert inspected, "VM output inspection was bypassed"
                result = run_source(output)
                if instrumented:
                    trace = re.compile(rb"^karity-vm-trace:[0-9a-f]{16} blocks:[0-9]+ blocktrace:[0-9a-f]{16}\n", re.MULTILINE)
                    assert trace.search(result[2]), result
                    result = (result[0], result[1], trace.sub(b"", result[2]))
                else:
                    assert "karity-vm-trace:" not in output
                assert result == expected, (backend, enabled, optimized, result)
                builds += 1
    print(f"runtime-trace-regression-ok builds={builds}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
