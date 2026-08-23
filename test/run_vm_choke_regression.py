from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


ROOT_DIR = Path(__file__).resolve().parents[1]
LUA = ROOT_DIR / "bin" / ("lua.exe" if os.name == "nt" else "lua")
SCRIPTS = (
    "09_table.lua",
    "10_function.lua",
    "12_vmtest.lua",
    "14_vm_call_machine.lua",
    "15_vm_semantic_ir.lua",
    "18_vm_cross_instruction_semantics.lua",
)


def lua_executable() -> str:
    if LUA.exists():
        return str(LUA)
    return shutil.which("lua5.3") or shutil.which("lua53") or shutil.which("lua") or "lua"


def run(command: list[str], timeout: float) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(command, capture_output=True, timeout=timeout)


def config(dispatcher: str, vm_count: int) -> dict:
    return {
        "passes": ["vm"],
        "vm_output_passes": [],
        "packer_output_passes": [],
        "vm_options": {
            "dispatcher_type": dispatcher,
            "blob_form": "string",
            "vm_count": vm_count,
            "fake_handlers": False,
            "mutate_handlers": False,
            "junk_instructions": False,
            "junk_rate": 0.0,
            "integrity_constants": False,
            "integrity_constant_rate": 0.0,
            "graph_execution_rate": 0.2,
            "cross_instruction_rate": 0.5,
            "runtime_polymorphism_rate": 0.0,
            "runtime_trace": False,
            "block_variant_rate": 0.0,
            "block_variant_count": 2,
            "block_variant_max_instructions": 4,
            "helper_variant_count": 4,
            "helper_diversity_rate": 1.0,
            "semantic_diversity_rate": 1.0,
        },
    }


def main() -> int:
    lua = lua_executable()
    cases = (("ifelseif", 1), ("mixed", 3))
    builds = 0
    with tempfile.TemporaryDirectory(prefix="karity-choke-") as raw_temp:
        temp = Path(raw_temp)
        for case_index, (dispatcher, vm_count) in enumerate(cases):
            config_path = temp / f"config-{case_index}.json"
            config_path.write_text(json.dumps(config(dispatcher, vm_count)), encoding="utf-8")
            for script_index, script_name in enumerate(SCRIPTS):
                source = ROOT_DIR / "test" / "scripts" / script_name
                output = temp / f"{case_index}-{script_name}"
                expected = run([lua, str(source)], 120)
                built = run(
                    [
                        sys.executable,
                        str(ROOT_DIR / "main.py"),
                        str(source),
                        "-o",
                        str(output),
                        "--config",
                        str(config_path),
                        "--seed",
                        str(9100 + case_index * 100 + script_index),
                    ],
                    600,
                )
                if built.returncode != 0:
                    raise RuntimeError(
                        f"build failed ({dispatcher}, {script_name}): "
                        f"{(built.stderr or built.stdout)!r}"
                    )
                actual = run([lua, str(output)], 120)
                if (actual.returncode, actual.stdout, actual.stderr) != (
                    expected.returncode,
                    expected.stdout,
                    expected.stderr,
                ):
                    raise AssertionError(
                        f"semantic mismatch ({dispatcher}, {script_name}): "
                        f"expected={(expected.returncode, expected.stdout, expected.stderr)!r} "
                        f"actual={(actual.returncode, actual.stdout, actual.stderr)!r}"
                    )
                emitted = output.read_text(encoding="utf-8")
                if "=decode(" in emitted:
                    raise AssertionError("runtime fetch still converges on decode()")
                if "_NX=function" in emitted or re.search(
                    r"_CG\[[^\]]+\]\(_NX,", emitted
                ):
                    raise AssertionError("call/return still converges on one router")
                if "_NX={function" not in emitted:
                    raise AssertionError("per-VM continuation router kit was not emitted")
                for helper in ("rget", "rset", "_flow", "_sem"):
                    count = len(re.findall(
                        rf"local function {re.escape(helper)}(?:_|\()", emitted
                    ))
                    if count < 4:
                        raise AssertionError(
                            f"missing {helper} execution-kit variants: {count}"
                        )
                if "--<<FETCH>>" in emitted or "--<<RGET>>" in emitted:
                    raise AssertionError("execution-kit build markers leaked")
                builds += 1

    print(f"vm-choke-ok builds={builds} dispatchers=ifelseif,mixed forced_rate=1.0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
