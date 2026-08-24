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
sys.path.insert(0, str(ROOT_DIR))
LUA = ROOT_DIR / "bin" / ("lua.exe" if os.name == "nt" else "lua")
SCRIPTS = (
    "14_vm_call_machine.lua",
    "18_vm_cross_instruction_semantics.lua",
)
CASES = (
    ("ifelseif", 1),
    ("bsearch", 1),
    ("split4", 1),
    ("bsplit4", 1),
    ("tailcall", 1),
    ("mixed", 3),
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
            "dispatcher_target_hiding": True,
            "semantic_state_threading": True,
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


def assert_target_transform() -> None:
    from obfuscator.vm.vm_obfuscation import apply_dispatch_target_hiding

    fixtures = (
        "exec=function(...) local _S,_XF,_PR,_SS,_MG={}, {}, {}, {}, {} "
        "for i in setmetatable({},{__call=function(t)return t end}) do "
        "if op==7 then return 1 elseif op==19 then return 2 end end end",
        "exec=function(...) local _S,_XF,_PR,_SS,_MG={}, {}, {}, {}, {} "
        "local _H=setmetatable({},{}) _H[7]=function()end "
        "_H[19]=function()end return _H[op]() end",
        "exec=function(...) local _S,_XF,_PR,_SS,_MG={}, {}, {}, {}, {} "
        "local _dsm=setmetatable({},{}) if op<=7 then return 1 "
        "elseif op<19 then return 2 end end",
    )
    forbidden = re.compile(r"\bop\s*(?:==|<=|<)\s*\d+|_H\[\d+\]")
    for fixture in fixtures:
        transformed = apply_dispatch_target_hiding(fixture)
        if forbidden.search(transformed):
            raise AssertionError(f"plain dispatcher target survived: {transformed}")
        if "local _DM=" not in transformed or "local function _ds" not in transformed:
            raise AssertionError("state-coupled target helpers were not emitted")


def main() -> int:
    assert_target_transform()
    lua = lua_executable()
    builds = 0
    with tempfile.TemporaryDirectory(prefix="karity-state-coupling-") as raw_temp:
        temp = Path(raw_temp)
        for case_index, (dispatcher, vm_count) in enumerate(CASES):
            config_path = temp / f"config-{case_index}.json"
            config_path.write_text(
                json.dumps(config(dispatcher, vm_count)), encoding="utf-8"
            )
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
                        str(8200 + case_index * 100 + script_index),
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
                for helper in ("_ss_step", "_ss_value", "_ds"):
                    if f"local function {helper}" not in emitted:
                        raise AssertionError(
                            f"missing {helper} ({dispatcher}, {script_name})"
                        )
                for call in ("_ss_step(_ip,op,A,B,C)", "_ds(op)"):
                    if call not in emitted:
                        raise AssertionError(
                            f"missing hot-path call {call} "
                            f"({dispatcher}, {script_name})"
                        )
                builds += 1

    print(
        f"state-coupling-ok builds={builds} "
        "dispatchers=ifelseif,bsearch,split4,bsplit4,tailcall,mixed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
