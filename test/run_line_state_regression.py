from __future__ import annotations

import os
import random
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

from obfuscator import Pipeline, build_pipeline_from_config
from obfuscator.profiling import Profiler
from obfuscator.vm.vm_variants import _render_tamper, apply_line_state


LUA = ROOT_DIR / "bin" / ("lua.exe" if os.name == "nt" else "lua")
if not LUA.exists():
    LUA = Path(shutil.which("lua5.3") or shutil.which("lua53") or shutil.which("lua") or "lua")


def run_lua(path: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run([str(LUA), str(path), *args], capture_output=True, timeout=120)
    result.stdout = result.stdout.replace(b"\r\n", b"\n")
    result.stderr = result.stderr.replace(b"\r\n", b"\n")
    return result


def vm_config(passes: list[str]) -> dict:
    return {
        "passes": passes,
        "vm_output_passes": [],
        "packer_output_passes": [],
        "vm_options": {
            "dispatcher_type": "ifelseif",
            "blob_form": "string",
            "vm_count": 1,
            "fake_handlers": False,
            "mutate_handlers": False,
            "junk_instructions": False,
            "junk_rate": 0.0,
            "integrity_constants": True,
            "integrity_constant_rate": 1.0,
            "graph_execution_rate": 0.0,
            "cross_instruction_rate": 0.0,
            "runtime_polymorphism_rate": 0.0,
            "block_variant_rate": 0.0,
            "helper_variant_count": 1,
            "helper_diversity_rate": 0.0,
            "semantic_diversity_rate": 0.0,
        },
        "signature": {"mode": "custom", "custom": "line state\nregression"},
    }


def main() -> int:
    tamper = _render_tamper()
    for function_name in (
        "error", "pcall", "tostring", "tonumber", "string.match",
    ):
        if f"_isC({function_name})" not in tamper:
            raise AssertionError(f"line-state dependency lacks C check: {function_name}")

    random.seed(16016)
    prefix = "-- probe signature\n-- second line\n"
    random_state = random.getstate()
    rendered, expected_state, probe_lines = apply_line_state(
        "return function(...) return _LS end",
        prefix,
    )
    if random.getstate() != random_state:
        raise AssertionError("line-state generator consumed the pipeline PRNG")
    if len(probe_lines) < 3 or len(set(probe_lines)) != len(probe_lines):
        raise AssertionError(f"line probes were not distributed: {probe_lines}")
    if str(probe_lines[0]) in rendered and "expected" in rendered.lower():
        raise AssertionError("line-state source exposed an expected-line comparison")
    if "_LS" in rendered:
        raise AssertionError("line-state source retained the fixed state identifier")

    random.seed(16017)
    late_rendered, _, _ = apply_line_state(
        "return function(...) return _LS end",
        output_passes=[
            "rename_obf", "localize_globals", "string_obf",
            "boolean_obf", "number_obf",
        ],
    )
    for leaked in ("_LS", "error(", "pcall(", "tostring(", "tonumber(", "string.match("):
        if leaked in late_rendered:
            raise AssertionError(f"late line-state emitter leaked {leaked!r}")

    with tempfile.TemporaryDirectory(prefix="karity-line-state-") as raw_temp:
        temp = Path(raw_temp)
        probe = temp / "probe.lua"
        runner = temp / "runner.lua"
        probe.write_text(prefix + rendered, encoding="utf-8")
        runner.write_text(
            "local f=assert(loadfile(arg[1]))()\n"
            "if arg[2]=='strip' then f=assert(load(string.dump(f,true))) end\n"
            "print(f())\n",
            encoding="utf-8",
        )

        clean = run_lua(runner, str(probe))
        stripped = run_lua(runner, str(probe), "strip")
        expected_stdout = f"{expected_state}\n".encode()
        if (clean.returncode, clean.stdout, clean.stderr) != (0, expected_stdout, b""):
            raise AssertionError(
                f"clean line state mismatch: expected={expected_stdout!r}, "
                f"actual={(clean.returncode, clean.stdout, clean.stderr)!r}"
            )
        if stripped.returncode != 0 or stripped.stdout == expected_stdout:
            raise AssertionError(
                "stripped bytecode retained the clean source-line state: "
                f"{(stripped.returncode, stripped.stdout, stripped.stderr)!r}"
            )

        for index, passes in enumerate((["vm"], ["vm", "pack"])):
            profiler = Profiler()
            output = build_pipeline_from_config(vm_config(passes), Pipeline).run(
                "local x=123456789; print(x+7)",
                profiler=profiler,
            )
            output_path = temp / f"vm-{index}.lua"
            output_path.write_text(output, encoding="utf-8")
            result = run_lua(output_path)
            if (result.returncode, result.stdout, result.stderr) != (0, b"123456796\n", b""):
                raise AssertionError(
                    f"line/integrity constant runtime mismatch for {passes}: "
                    f"{(result.returncode, result.stdout, result.stderr)!r}"
                )
            details = [
                detail
                for record in profiler.records
                for detail in record.details
                if detail.get("phase") == "source_line_state"
            ]
            if not details or details[0].get("probe_count", 0) < 3:
                raise AssertionError(f"missing line-state profile for {passes}")

    print("line-state-regression-ok probes=3-5 vm=standalone,packed integrity=forced")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
