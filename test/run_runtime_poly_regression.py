from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time


ROOT_DIR = Path(__file__).resolve().parents[1]
LUA = ROOT_DIR / "bin" / ("lua.exe" if os.name == "nt" else "lua")
TRACE_RE = re.compile(
    rb"(?:^|\r?\n)karity-vm-trace:([0-9a-f]{16}) "
    rb"blocks:([0-9]+) blocktrace:([0-9a-f]{16})\r?\n?"
)


def lua_executable() -> str:
    if LUA.exists():
        return str(LUA)
    return shutil.which("lua5.3") or shutil.which("lua53") or shutil.which("lua") or "lua"


def run_lua(lua: str, script: Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run([lua, str(script)], capture_output=True, timeout=120)


def main() -> int:
    lua = lua_executable()
    source = ROOT_DIR / "test" / "scripts" / "18_vm_cross_instruction_semantics.lua"
    expected = run_lua(lua, source)
    if expected.returncode != 0:
        raise RuntimeError(f"source failed: {expected.stderr!r}")

    config = {
        "passes": ["vm"],
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
            "integrity_constants": False,
            "integrity_constant_rate": 0.0,
            "graph_execution_rate": 1.0,
            "cross_instruction_rate": 1.0,
            "runtime_polymorphism_rate": 1.0,
            "runtime_trace": True,
            "block_variant_rate": 1.0,
            "block_variant_count": 3,
            "block_variant_max_instructions": 4,
        },
    }

    with tempfile.TemporaryDirectory(prefix="karity-poly-") as temp:
        temp_dir = Path(temp)
        config_path = temp_dir / "config.json"
        output_path = temp_dir / "runtime-poly.lua"

        def build_output(settings: dict, path: Path, seed: int) -> None:
            config_path.write_text(json.dumps(settings), encoding="utf-8")
            build = subprocess.run(
                [
                    sys.executable,
                    str(ROOT_DIR / "main.py"),
                    str(source),
                    "-o",
                    str(path),
                    "--config",
                    str(config_path),
                    "--seed",
                    str(seed),
                ],
                capture_output=True,
                timeout=600,
            )
            if build.returncode != 0:
                raise RuntimeError(f"build failed: {(build.stderr or build.stdout)!r}")

        build_output(config, output_path, 7301)

        traces: set[bytes] = set()
        block_traces: set[bytes] = set()
        poly_start = time.perf_counter()
        for _ in range(5):
            result = run_lua(lua, output_path)
            matches = TRACE_RE.findall(result.stderr)
            clean_stderr = TRACE_RE.sub(b"", result.stderr)
            if result.returncode != expected.returncode:
                raise AssertionError(f"return code mismatch: {result.returncode}")
            if result.stdout != expected.stdout or clean_stderr != expected.stderr:
                raise AssertionError(
                    f"semantic output mismatch: stdout={result.stdout!r} stderr={clean_stderr!r}"
                )
            if len(matches) != 1:
                raise AssertionError(f"missing runtime trace: {result.stderr!r}")
            trace, block_count, block_trace = matches[0]
            if int(block_count) == 0:
                raise AssertionError("no runtime block variant was executed")
            traces.add(trace)
            block_traces.add(block_trace)
        poly_elapsed = time.perf_counter() - poly_start

        baseline = json.loads(json.dumps(config))
        baseline["vm_options"]["runtime_polymorphism_rate"] = 0.0
        baseline["vm_options"]["runtime_trace"] = False
        baseline["vm_options"]["block_variant_rate"] = 0.0
        baseline_path = temp_dir / "runtime-baseline.lua"
        build_output(baseline, baseline_path, 7302)
        baseline_start = time.perf_counter()
        for _ in range(5):
            result = run_lua(lua, baseline_path)
            if (result.returncode, result.stdout, result.stderr) != (
                expected.returncode,
                expected.stdout,
                expected.stderr,
            ):
                raise AssertionError("disabled runtime polymorphism changed semantics")
        baseline_elapsed = time.perf_counter() - baseline_start

    if len(traces) < 3:
        raise AssertionError(f"insufficient trace diversity: {sorted(traces)!r}")
    if len(block_traces) < 3:
        raise AssertionError(
            f"insufficient block-route diversity: {sorted(block_traces)!r}"
        )
    ratio = poly_elapsed / baseline_elapsed if baseline_elapsed else float("inf")
    print(
        f"runtime-poly-ok runs=5 unique_traces={len(traces)} "
        f"unique_block_traces={len(block_traces)} process_time_ratio={ratio:.3f}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
