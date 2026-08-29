from __future__ import annotations

from pathlib import Path
import os
import random
import shutil
import subprocess
import sys
import tempfile


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

from obfuscator.registry import ConfigError, validate_config, validate_release_config
from obfuscator.vm import VMPass


def lua_executable() -> str:
    bundled = ROOT_DIR / "bin" / ("lua.exe" if os.name == "nt" else "lua")
    if bundled.exists():
        return str(bundled)
    return shutil.which("lua5.3") or shutil.which("lua53") or shutil.which("lua") or "lua"


def options(backend: str, dispatcher: str = "ifelseif") -> dict:
    return {
        "backend": backend,
        "dispatcher_type": dispatcher,
        "blob_form": "string",
        "vm_count": 1,
        "fake_handlers": False,
        "mutate_handlers": False,
        "junk_instructions": False,
        "junk_rate": 0.0,
        "integrity_constants": False,
        "integrity_constant_rate": 0.0,
        "graph_execution_rate": 0.0,
        "cross_instruction_rate": 0.0,
        "runtime_polymorphism_rate": 0.0,
        "runtime_trace": False,
        "block_variant_rate": 0.0,
        "block_variant_count": 2,
        "block_variant_max_instructions": 2,
        "helper_variant_count": 1,
        "helper_diversity_rate": 0.0,
        "semantic_diversity_rate": 0.0,
        "dispatcher_target_hiding": False,
        "semantic_state_threading": False,
        "argument_virtualization": False,
        "upvalue_virtualization": False,
        "table_virtualization": False,
        "branch_virtualization": False,
    }


def run_output(source: str, backend: str, dispatcher: str = "ifelseif") -> bytes:
    dispatch_seeds = {
        "ifelseif": 3400, "tailcall": 3401, "table": 3402,
        "bsearch": 3403, "split4": 3404, "bsplit4": 3405, "mixed": 3406,
    }
    random.seed(1200 if backend == "karity" else dispatch_seeds[dispatcher])
    output_prefix = "-- backend regression\n" if backend == "classic" else ""
    vm = VMPass(
        # Exercise the shared current output pipeline through the classic
        # runtime as well. Karity's emitter has its own focused suite.
        vm_output_passes=["minify"] if backend == "classic" else [],
        vm_options=options(backend, dispatcher),
        output_prefix=output_prefix,
    )
    # VMPass accounts for the outer pipeline's signature when deriving its
    # source-bound key; Pipeline is responsible for prepending that signature.
    output = output_prefix + vm.run(source)
    if vm.backend != backend:
        raise AssertionError(f"selected {backend}, facade reported {vm.backend}")
    if backend == "classic":
        output_profile = next(
            detail for detail in vm.last_profile
            if detail.get("phase") == "obfuscate_vm_output"
        )
        phases = [detail.get("phase") for detail in output_profile["details"]]
        if "vm_output:classic_runtime" not in phases:
            raise AssertionError("classic runtime phase was not selected")
        if "vm_output:handler_graphs" in phases:
            raise AssertionError("classic unexpectedly generated Karity handler graphs")

    with tempfile.TemporaryDirectory(prefix=f"karity-{backend}-") as temp:
        path = Path(temp) / "output.lua"
        path.write_text(output, encoding="utf-8")
        result = subprocess.run(
            [lua_executable(), str(path)], capture_output=True, timeout=120
        )
    if result.returncode != 0:
        raise AssertionError(
            f"{backend} runtime failed: rc={result.returncode} stderr={result.stderr!r}"
        )
    return result.stdout.replace(b"\r\n", b"\n")


def main() -> int:
    base_config = {
        "passes": ["vm"],
        "vm_output_passes": [],
        "packer_output_passes": [],
    }
    for backend in ("karity", "classic", "default"):
        validate_config({**base_config, "vm_options": options(backend)})

    classic_release = options("classic", "mixed")
    classic_release.update({
        "vm_count": 2,
        "fake_handlers": True,
        "mutate_handlers": True,
        "junk_instructions": True,
        "junk_rate": 0.2,
        "integrity_constants": True,
        "integrity_constant_rate": 0.2,
        "blob_form": "random",
    })
    validate_release_config({
        **base_config,
        "passes": ["anti_debug", "anti_decompile", "vm"],
        "vm_options": classic_release,
    })

    try:
        validate_config({**base_config, "vm_options": {"backend": "missing"}})
    except ConfigError:
        pass
    else:
        raise AssertionError("unknown VM backend was accepted")

    if VMPass(vm_options={}).backend != "karity":
        raise AssertionError("a missing backend must preserve current karity behavior")
    if VMPass(vm_options={"backend": "default"}).backend != "classic":
        raise AssertionError("default alias must resolve to classic")

    source = "local x=20+22; local t={x,3}; print(t[1]+t[2])"
    cases = [("karity", "ifelseif")] + [
        ("classic", dispatcher)
        for dispatcher in (
            "ifelseif", "tailcall", "table", "bsearch",
            "split4", "bsplit4", "mixed",
        )
    ]
    for backend, dispatcher in cases:
        stdout = run_output(source, backend, dispatcher)
        if stdout != b"45\n":
            raise AssertionError(
                f"{backend}/{dispatcher} semantic mismatch: {stdout!r}"
            )

    print("vm-backend-regression-ok backends=classic,karity classic_dispatchers=7 alias=default")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
