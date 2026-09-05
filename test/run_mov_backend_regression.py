from __future__ import annotations

import random
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from obfuscator.registry import (
    validate_config, validate_release_config, resolve_config_profile, ReleaseCheckError,
)
from obfuscator.vm import VMPass
from obfuscator.vm.mov.builder import build_runtime
from run_vm_backend_regression import lua_executable, options


def run(path: Path) -> tuple:
    result = subprocess.run([lua_executable(), str(path)], capture_output=True, timeout=120)
    return result.returncode, result.stdout, result.stderr


def check_cli(profile: str, extra: list[str]) -> None:
    with tempfile.TemporaryDirectory(prefix="mov-cli-") as temp:
        source = ROOT / "test" / "scripts" / "14_vm_call_machine.lua"
        target = Path(temp) / "packed.lua"
        started = time.perf_counter()
        built = subprocess.run(
            [sys.executable, str(ROOT / "main.py"), str(source), "-o", str(target),
             "--config", str(ROOT / "config.example.json"), "--profile", profile,
             "--vm-option", "backend=mov", "--vm-option", "vm_count=2", *extra],
            capture_output=True, timeout=180,
        )
        assert built.returncode == 0, (built.stdout, built.stderr)
        print(f"mov-cli-built profile={profile} bytes={target.stat().st_size} elapsed={time.perf_counter()-started:.2f}s", flush=True)
        expected, actual = run(source), run(target)
        assert expected == actual, ("CLI/packer MOV semantics mismatch", expected, actual)
    print(f"mov-cli-ok profile={profile} extra={extra}", flush=True)


def check(source: Path, opts: dict, passes: list[str], seed: int) -> None:
    random.seed(seed)
    signature = "-- MOV regression\n"
    vm = VMPass(vm_options=opts, vm_output_passes=passes, output_prefix=signature)
    output = signature + vm.run(source.read_text(encoding="utf-8"))
    detail = next(p for p in vm.last_profile if p["phase"] == "mov_lowering")
    assert detail["micro_instructions"] > 0
    assert detail["stored_micro_instructions"] <= detail["micro_instructions"]
    assert detail["effective_vms"] == min(opts["vm_count"], detail["prototypes"])
    assert all(detail["vm_prototypes"]), "unused MOV interpreter"
    assert detail["digit_encoding"] == "per_vm_permutation"
    if source.name == "mov_semantics.lua":
        assert detail["lowered_sites"] > 0, "integer path was not lowered"
        assert detail["stored_micro_instructions"] < detail["micro_instructions"], "shared recipes duplicated per prototype"
    phases = next(p["details"] for p in vm.last_profile if p["phase"] == "obfuscate_vm_output")
    assert any(p["phase"] == "vm_output:mov_runtime" for p in phases)
    assert not any(p["phase"] == "vm_output:handler_graphs" for p in phases)
    assert "__MOV_" not in output
    with tempfile.TemporaryDirectory(prefix="mov-regression-") as temp:
        target = Path(temp) / "protected.lua"
        target.write_text(output, encoding="utf-8")
        expected, actual = run(source), run(target)
        if expected != actual:
            raise AssertionError(f"{source.name} seed={seed}: expected={expected!r}, actual={actual!r}")
    print(f"mov-ok {source.name} seed={seed} vms={detail['effective_vms']} sites={detail['lowered_sites']}", flush=True)


def main() -> int:
    base = options("mov")
    validate_config({"passes": ["vm"], "vm_options": base})
    for count in (2, 3):
        validate_config({"passes": ["vm"], "vm_options": {**base, "vm_count": count}})
    root_config = json.loads((ROOT / "config.example.json").read_text(encoding="utf-8"))
    release = resolve_config_profile(root_config, "high")
    release["vm_options"].update(backend="mov", fake_handlers=False,
                                  mutate_handlers=False, dispatcher_type="ifelseif")
    validate_release_config(release)
    for change in ({"vm_count": 1}, {"integrity_constants": False},
                   {"junk_instructions": False}, {"junk_rate": 0.0},
                   {"integrity_constant_rate": 0.0}, {"blob_form": "string"}):
        try:
            validate_release_config({**release, "vm_options": {**release["vm_options"], **change}})
        except ReleaseCheckError:
            pass
        else:
            raise AssertionError(f"weak MOV release settings accepted: {change}")
    fixtures = sorted((ROOT / "test" / "scripts").glob("*.lua"))
    focused = ROOT / "test" / "fixtures" / "mov_semantics.lua"
    fixtures.append(focused)
    cross_vm = ROOT / "test" / "fixtures" / "mov_cross_vm.lua"
    fixtures.append(cross_vm)
    for i, source in enumerate(fixtures):
        check(source, base, ["rename_obf", "minify"], 7100 + i)
    for i, form in enumerate(("table", "numeric", "string")):
        opts = {**base, "vm_count": i + 1, "blob_form": form, "junk_instructions": True, "junk_rate": 0.2,
                "integrity_constants": True, "integrity_constant_rate": 1.0}
        check(focused, opts, ["rename_obf", "minify"], 8100 + i)
        check(cross_vm, opts, ["rename_obf", "minify"], 8200 + i)
    # A semantic comparison alone could pass if every operation accidentally
    # fell back to native Lua. Make native integer fallbacks fail explicitly.
    def forbid_integer_fallbacks(classic, opcodes):
        runtime = build_runtime(classic, opcodes)
        runtime = runtime.replace(
            "local function _arith2(a,b,av,slot)",
            """local function _arith2(a,b,av,slot)
            if math.type(a)=="integer" and math.type(b)=="integer" and
                (slot==__VM_SLOT_ADD__ or slot==__VM_SLOT_SUB__ or slot==__VM_SLOT_MUL__ or
                 slot==__VM_SLOT_BAND__ or slot==__VM_SLOT_BOR__ or slot==__VM_SLOT_BXOR__ or
                 slot==__VM_SLOT_SHL__ or slot==__VM_SLOT_SHR__) then
                error("native integer arithmetic fallback") end""",
        ).replace(
            "local function _arith1(a,av,slot)",
            """local function _arith1(a,av,slot)
            if math.type(a)=="integer" then error("native integer unary fallback") end""",
        )
        for op in (31, 32, 33):
            marker = f"elseif op=={op} then"
            runtime = runtime.replace(marker, marker + """
                if math.type(rget(B))=="integer" and math.type(rget(C))=="integer" then
                    error("native integer comparison fallback") end;""")
        return runtime
    with patch("obfuscator.vm.mov.builder.build_runtime", forbid_integer_fallbacks):
        check(focused, {**base, "vm_count": 3}, [], 9000)
    check(ROOT / "test" / "scripts" / "14_vm_call_machine.lua", {**base, "vm_count": 2},
          ["function_obf", "rename_obf", "localize_globals", "string_obf",
           "boolean_obf", "number_obf", "minify"], 9100)
    check_cli("fast-vm", ["--seed", "9300"])
    check_cli("fast-vm", ["--seed", "9300", "--passes", "vm,pack"])
    check_cli("high", ["--release-check"])
    print(f"mov-backend-regression-ok fixtures={len(fixtures)} protected_variants=6 multi_vm=ok integer_fallback_trap=ok output_passes=ok cli_packer_release=ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
