from __future__ import annotations

import random
import re
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
from obfuscator.vm.mov.layout import make_kits
from obfuscator.vm.mov.division import divide
from obfuscator.vm.mov.ir import Host, Op
from obfuscator.vm.mov.lower import lower
from obfuscator.vm.mov.float_compare import compare as compare_floats
from obfuscator.vm.mov.float_ops import negate as negate_float
from obfuscator.vm.mov.shift import shift
from obfuscator.vm.mov.mixed_compare import compare as compare_mixed
from obfuscator.vm.mov.string_compare import compare as compare_strings
from obfuscator.vm.mov.string_ops import length as string_length, concatenate as string_concat
from obfuscator.vm.mov.tables import banks
from run_vm_backend_regression import lua_executable, options
from mov_shift_checks import check_shift_microcode


def run(path: Path) -> tuple:
    result = subprocess.run([lua_executable(), str(path)], capture_output=True, timeout=120)
    return result.returncode, result.stdout, result.stderr


def check_division_work() -> None:
    """Measure executed microinstructions, independent of CI machine speed."""
    encode = make_kits(1)[0].encode
    decode = {value: i for i, value in enumerate(encode)}
    add, sub = [
        {x: {y: {c: {1: pair[0], 2: pair[1]} for c, pair in enumerate(states)}
             for y, states in enumerate(ys)} for x, ys in enumerate(bank)}
        for bank in banks(encode)[:2]
    ]
    code = []
    divide(code)

    def execute(a, b):
        slots = {1: 0, 17: 1, 18: 2, 21: encode[0], 25: add, 30: True,
                 27: {encode[i]: i != 0 for i in range(16)}, 162: sub, 163: False,
                 164: {encode[i]: i >= 8 for i in range(16)},
                 165: {i: {1: i-1, 2: i>1, 3: max(i-4, 0), 4: i>4} for i in range(1, 65)},
                 168: {x: {y: x != y for y in (False, True)} for x in (False, True)},
                 170: False, 172: {0: True, 1: False}, 173: 64}
        slots.update({32+i: i for i in range(16)})
        slots[2] = {i: encode[(a >> (4*i)) & 15] for i in range(16)}
        slots[3] = {i: encode[(b >> (4*i)) & 15] for i in range(16)}
        pc = 1
        for steps in range(1, 50000):
            ins = code[pc-1]
            pc += 1
            if ins.op == Op.MOVE:
                slots[ins.a] = slots[ins.b]
            elif ins.op == Op.LOOKUP:
                slots[ins.a] = slots[ins.b][slots[ins.c]]
            elif ins.op == Op.SELECT:
                assert isinstance(slots[ins.a], bool)
                pc = ins.b if slots[ins.a] else ins.c
            else:
                assert ins.a == Host.COMMIT
                value = sum(decode[slots[64+i]] << (4*i) for i in range(16))
                assert value == (a // b) & ((1 << 64)-1)
                return steps
        raise AssertionError("division recipe did not terminate")

    small, large, zero = execute(7, 3), execute((1 << 63)-1, 3), execute(0, 3)
    execute(-17, 3)
    assert zero < small < large // 2, (zero, small, large)
    print(f"mov-division-work small={small} full_width={large} zero={zero}", flush=True)


def check_cli(profile: str, extra: list[str], source_name: str = "14_vm_call_machine.lua") -> None:
    with tempfile.TemporaryDirectory(prefix="mov-cli-") as temp:
        source = ROOT / "test" / "scripts" / source_name
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
    check_shift_microcode()
    check_division_work()
    classic = (ROOT / "obfuscator/vm/runtimes/classic_exec.lua").read_text(encoding="utf-8")
    runtime = build_runtime(classic, make_kits(3))
    dispatches = runtime.split("and q[2]==0 then")[1:]
    assert len(dispatches) == 3
    for dispatch in dispatches:
        dispatch = dispatch.split('else error("bad MOV instruction")', 1)[0]
        assert not re.search(r"(?:if|elseif)\s+op==\d+\s+then", dispatch)
    assert "if slot==" not in runtime
    keys = re.findall(r"_mov_host\[op~(\d+)\]", runtime)
    assert len(keys) == 3 and len(set(keys)) == 3
    assert runtime.count("local _mov_host={") == 3
    recipe = []
    divide(recipe)
    assert {i.a for i in recipe if i.op == Op.HOST} == {Host.COMMIT, Host.DIVZERO}
    assert all(i.op in (Op.MOVE, Op.LOOKUP, Op.SELECT, Op.HOST) for i in recipe)
    float_recipe = []
    compare_floats(float_recipe)
    assert all(i.op in (Op.MOVE, Op.LOOKUP, Op.SELECT) for i in float_recipe)
    unary_recipe = []
    negate_float(unary_recipe)
    assert {i.a for i in unary_recipe if i.op == Op.HOST} == {Host.COMMIT_FLOAT}
    shift_recipe = []
    shift(shift_recipe)
    assert {i.a for i in shift_recipe if i.op == Op.HOST} == {Host.COMMIT}
    assert "local count=rget(C)" not in runtime
    mixed_recipe = []
    compare_mixed(mixed_recipe)
    assert all(i.op in (Op.MOVE, Op.LOOKUP, Op.SELECT) for i in mixed_recipe)
    string_recipe = []
    compare_strings(string_recipe)
    assert all(i.op in (Op.MOVE, Op.LOOKUP, Op.SELECT) for i in string_recipe)
    for build_recipe, commit in ((string_length, Host.COMMIT), (string_concat, Host.COMMIT_STRING)):
        code = []
        build_recipe(code)
        assert {i.a for i in code if i.op == Op.HOST} == {commit}
    for opcode in (27, 34, 35):
        program = lower([opcode])
        site = program.code[:program.entries[1] - 1]
        assert any(i.op == Op.LOOKUP for i in site)
        assert not any(i.op == Op.HOST and i.a == Host.EXEC for i in site)
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
    division = ROOT / "test" / "fixtures" / "mov_division.lua"
    fixtures.append(division)
    shifts = ROOT / "test/fixtures/mov_shift.lua"
    fixtures.append(shifts)
    floats = ROOT / "test" / "fixtures" / "mov_float_compare.lua"
    fixtures.append(floats)
    float_unary = ROOT / "test/fixtures/mov_float_unary.lua"
    fixtures.append(float_unary)
    mixed = ROOT / "test" / "fixtures" / "mov_mixed_compare.lua"
    fixtures.append(mixed)
    strings = ROOT / "test" / "fixtures" / "mov_string_compare.lua"
    fixtures.append(strings)
    string_ops = ROOT / "test" / "fixtures" / "mov_string_ops.lua"
    fixtures.append(string_ops)
    for i, source in enumerate(fixtures):
        check(source, base, ["rename_obf", "minify"], 7100 + i)
    for i, form in enumerate(("table", "numeric", "string")):
        opts = {**base, "vm_count": i + 1, "blob_form": form, "junk_instructions": True, "junk_rate": 0.2,
                "integrity_constants": True, "integrity_constant_rate": 1.0}
        check(focused, opts, ["rename_obf", "minify"], 8100 + i)
        check(cross_vm, opts, ["rename_obf", "minify"], 8200 + i)
    # A semantic comparison alone could pass if every operation accidentally
    # fell back to native Lua. Make native integer fallbacks fail explicitly.
    def forbid_native_fallbacks(classic, opcodes):
        classic = classic.replace('elseif op==28 then', '''elseif op==28 then
            if type(rget(B))=="string" then error("native string length fallback") end;''')
        classic = classic.replace('elseif op==29 then', '''elseif op==29 then
            local strings=true
            for slot=B,C do if type(rget(slot))~="string" then strings=false; break end end
            if strings then error("native string concat fallback") end;''')
        for op in (31, 32, 33):
            marker = f"elseif op=={op} then"
            assert marker in classic
            if op == 31:
                guard = 'error("native string equality fallback")'
            else:
                guard = """local collate
                    if type(os)=="table" and type(os.setlocale)=="function" then
                        collate=os.setlocale(nil,"collate") end
                    if collate=="C" or collate=="POSIX" then
                        error("native binary string ordering fallback") end
                    _G.__mov_host_order_seen=true"""
            classic = classic.replace(marker, marker + '\nif type(rget(B))=="string" and type(rget(C))=="string" then\n' + guard + '\nend;')
        for op in (31, 32, 33):
            marker = f"elseif op=={op} then"
            assert marker in classic
            classic = classic.replace(marker, marker + """
                if type(rget(B))=="number" and type(rget(C))=="number" then
                    error("native numeric comparison fallback") end;""")
        for op in (27, 34, 35):
            marker = f"elseif op=={op} then"
            assert marker in classic
            classic = classic.replace(marker, marker + ' error("native boolean fallback");')
        for op in (16, 19, 31, 32, 33):
            marker = f"elseif op=={op} then"
            assert marker in classic
            classic = classic.replace(marker, marker + """
                if math.type(rget(B))=="integer" and math.type(rget(C))=="integer" then
                    error("native integer comparison/division fallback") end;""")
        runtime = build_runtime(classic, opcodes)
        runtime = '_G.__mov_order_test=true\n' + runtime
        assert "local function _arith2(a,b,av,slot)" in runtime
        assert "local function _arith1(a,av,slot)" in runtime
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
            if math.type(a)=="float" and slot==__VM_SLOT_UNM__ then
                error("native float negation fallback") end
            if math.type(a)=="integer" then error("native integer unary fallback") end""",
        )
        return runtime
    with patch("obfuscator.vm.mov.builder.build_runtime", forbid_native_fallbacks):
        check(focused, {**base, "vm_count": 3}, [], 9000)
        check(shifts, {**base, "vm_count": 3, "blob_form": "table",
                       "integrity_constants": True, "integrity_constant_rate": 1.0},
              ["rename_obf", "minify"], 10301)
        check(float_unary, {**base, "vm_count": 3, "blob_form": "table",
                            "integrity_constants": True, "integrity_constant_rate": 1.0},
              ["rename_obf", "minify"], 10201)
        check(division, {**base, "vm_count": 3, "blob_form": "table",
                         "integrity_constants": True, "integrity_constant_rate": 1.0},
              ["rename_obf", "minify"], 9701)
        check(floats, {**base, "vm_count": 3, "blob_form": "table",
                       "integrity_constants": True, "integrity_constant_rate": 1.0},
              ["rename_obf", "minify"], 9801)
        check(mixed, {**base, "vm_count": 3, "blob_form": "table",
                      "integrity_constants": True, "integrity_constant_rate": 1.0},
              ["rename_obf", "minify"], 9901)
        check(strings, {**base, "vm_count": 3, "blob_form": "table",
                        "integrity_constants": True, "integrity_constant_rate": 1.0},
              ["rename_obf", "minify"], 10001)
        check(string_ops, {**base, "vm_count": 3, "blob_form": "table",
                           "integrity_constants": True, "integrity_constant_rate": 1.0},
              ["rename_obf", "minify"], 10101)
        # Output literal obfuscation may itself use string.char; this trap
        # targets the VM value representation without those unrelated layers.
        check(ROOT / "test/fixtures/mov_string_storage.lua", {**base, "vm_count": 2}, [], 10103)
    check(ROOT / "test" / "scripts" / "14_vm_call_machine.lua", {**base, "vm_count": 2},
          ["function_obf", "rename_obf", "localize_globals", "string_obf",
           "boolean_obf", "number_obf", "minify"], 9100)
    check(division, {**base, "vm_count": 2, "blob_form": "numeric"},
          ["function_obf", "rename_obf", "localize_globals", "string_obf",
           "boolean_obf", "number_obf", "minify"], 9702)
    check(shifts, {**base, "vm_count": 2, "blob_form": "numeric"},
          ["function_obf", "rename_obf", "localize_globals", "string_obf",
           "boolean_obf", "number_obf", "minify"], 10302)
    check(floats, {**base, "vm_count": 2, "blob_form": "numeric"},
          ["function_obf", "rename_obf", "localize_globals", "string_obf",
           "boolean_obf", "number_obf", "minify"], 9802)
    check(mixed, {**base, "vm_count": 2, "blob_form": "numeric"},
          ["function_obf", "rename_obf", "localize_globals", "string_obf",
           "boolean_obf", "number_obf", "minify"], 9902)
    check(float_unary, {**base, "vm_count": 2, "blob_form": "numeric"},
          ["function_obf", "rename_obf", "localize_globals", "string_obf",
           "boolean_obf", "number_obf", "minify"], 10202)
    check(strings, {**base, "vm_count": 2, "blob_form": "numeric"},
          ["function_obf", "rename_obf", "localize_globals", "string_obf",
           "boolean_obf", "number_obf", "minify"], 10002)
    check(string_ops, {**base, "vm_count": 2, "blob_form": "numeric"},
          ["function_obf", "rename_obf", "localize_globals", "string_obf",
           "boolean_obf", "number_obf", "minify"], 10102)
    check_cli("fast-vm", ["--seed", "9300"])
    check_cli("fast-vm", ["--seed", "9300", "--passes", "vm,pack"])
    # The release-profile check covers the complete CLI/config/pipeline path.
    # Use a compact fixture here: call-machine semantics are already exercised
    # above, while their MOV microcode can exceed hosted-runner wall-clock limits.
    check_cli("high", ["--release-check"], "01_helloWorld.lua")
    print(f"mov-backend-regression-ok fixtures={len(fixtures)} protected_variants=6 multi_vm=ok lookup_fallback_traps=ok output_passes=ok cli_packer_release=ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
