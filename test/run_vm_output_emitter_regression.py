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
from obfuscator.vm.output_emitter import emit_vm_literals


LUA = ROOT_DIR / "bin" / ("lua.exe" if os.name == "nt" else "lua")
if not LUA.exists():
    LUA = Path(shutil.which("lua5.3") or shutil.which("lua53") or shutil.which("lua") or "lua")


def run_source(source: str) -> tuple[int, bytes, bytes]:
    with tempfile.TemporaryDirectory(prefix="karity-vm-emitter-") as raw_temp:
        path = Path(raw_temp) / "emitter.lua"
        path.write_text(source, encoding="utf-8")
        result = subprocess.run([str(LUA), str(path)], capture_output=True, timeout=120)
        return (
            result.returncode,
            result.stdout.replace(b"\r\n", b"\n"),
            result.stderr.replace(b"\r\n", b"\n"),
        )


def vm_config() -> dict:
    return {
        "passes": ["vm"],
        "vm_output_passes": [
            "string_obf", "boolean_obf", "number_obf", "minify",
        ],
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
            "graph_execution_rate": 0.0,
            "cross_instruction_rate": 0.0,
            "runtime_polymorphism_rate": 0.0,
            "block_variant_rate": 0.0,
            "helper_variant_count": 1,
            "helper_diversity_rate": 0.0,
            "semantic_diversity_rate": 0.0,
        },
        "signature": {"mode": "none"},
    }


def walk_details(details: list[dict]):
    for detail in details:
        yield detail
        nested = detail.get("details")
        if isinstance(nested, list):
            yield from walk_details(nested)


def main() -> int:
    random.seed(260826)
    source = (
        'local s="hello";local t=true;local f=false;local n=123;'
        'print(s,t,f,n)'
    )
    emitted, details = emit_vm_literals(
        source,
        ["string_obf", "boolean_obf", "number_obf"],
    )
    parse_details = [d for d in details if d["phase"] == "vm_output:literal_parse"]
    if len(parse_details) != 1 or parse_details[0].get("parse_count") != 1:
        raise AssertionError(f"literal backend did not parse exactly once: {details}")
    number_detail = next(d for d in details if d["phase"] == "vm_output:number_obf")
    if number_detail["replacements"] <= 10:
        raise AssertionError(
            "number emitter did not consume string/boolean generated literals: "
            f"{number_detail}"
        )
    actual = run_source(emitted)
    expected = (0, b"hello\ttrue\tfalse\t123\n", b"")
    if actual != expected:
        raise AssertionError(f"direct emitter semantic mismatch: {actual!r}")

    random.seed(260827)
    layered, layered_details = emit_vm_literals(
        "print(7)", ["number_obf", "number_obf"],
    )
    number_layers = [
        d for d in layered_details if d["phase"] == "vm_output:number_obf"
    ]
    if len(number_layers) != 2 or number_layers[1]["replacements"] <= 1:
        raise AssertionError(f"number emitter stages did not layer: {number_layers}")
    if run_source(layered) != (0, b"7\n", b""):
        raise AssertionError("layered number emitter changed semantics")

    random.seed(260828)
    char_source, char_details = emit_vm_literals(
        "print(string.char(65))", ["number_obf"],
    )
    char_number = next(d for d in char_details if d["phase"] == "vm_output:number_obf")
    if char_number["replacements"] != 0 or run_source(char_source) != (0, b"A\n", b""):
        raise AssertionError("original string.char byte-domain exclusion regressed")

    random.seed(260829)
    profiler = Profiler()
    vm_output = build_pipeline_from_config(vm_config(), Pipeline).run(
        'local s="VM_EMITTER";local ok=true;print(s,ok,321)',
        profiler=profiler,
    )
    if run_source(vm_output) != (0, b"VM_EMITTER\ttrue\t321\n", b""):
        raise AssertionError("VM emitter integration changed runtime semantics")
    vm_details = [
        detail
        for record in profiler.records
        for detail in walk_details(record.details)
    ]
    parse_count = sum(
        detail.get("parse_count", 0)
        for detail in vm_details
        if detail.get("phase") == "vm_output:literal_parse"
    )
    if parse_count != 1:
        raise AssertionError(f"VM output literal parse count mismatch: {parse_count}")

    print(
        "vm-output-emitter-ok parse_count=1 "
        f"nested_numbers={number_detail['replacements']} duplicate_layers=2"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
