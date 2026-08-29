from __future__ import annotations

import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

from obfuscator import Pipeline, build_pipeline_from_config
from obfuscator.profiling import Profiler
from obfuscator.passes.function_obfuscation import FunctionObfuscationPass
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
            "function_obf",
            "rename_obf", "localize_globals",
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
    nested_helper_source = """
local function dispatch(x)
    local marker=setmetatable({},{__call=function(t)return t end})
    local function helper(a)
        local b=a+1
        local c=b*2
        return c
    end
    return helper(x)
end
print(dispatch(3))
"""
    function_pass = FunctionObfuscationPass(skip_vm_dispatcher=True)
    helper_pipeline = Pipeline(show_header=False).add(function_pass)
    transformed_helper = helper_pipeline.run(nested_helper_source)
    if run_source(transformed_helper) != (0, b"8\n", b""):
        raise AssertionError("dispatcher helper transformation changed semantics")
    if (
        function_pass.last_skipped_dispatcher_count != 1
        or function_pass.last_transformed_count < 1
    ):
        raise AssertionError(
            "dispatcher sentinel swallowed nested helper: "
            f"skipped={function_pass.last_skipped_dispatcher_count} "
            f"transformed={function_pass.last_transformed_count}"
        )

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
    if number_detail.get("retokenized_generated_numbers") is not False:
        raise AssertionError(
            "terminal number emitter unnecessarily retokenized generated leaves: "
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
    if [
        detail.get("retokenized_generated_numbers")
        for detail in number_layers
    ] != [True, False]:
        raise AssertionError(
            "number emitter did not limit retokenization to non-terminal stages: "
            f"{number_layers}"
        )
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
    vm_runtime = run_source(vm_output)
    if vm_runtime != (0, b"VM_EMITTER\ttrue\t321\n", b""):
        raise AssertionError(
            f"VM emitter integration changed runtime semantics: {vm_runtime!r}"
        )
    if "\n" in vm_output or "\r" in vm_output:
        raise AssertionError("minified VM output retained a multiline section")
    if "obfuscated using karity obfuscator" in vm_output.lower():
        raise AssertionError("VM wrapper leaked the legacy hidden signature")
    if re.search(r"\bCTAG_(?:NIL|BOOL|INT|FLOAT|STR|IEXPR)\b", vm_output):
        raise AssertionError("VM output retained a fixed constant-tag symbol")
    if re.search(r"\bCK_(?:NIL|BOOL|INT|FLOAT|STR|IEXPR)\b", vm_output):
        raise AssertionError("VM output retained a fixed decoded-constant symbol")
    if re.search(r"\b_vmf\b", vm_output):
        raise AssertionError("VM wrapper retained the fixed _vmf binding")
    for leaked_name in (
        "_AR", "_DG", "_call_args", "_return_values", "_loop_commit",
        "_LS",
        "KARITY_EXACT_BEGIN", "KARITY_EXACT_END",
    ):
        if re.search(rf"\b{re.escape(leaked_name)}\b", vm_output):
            raise AssertionError(
                f"generated VM symbol bypassed output integration: {leaked_name}"
            )
    vm_details = [
        detail
        for record in profiler.records
        for detail in walk_details(record.details)
    ]
    parse_count = sum(
        detail.get("parse_count", 0)
        for detail in vm_details
    )
    if parse_count not in (1, 2):
        raise AssertionError(f"VM output shared parse count mismatch: {parse_count}")
    identifier_phases = {
        detail.get("phase")
        for detail in vm_details
        if detail.get("class") == "VmIdentifierEmitter"
    }
    if identifier_phases != {
        "vm_output:rename_obf", "vm_output:localize_globals",
    }:
        raise AssertionError(f"identifier emitter phases missing: {identifier_phases}")
    rename_details = [
        detail for detail in vm_details
        if detail.get("phase") == "vm_output:rename_obf"
    ]
    required_rename_timings = {
        "collect_elapsed", "scope_resolution_elapsed",
        "replacement_elapsed", "render_elapsed",
    }
    if (
        len(rename_details) != 1
        or not required_rename_timings.issubset(rename_details[0])
    ):
        raise AssertionError(f"rename phase timings missing: {rename_details}")
    function_details = [
        detail for detail in vm_details
        if detail.get("phase") == "vm_output:function_obf"
    ]
    if (
        len(function_details) != 1
        or function_details[0].get("backend") != "shared_syntax_context"
        or function_details[0].get("transformed_functions", 0) <= 0
    ):
        raise AssertionError(
            f"function pass did not reuse shared context: {function_details}"
        )
    graph_details = [
        detail for detail in vm_details
        if detail.get("phase") == "vm_output:handler_graphs"
    ]
    if (
        len(graph_details) != 1
        or graph_details[0].get("backend") != "pre_output_pipeline"
    ):
        raise AssertionError(
            f"handler graphs bypassed VM output passes: {graph_details}"
        )

    print(
        f"vm-output-emitter-ok parse_count={parse_count} "
        f"nested_numbers={number_detail['replacements']} duplicate_layers=2"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
