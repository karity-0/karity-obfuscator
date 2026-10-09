from __future__ import annotations

from pathlib import Path
import random
import subprocess
import sys
import tempfile
from unittest.mock import patch
from lua_runtime import lua_executable


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

from obfuscator.registry import ConfigError, validate_config, validate_release_config
from obfuscator.vm import VMPass


def check_classic_optimizer() -> None:
    """Exercise the optimizer independently of a random handler layout."""
    from obfuscator.vm.backends.classic_optimizer import optimize_layout
    from obfuscator.vm.backends.handler_ir import (
        HandlerFunction, HandlerInstruction, OPERATION_IDS,
    )
    from obfuscator.vm.backends.handler_layout import (
        PhysicalFunction, PhysicalInstruction,
    )

    def jump(index: int, target: int, *, close: int = 0) -> HandlerInstruction:
        return HandlerInstruction(
            OPERATION_IDS["JUMP"], close,
        ).with_bx(target - index - 1 + 131071)

    def function(*, protected: bool = False, close: bool = False) -> PhysicalFunction:
        raw = [jump(0, 1, close=int(close)), jump(1, 3),
               HandlerInstruction(OPERATION_IDS["MOVE"]),
               HandlerInstruction(OPERATION_IDS["RETURN"])]
        source = HandlerFunction("optimizer", 0, 0, 1, raw, [], [], [])
        items = [
            PhysicalInstruction(instruction, index, (),
                                ((1, 1, 1, 1, 0),) if protected and index == 1 else ())
            for index, instruction in enumerate(raw)
        ]
        return PhysicalFunction(source, 0, items, [], set(), False, [])

    layout = type("Layout", (), {"functions": function()})()
    statistics, events = optimize_layout(layout)
    assert statistics == {
        "before": 4, "after": 4,
        "jump_chain_redirects": 1, "jump_chain_rejections": 0,
    }
    assert layout.functions.code[0].instruction.sbx == 2
    assert events == ({
        "function": "optimizer", "pc": 0, "kind": "jump-chain",
        "outcome": "applied", "target": 3,
    },)

    protected_layout = type("Layout", (), {"functions": function(protected=True)})()
    _, protected_events = optimize_layout(protected_layout)
    assert protected_layout.functions.code[0].instruction.sbx == 0
    assert protected_events[0]["reason"] == "graph-boundary"

    close_layout = type("Layout", (), {"functions": function(close=True)})()
    _, close_events = optimize_layout(close_layout)
    assert close_layout.functions.code[0].instruction.sbx == 0
    assert close_events[0]["reason"] == "upvalue-close"


def check_karity_cross_instruction_cache() -> None:
    """Measure a hit on a later instruction, not merely a duplicate operand."""
    from lupa.lua51 import LuaRuntime as Lua51Runtime
    from obfuscator.vm.targets.lua51 import Lua51Target
    from obfuscator.vm.targets.lua53 import Lua53Target
    from obfuscator.vm.targets.profile import TargetProfile

    source = (
        "local anchor=7; local sum=0; "
        "for i=1,80 do local a=anchor; local b=anchor; "
        "sum=sum+a+b end; assert(sum==1120)"
    )
    def execute(version, output):
        if version == "5.1":
            try:
                Lua51Runtime(encoding=None).execute(output.encode())
            except Exception as error:
                return str(error)
            return None
        with tempfile.TemporaryDirectory(prefix="karity-cache-") as temp:
            path = Path(temp) / "output.lua"
            path.write_text(output, encoding="utf-8")
            result = subprocess.run([lua_executable(), str(path)], capture_output=True,
                                    timeout=120)
        return result.stderr.decode(errors="replace") if result.returncode else None

    for version, target_class, cache in (
            ("5.1", Lua51Target, "_MJ._RC"),
            ("5.3", Lua53Target, "_RC")):
        original = target_class.runtime_template
        cache_options = options("karity")
        cache_options.update({"helper_variant_count": 4, "helper_diversity_rate": 1.0})
        mode = "cross"

        def instrument(self, name):
            template = original(self, name)
            if name != "vm.lua":
                return template
            reads = f"local cached={cache}[i]"
            hit = "if cached then return cached[1] end"
            store = f"{cache}[i]={{value}}"
            nil_store = f"{cache}[i]={{nil}}"
            for marker in (reads, hit, store, nil_store):
                if template.count(marker) != 1:
                    raise AssertionError(f"Karity cache instrumentation lost {marker}")
            if mode == "cross":
                check = ("if cached then if cached[2]~=pc then "
                         "error('cross-instruction-cache-hit') end; return cached[1] end")
            else:
                check = ("if cached then if cached[3]~=_RE[_rpos(3,i)] then "
                         "error('stale-register-cache') end; return cached[1] end")
            template = template.replace(hit, check)
            return (template.replace(store, f"{cache}[i]={{value,pc,_RE[_rpos(3,i)]}}")
                    .replace(nil_store, f"{cache}[i]={{nil,pc,_RE[_rpos(3,i)]}}"))

        random.seed(7719)
        normal_output = VMPass(
            target=TargetProfile(version, "karity"),
            vm_options=cache_options, vm_output_passes=[],
        ).run(source)
        if f"{cache}[i]=nil" not in normal_output:
            raise AssertionError(f"Karity {version} cloned rset omitted cache invalidation")
        normal_error = execute(version, normal_output)
        if normal_error is not None:
            raise AssertionError(f"Karity {version} normal cache runtime failed: {normal_error}")
        random.seed(7719)
        with patch.object(target_class, "runtime_template", instrument):
            output = VMPass(
                target=TargetProfile(version, "karity"),
                vm_options=cache_options, vm_output_passes=[],
            ).run(source)
        error = execute(version, output)
        if error is None or "cross-instruction-cache-hit" not in error:
            raise AssertionError(
                f"Karity {version} did not reuse a read across instructions: {error}"
            )
        mode = "stale"
        random.seed(7719)
        with patch.object(target_class, "runtime_template", instrument):
            checked_output = VMPass(
                target=TargetProfile(version, "karity"),
                vm_options=cache_options, vm_output_passes=[],
            ).run(source)
        stale_error = execute(version, checked_output)
        if stale_error is not None:
            raise AssertionError(f"Karity {version} reused a stale register: {stale_error}")



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


def run_output(source: str, backend: str, dispatcher: str = "ifelseif",
               output_passes: list[str] | None = None,
               vm_options: dict | None = None) -> bytes:
    dispatch_seeds = {
        "ifelseif": 3400, "tailcall": 3401, "table": 3402,
        "bsearch": 3403, "split4": 3404, "bsplit4": 3405, "mixed": 3406,
    }
    random.seed(1200 if backend == "karity" else dispatch_seeds[dispatcher])
    output_prefix = "-- backend regression\n" if backend == "classic" else ""
    selected_options = options(backend, dispatcher)
    if vm_options:
        selected_options.update(vm_options)
    vm = VMPass(
        # Exercise the shared current output pipeline through the classic
        # runtime as well. Karity's emitter has its own focused suite.
        vm_output_passes=(output_passes if output_passes is not None
                          else ["minify"] if backend == "classic" else []),
        vm_options=selected_options,
        output_prefix=output_prefix,
    )
    # VMPass accounts for the outer pipeline's signature when deriving its
    # source-bound key; Pipeline is responsible for prepending that signature.
    output = output_prefix + vm.run(source)
    if backend in ("karity", "default") and not selected_options["semantic_state_threading"]:
        for call in ("_ss_step(_ip,op,A,B,C)",
                     "_ss_value(i,encoded,epoch,kind)"):
            if call in output:
                raise AssertionError(f"disabled Karity semantic-state call survived: {call}")
        if output.count("_ss_value(slot,encoded,epoch,kind)") != output.count(
                "local function _ss_value(slot,encoded,epoch,kind)"):
            raise AssertionError("disabled Karity register-write semantic-state call survived")
    if "__call" in output or "VM_DISPATCH_ENTRY" in output:
        raise AssertionError(f"dispatcher signature leaked for {backend}/{dispatcher}")
    if vm.backend != ("karity" if backend == "default" else backend):
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
    check_classic_optimizer()
    check_karity_cross_instruction_cache()
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
    if VMPass(vm_options={"backend": "default"}).backend != "karity":
        raise AssertionError("default alias must resolve to karity")

    source = ('local empty=""; assert(type(empty)=="string" and #empty==0); '
              'local seen=0; for _,v in ipairs({1,empty,3}) do seen=seen+1 end; '
              'assert(seen==3); local x=20+22; local t={x,3}; print(t[1]+t[2])')
    cases = [("karity", "ifelseif"), ("default", "ifelseif")] + [
        ("classic", dispatcher)
        for dispatcher in (
            "ifelseif", "tailcall", "table", "bsearch",
            "split4", "bsplit4", "mixed",
        )
    ]
    for backend in ("karity", "classic", "mov"):
        dispatchers = (("ifelseif",) if backend == "mov" else
                       ("ifelseif", "bsearch", "tailcall", "split4", "bsplit4", "mixed"))
        for dispatcher in dispatchers:
            for output_passes in ([], ["function_obf"]):
                actual = run_output(source, backend, dispatcher, output_passes)
                if actual != b"45\n":
                    raise AssertionError(
                        f"dispatcher annotation changed {backend}/{dispatcher}: {actual!r}"
                    )
    for backend, dispatcher in cases:
        stdout = run_output(source, backend, dispatcher)
        if stdout != b"45\n":
            raise AssertionError(
                f"{backend}/{dispatcher} semantic mismatch: {stdout!r}"
            )

    # CALL, metamethod dispatch, and protected calls all cross the Karity
    # native-value boundary. Verify coroutine suspension/resumption and error
    # propagation on the same script for each backend.
    boundary_source = (ROOT_DIR / "test/fixtures/backend_escape_boundaries.lua").read_text(
        encoding="utf-8"
    )
    for backend in ("classic", "karity", "mov"):
        stdout = run_output(boundary_source, backend)
        if stdout != b"pause\t11\t40\tfalse\tfalse\n":
            raise AssertionError(
                f"{backend} coroutine/native-boundary mismatch: {stdout!r}"
            )
    metamethod_yield_source = (
        ROOT_DIR / "test/fixtures/backend_metamethod_yield.lua"
    ).read_text(encoding="utf-8")
    for backend in ("classic", "karity", "mov"):
        stdout = run_output(metamethod_yield_source, backend)
        if stdout != b"add\t42\n":
            raise AssertionError(
                f"{backend} Lua 5.3 metamethod-yield mismatch: {stdout!r}"
            )

    repeated_pending = (ROOT_DIR / "test/fixtures/backend_repeated_pending.lua").read_text(
        encoding="utf-8"
    )
    stdout = run_output(
        repeated_pending, "karity",
        vm_options={"cross_instruction_rate": 1.0,
                    "runtime_polymorphism_rate": 1.0,
                    "graph_execution_rate": 0.0},
    )
    if stdout != b"44\n":
        raise AssertionError(f"Karity repeated pending operand mismatch: {stdout!r}")

    comparison_source = (
        'local x=11; local y=x+1; '
        'assert(y==y and not (y<y) and y<=y); '
        'local calls=0; local t=setmetatable({}, '
        '{__lt=function(a,b) calls=calls+1; return true end}); '
        'assert(t<t and calls==1); '
        'local n=0/0; assert(not (n==n)); '
        'print(calls)'
    )
    for diversity in (0.0, 1.0):
        stdout = run_output(
            comparison_source, "karity",
            vm_options={"cross_instruction_rate": 1.0,
                        "semantic_diversity_rate": diversity,
                        "graph_execution_rate": 0.0},
        )
        if stdout != b"1\n":
            raise AssertionError(
                f"Karity repeated comparison operand mismatch: {stdout!r}"
            )

    print("vm-backend-regression-ok backends=classic,karity,mov "
          "annotation_cases=26 classic_dispatchers=7 alias=default")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
