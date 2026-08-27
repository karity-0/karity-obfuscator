from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent

GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"

HEADER = "-- obfuscated using karity obfuscator!"
DEFAULT_TIMEOUT = float(os.environ.get("KARITY_PACKER_TEST_TIMEOUT", "30"))
DEFAULT_PACKER_BUDGET = float(os.environ.get("KARITY_PACKER_PERF_BUDGET", "5.0"))


def parse_args():
    parser = argparse.ArgumentParser(description="run packer regression tests")
    parser.add_argument("-c", "--config", default=str(ROOT_DIR / "config.json"))
    parser.add_argument("--lua")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--packer-budget", type=float, default=DEFAULT_PACKER_BUDGET)
    parser.add_argument("--keep", action="store_true")
    return parser.parse_args()


def default_lua_exe() -> str:
    local_lua = ROOT_DIR / "bin" / ("lua.exe" if os.name == "nt" else "lua")
    if local_lua.exists():
        return str(local_lua)
    return shutil.which("lua5.3") or shutil.which("lua53") or shutil.which("lua") or "lua"


def decode(data: bytes) -> str:
    return (data or b"").decode("utf-8", errors="replace")


def run_process(command: list[str], timeout: float):
    try:
        return subprocess.run(
            command,
            cwd=ROOT_DIR,
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise AssertionError(
            f"process timed out after {timeout:.1f}s:\n"
            f"{' '.join(map(str, command))}\n"
            f"stdout:\n{decode(exc.stdout or b'')}\n"
            f"stderr:\n{decode(exc.stderr or b'')}"
        ) from exc


def run_lua(lua_exe: str, path: Path, timeout: float):
    return run_process([lua_exe, str(path)], timeout)


def minimal_vm_options() -> list[str]:
    return [
        "dispatcher_type=ifelseif",
        "blob_form=string",
        "vm_count=1",
        "fake_handlers=false",
        "mutate_handlers=false",
        "junk_instructions=false",
        "junk_rate=0.0",
        "integrity_constants=false",
        "integrity_constant_rate=0.0",
    ]


def build(source: Path, output: Path, *, config: str, timeout: float, vm: bool, profile_report: Path | None = None):
    command = [
        sys.executable,
        str(ROOT_DIR / "main.py"),
        str(source),
        "-o",
        str(output),
        "--config",
        config,
        "--passes",
        "vm,pack" if vm else "pack",
        "--packer-output-passes",
        "minify",
    ]

    if vm:
        command.extend(["--vm-output-passes", "minify"])
        for option in minimal_vm_options():
            command.extend(["--vm-option", option])

    if profile_report is not None:
        command.extend(["--profile-report", str(profile_report)])

    result = run_process(command, timeout)

    if result.returncode != 0:
        raise AssertionError(
            "build failed\n"
            f"command: {' '.join(command)}\n"
            f"stdout:\n{decode(result.stdout)}\n"
            f"stderr:\n{decode(result.stderr)}"
        )

    if not output.exists():
        raise AssertionError(f"build succeeded but output does not exist: {output}")

    return result


def assert_same_runtime(lua_exe: str, source: Path, packed: Path, timeout: float):
    original = run_lua(lua_exe, source, timeout)
    obfuscated = run_lua(lua_exe, packed, timeout)

    lhs = (original.returncode, original.stdout, original.stderr)
    rhs = (obfuscated.returncode, obfuscated.stdout, obfuscated.stderr)

    if lhs != rhs:
        raise AssertionError(
            "runtime mismatch\n"
            f"source: rc={original.returncode} stdout={original.stdout!r} stderr={original.stderr!r}\n"
            f"packed: rc={obfuscated.returncode} stdout={obfuscated.stdout!r} stderr={obfuscated.stderr!r}"
        )


def assert_tamper_rejected(lua_exe: str, source: Path, tampered: Path, timeout: float):
    original = run_lua(lua_exe, source, timeout)
    changed = run_lua(lua_exe, tampered, timeout)

    if (original.returncode, original.stdout, original.stderr) == (
        changed.returncode,
        changed.stdout,
        changed.stderr,
    ):
        raise AssertionError("tampered packed script still behaved exactly like the source")


def mutate_loader_hash_constant(text: str) -> str:
    old = "0x811C9DC5"
    new = "0x811C9DC4"
    if old not in text:
        raise AssertionError(f"could not find expected loader hash constant {old}")
    return text.replace(old, new, 1)


def make_semantic_source(path: Path):
    source = (
        "local function calc(a,b)\n"
        "    local t={}\n"
        "    for i=1,20 do\n"
        "        t[i]=(a*i+b)%97\n"
        "    end\n"
        "    return table.concat(t,\",\")\n"
        "end\n"
        "local x=calc(17,29)\n"
        "print(\"PACKER_REGRESSION\")\n"
        "print(#x)\n"
        "print(x:sub(1,24))\n"
    )
    path.write_text(source, encoding="utf-8")


def make_large_vm_source(path: Path):
    lines = ["local s=0"]
    for i in range(1, 1801):
        lines.append(f"s=(s+(({i}*17)~({i}+91)))&0x7FFFFFFF")
    lines.extend(['print("PACKER_PERF")', "print(s)"])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def load_profile(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def get_pass_record(profile: dict, name: str) -> dict:
    for record in profile.get("passes", []):
        if record.get("name") == name:
            return record
    raise AssertionError(f"{name} record missing from profile report")


def test_pack_semantics(ctx: Path):
    source = ctx / "semantic.lua"
    output = ctx / "semantic_pack.lua"
    make_semantic_source(source)
    build(source, output, config=ARGS.config, timeout=ARGS.timeout, vm=False)
    assert_same_runtime(ARGS.lua_exe, source, output, ARGS.timeout)


def test_vm_pack_semantics(ctx: Path):
    source = ctx / "semantic_vm.lua"
    output = ctx / "semantic_vm_pack.lua"
    make_semantic_source(source)
    build(source, output, config=ARGS.config, timeout=ARGS.timeout, vm=True)
    assert_same_runtime(ARGS.lua_exe, source, output, ARGS.timeout)


def test_single_signature_header(ctx: Path):
    source = ctx / "header.lua"
    output = ctx / "header_pack.lua"
    config_path = ctx / "header_config.json"
    make_semantic_source(source)
    config = json.loads(Path(ARGS.config).read_text(encoding="utf-8"))
    config["signature"] = {
        "mode": "custom",
        "custom": "obfuscated using karity obfuscator!",
    }
    config_path.write_text(json.dumps(config), encoding="utf-8")
    build(source, output, config=config_path, timeout=ARGS.timeout, vm=True)

    text = output.read_text(encoding="utf-8")
    if not text.startswith(HEADER + "\n"):
        raise AssertionError("packed output does not start with the public header")
    count = text.count(HEADER)
    if count != 1:
        raise AssertionError(f"expected exactly one visible header, found {count}")


def test_randomized_builds(ctx: Path):
    source = ctx / "random.lua"
    first = ctx / "random_a.lua"
    second = ctx / "random_b.lua"
    make_semantic_source(source)

    build(source, first, config=ARGS.config, timeout=ARGS.timeout, vm=True)
    build(source, second, config=ARGS.config, timeout=ARGS.timeout, vm=True)

    if first.read_bytes() == second.read_bytes():
        raise AssertionError("two unseeded packed builds were byte-identical")

    assert_same_runtime(ARGS.lua_exe, source, first, ARGS.timeout)
    assert_same_runtime(ARGS.lua_exe, source, second, ARGS.timeout)


def test_loader_tamper_breaks_payload(ctx: Path):
    source = ctx / "tamper.lua"
    output = ctx / "tamper_pack.lua"
    tampered = ctx / "tamper_loader.lua"
    make_semantic_source(source)

    build(source, output, config=ARGS.config, timeout=ARGS.timeout, vm=True)
    tampered.write_text(
        mutate_loader_hash_constant(output.read_text(encoding="utf-8")),
        encoding="utf-8",
    )
    assert_tamper_rejected(ARGS.lua_exe, source, tampered, ARGS.timeout)


def test_load_replacement_breaks_payload(ctx: Path):
    source = ctx / "load_replace.lua"
    output = ctx / "load_replace_pack.lua"
    tampered = ctx / "load_replace_tampered.lua"
    make_semantic_source(source)

    build(source, output, config=ARGS.config, timeout=ARGS.timeout, vm=True)
    tampered.write_text("load=print;" + output.read_text(encoding="utf-8"), encoding="utf-8")
    assert_tamper_rejected(ARGS.lua_exe, source, tampered, ARGS.timeout)


def test_vm_packer_performance(ctx: Path):
    source = ctx / "large_vm.lua"
    output = ctx / "large_vm_pack.lua"
    report = ctx / "large_vm_profile.json"
    make_large_vm_source(source)

    build(
        source,
        output,
        config=ARGS.config,
        timeout=max(ARGS.timeout, ARGS.packer_budget * 4),
        vm=True,
        profile_report=report,
    )

    profile = load_profile(report)
    vm_record = get_pass_record(profile, "VMPass")
    packer_record = get_pass_record(profile, "PackerPass")

    vm_output = int(vm_record.get("output_bytes", 0))
    packer_elapsed = float(packer_record["elapsed"])

    if vm_output < 150_000:
        raise AssertionError(
            f"performance fixture generated only {vm_output} bytes of VM output"
        )

    if packer_elapsed > ARGS.packer_budget:
        raise AssertionError(
            f"packer performance regression: {packer_elapsed:.3f}s > "
            f"{ARGS.packer_budget:.3f}s for {vm_output} byte VM output"
        )

    assert_same_runtime(ARGS.lua_exe, source, output, ARGS.timeout)


TESTS = [
    ("pack semantics", test_pack_semantics),
    ("vm + pack semantics", test_vm_pack_semantics),
    ("single signature header", test_single_signature_header),
    ("randomized builds", test_randomized_builds),
    ("loader self-hash tamper", test_loader_tamper_breaks_payload),
    ("load replacement tamper", test_load_replacement_breaks_payload),
    ("vm packer performance", test_vm_packer_performance),
]


def run() -> int:
    global ARGS
    ARGS = parse_args()
    ARGS.lua_exe = ARGS.lua or default_lua_exe()

    print(f"lua: {ARGS.lua_exe}")
    print(f"config: {ARGS.config}")
    print(f"packer perf budget: {ARGS.packer_budget:.3f}s")

    if ARGS.keep:
        ctx = BASE_DIR / "output" / "packer_regression"
        ctx.mkdir(parents=True, exist_ok=True)
        temp_ctx = None
    else:
        temp_ctx = tempfile.TemporaryDirectory(prefix="karity-packer-test-")
        ctx = Path(temp_ctx.name)

    passed = 0
    try:
        print("\n--- Packer Regression Tests ---")
        for name, fn in TESTS:
            started = time.perf_counter()
            try:
                fn(ctx)
            except Exception as exc:
                elapsed = time.perf_counter() - started
                print(f"{RED}{name}: failed{RESET} ({elapsed:.3f}s)")
                print(f"  {exc}")
            else:
                elapsed = time.perf_counter() - started
                print(f"{GREEN}{name}: ok{RESET} ({elapsed:.3f}s)")
                passed += 1
    finally:
        if temp_ctx is not None:
            temp_ctx.cleanup()

    total = len(TESTS)
    print(f"\ntotal result: {passed}/{total} passed")

    if passed == total:
        print(f"{GREEN}packer regression success!{RESET}")
        return 0

    print(f"{RED}packer regression failed!{RESET}")
    return 1


if __name__ == "__main__":
    raise SystemExit(run())
