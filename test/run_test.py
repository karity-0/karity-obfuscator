from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path


BASE_DIR = Path(__file__).parent
ROOT_DIR = BASE_DIR.parent

GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"
DEFAULT_LUA_TIMEOUT = float(os.environ.get("KARITY_TEST_LUA_TIMEOUT", "120"))
DEFAULT_BUILD_TIMEOUT = float(os.environ.get("KARITY_TEST_BUILD_TIMEOUT", "600"))


def parse_args():
    parser = argparse.ArgumentParser(description="run Lua obfuscator semantic tests")
    parser.add_argument("filters", nargs="*", help="only run scripts whose filename contains one of these values")
    parser.add_argument("-c", "--config", default=str(ROOT_DIR / "config.json"), help="config json path")
    parser.add_argument("--profile", help="config profile to pass to main.py")
    parser.add_argument("--seed", type=int, help="base random seed; each test gets seed + test index")
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 1, help="parallel worker count")
    parser.add_argument("--lua", help="lua executable path")
    parser.add_argument("--lua-timeout", type=float, default=DEFAULT_LUA_TIMEOUT, help="per-script lua timeout")
    parser.add_argument("--build-timeout", type=float, default=DEFAULT_BUILD_TIMEOUT, help="per-script build timeout")
    parser.add_argument("--keep-output", action="store_true", help="keep obfuscated outputs for passing tests")
    return parser.parse_args()


def default_lua_exe() -> str:
    local_lua = ROOT_DIR / "bin" / ("lua.exe" if os.name == "nt" else "lua")
    if local_lua.exists():
        return str(local_lua)
    return shutil.which("lua5.3") or shutil.which("lua53") or shutil.which("lua") or "lua"


def run_lua(lua_exe: str, path: Path, timeout: float):
    try:
        result = subprocess.run(
            [lua_exe, str(path)],
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        return "TIMEOUT", exc.stdout or b"", exc.stderr or b""
    return result.returncode, result.stdout, result.stderr


def decode_tail(data: bytes, limit: int = 1200) -> str:
    return (data or b"")[-limit:].decode("utf-8", errors="replace")


def build_command(script: Path, obf_path: Path, args, index: int) -> list[str]:
    command = [
        sys.executable,
        str(ROOT_DIR / "main.py"),
        str(script),
        "-o",
        str(obf_path),
        "--config",
        args.config,
    ]
    if args.profile:
        command.extend(["--profile", args.profile])
    if args.seed is not None:
        command.extend(["--seed", str(args.seed + index)])
    return command


def worker(payload):
    index, script, args_dict = payload
    args = argparse.Namespace(**args_dict)

    rc1, out1, err1 = run_lua(args.lua_exe, script, args.lua_timeout)
    if rc1 == "TIMEOUT":
        return False, script.name, None, "source timed out", f"timeout={args.lua_timeout}s"

    output_dir = BASE_DIR / "output"
    output_dir.mkdir(exist_ok=True)
    obf_path = output_dir / f"{script.stem}_obfuscated.lua"

    if obf_path.exists():
        obf_path.unlink()

    try:
        build = subprocess.run(
            build_command(script, obf_path, args, index),
            capture_output=True,
            timeout=args.build_timeout,
        )
    except subprocess.TimeoutExpired as exc:
        detail = decode_tail(exc.stderr or exc.stdout or b"")
        return False, script.name, obf_path, "build timed out", detail

    if build.returncode != 0 or not obf_path.exists():
        detail = decode_tail(build.stderr or build.stdout or b"")
        return False, script.name, obf_path, f"build failed rc={build.returncode}", detail

    rc2, out2, err2 = run_lua(args.lua_exe, obf_path, args.lua_timeout)
    if (rc1, out1, err1) != (rc2, out2, err2):
        detail = (
            f"original: rc={rc1} stdout={out1!r} stderr={err1!r}\n"
            f"obfuscated: rc={rc2} stdout={out2!r} stderr={err2!r}"
        )
        return False, script.name, obf_path, "output mismatch", detail

    if not args.keep_output:
        obf_path.unlink(missing_ok=True)
    return True, script.name, obf_path if args.keep_output else None, None, None


def select_scripts(filters: list[str]) -> list[Path]:
    scripts_dir = BASE_DIR / "scripts"
    scripts = []
    for script in sorted(scripts_dir.glob("*.lua")):
        if filters and not any(f in script.name for f in filters):
            continue
        scripts.append(script)
    return scripts


def run_test() -> int:
    args = parse_args()
    args.lua_exe = args.lua or default_lua_exe()
    args.jobs = max(1, args.jobs)

    target_scripts = select_scripts(args.filters)
    if not target_scripts:
        print(f"{RED}No tests matched the given filters: {args.filters}{RESET}")
        return 1

    print(f"lua: {args.lua_exe}")
    print(f"profile: {args.profile or '(config default)'}")
    print(f"jobs: {args.jobs}")

    args_dict = vars(args)
    payloads = [(index, script, args_dict) for index, script in enumerate(target_scripts)]

    total = len(target_scripts)
    passed = 0

    with ProcessPoolExecutor(max_workers=args.jobs) as executor:
        results = list(executor.map(worker, payloads))

    print("\n--- Test Results ---")
    for success, name, output_path, reason, detail in results:
        if success:
            suffix = f" ({output_path})" if output_path else ""
            print(f"{name}: ok{suffix}")
            passed += 1
        else:
            print(f"{name}: failed - {reason}")
            if output_path:
                print(f"  output: {output_path}")
            if detail:
                print(f"  detail: {detail}")

    print(f"\ntotal result: {passed}/{total} passed.")

    if passed == total:
        print(f"{GREEN}test success!{RESET}")
        return 0

    print(f"{RED}test failed!{RESET}")
    return 1


if __name__ == "__main__":
    raise SystemExit(run_test())
