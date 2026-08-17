from pathlib import Path
import os
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor

BASE_DIR = Path(__file__).parent

GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"
LUA_TIMEOUT = float(os.environ.get("KARITY_TEST_LUA_TIMEOUT", "120"))
BUILD_TIMEOUT = float(os.environ.get("KARITY_TEST_BUILD_TIMEOUT", "600"))

def run_lua(path):
    try:
        result = subprocess.run(
            ["lua", str(path)],
            capture_output=True,
            timeout=LUA_TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        return "TIMEOUT", exc.stdout or b"", exc.stderr or b""
    return result.returncode, result.stdout, result.stderr

def worker(script):
    print(f"test: {script.name}")
    
    rc1, out1, err1 = run_lua(script)
    if rc1 == "TIMEOUT":
        return False, script.name, (rc1, out1, err1), (
            "source timed out", LUA_TIMEOUT, b""
        )

    output_dir = BASE_DIR / "output"
    obf_path = output_dir / f"{script.stem}_obfuscated.lua"

    if obf_path.exists():
        obf_path.unlink()

    try:
        build = subprocess.run(
            ["python", str(BASE_DIR.parent / "main.py"), str(script), "-o", str(obf_path)],
            capture_output=True,
            timeout=BUILD_TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        detail = (exc.stderr or exc.stdout or b"")[-1000:]
        return False, script.name, (rc1, out1, err1), (
            "build timed out", BUILD_TIMEOUT, detail
        )

    if build.returncode != 0 or not obf_path.exists():
        detail = (build.stderr or build.stdout or b"")[-1000:]
        return False, script.name, (rc1, out1, err1), (
            "build failed", build.returncode, detail
        )

    rc2, out2, err2 = run_lua(obf_path)

    if (rc1, out1, err1) != (rc2, out2, err2):
        return False, script.name, (rc1, out1, err1), (rc2, out2, err2)
    return True, script.name, None, None

def run_test():
    scripts_dir = BASE_DIR / "scripts"
    output_dir = BASE_DIR / "output"
    output_dir.mkdir(exist_ok=True)

    filters = sys.argv[1:]

    target_scripts = []
    for script in sorted(scripts_dir.glob("*.lua")):
        if filters and not any(f in script.name for f in filters):
            continue
        target_scripts.append(script)

    if not target_scripts:
        print(f"{RED}No tests matched the given filters: {filters}{RESET}")
        return

    total = len(target_scripts)
    passed = 0

    with ProcessPoolExecutor() as executor:
        results = executor.map(worker, target_scripts)

    print("\n--- Test Results ---")
    for success, name, orig, obf in results:
        if success:
            print(f"{name}: ok")
            passed += 1
        else:
            print(f"{name}: mismatch")
            print("  original     :", orig)
            print("  obfuscated   :", obf)

    print(f"\ntotal result: {passed}/{total} passed.")

    if passed == total:
        print(f"{GREEN}test success!{RESET}")
    else:
        print(f"{RED}test failed!{RESET}")

if __name__ == "__main__":
    run_test()
