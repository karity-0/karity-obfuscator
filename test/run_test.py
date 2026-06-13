from pathlib import Path
import subprocess
import sys

BASE_DIR = Path(__file__).parent

GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"

def run_lua(path):
    result = subprocess.run(
        ["lua", str(path)],
        capture_output=True
    )
    return result.returncode, result.stdout, result.stderr


def run_test():
    scripts_dir = BASE_DIR / "scripts"
    output_dir = BASE_DIR / "output"
    output_dir.mkdir(exist_ok=True)

    filters = sys.argv[1:]

    total = 0
    passed = 0

    for script in sorted(scripts_dir.glob("*.lua")):
        if filters and not any(f in script.name for f in filters):
            continue

        print(f"test: {script.name}")
        total += 1

        rc1, out1, err1 = run_lua(script)

        obf_path = output_dir / f"{script.stem}_obfuscated.lua"
        subprocess.run(
            ["python", str(BASE_DIR.parent / "main.py"), str(script), "-o", str(obf_path)]
        )

        rc2, out2, err2 = run_lua(obf_path)

        if (rc1, out1, err1) != (rc2, out2, err2):
            print("test: mismatch")
            print("original     :", rc1, out1, err1)
            print("obfuscated   :", rc2, out2, err2)
        else:
            print("test: ok")
            passed += 1

    if total == 0:
        print(f"{RED}No tests matched the given filters: {filters}{RESET}")
        return

    print(f"\ntotal result: {passed}/{total} passed.")

    if passed == total:
        print(f"{GREEN}test success!{RESET}")
    else:
        print(f"{RED}test failed!{RESET}")

if __name__ == "__main__":
    run_test()