from pathlib import Path
import subprocess

BASE_DIR = Path(__file__).parent

def run_lua(path):
    result = subprocess.run(
        ["lua", str(path)],
        capture_output=True,
        text=True
    )
    return result.returncode, result.stdout, result.stderr


def run_test():
    scripts_dir = BASE_DIR / "scripts"
    output_dir = BASE_DIR / "output"
    output_dir.mkdir(exist_ok=True)

    for script in scripts_dir.glob("*.lua"):
        print(f"test: {script.name}")

        rc1, out1, err1 = run_lua(script)

        obf_path = output_dir / f"{script.stem}_obfuscated.lua"
        subprocess.run(
            ["python", BASE_DIR.parent / "main.py", str(script), "-o", str(obf_path)]
        )

        rc2, out2, err2 = run_lua(obf_path)

        if (rc1, out1, err1) != (rc2, out2, err2):
            print("test: mismatch")
            print("original     :", rc1, out1, err1)
            print("obfuscated   :", rc2, out2, err2)
        else:
            print("test: ok")

if __name__ == "__main__":
    run_test()