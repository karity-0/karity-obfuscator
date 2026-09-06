"""The shared local/CI verification manifest. Run from any working directory."""
from pathlib import Path
import argparse
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
REGRESSIONS = (
    "backend_options", "number_obf", "packer", "runtime_poly", "runtime_trace",
    "vm_backend", "mov_backend", "state_coupling", "vm_mutation",
    "vm_output_emitter", "vm_choke", "gui", "signature", "line_state",
    "function_boundary", "function_loop", "function_nested",
)
COMMANDS = [("tools/generate_config_docs.py", "--check")]
COMMANDS += [(f"test/run_{name}_regression.py",) for name in REGRESSIONS]
COMMANDS += [("test/run_test.py", "--config", "config.example.json", "--profile", "dev", "--jobs", "2")]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="print commands without running them")
    args = parser.parse_args()
    expected = {f"run_{name}_regression.py" for name in REGRESSIONS}
    discovered = {path.name for path in (ROOT / "test").glob("run_*_regression.py")}
    if expected != discovered:
        raise RuntimeError(f"CI regression manifest is out of sync: {sorted(expected ^ discovered)}")
    for command in COMMANDS:
        print("python " + " ".join(command), flush=True)
        if not args.list:
            result = subprocess.run([sys.executable, *command], cwd=ROOT)
            if result.returncode:
                return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
