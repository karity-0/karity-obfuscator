"""Verify type inference and rejection of invalid options using the CI checker."""
from pathlib import Path
import ast
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    for platform in ("linux", "win32"):
        subprocess.run([sys.executable, "-m", "mypy", "--config-file", "mypy.ini",
                        "--platform", platform], cwd=ROOT, check=True)
    negative = subprocess.run(
        [sys.executable, "-m", "mypy", "--config-file", "mypy.ini",
         "test/typing/invalid_contracts.py"], cwd=ROOT,
        capture_output=True, text=True,
    )
    if negative.returncode != 1:
        raise AssertionError(f"invalid contracts were not type checked: {negative.stdout}{negative.stderr}")
    for code in ("typeddict-unknown-key", "typeddict-item", "assignment", "type-var"):
        if f"[{code}]" not in negative.stdout:
            raise AssertionError(f"missing {code} diagnostic: {negative.stdout}")

    sys.path.insert(0, str(ROOT))
    from obfuscator.config_types import VMOptions
    from obfuscator.passes import RemoveCommentPass
    from obfuscator.pipeline import Pipeline
    from obfuscator.registry import VM_OPTION_DOCS, build_pipeline_from_config

    if set(VMOptions.__annotations__) != set(VM_OPTION_DOCS):
        raise AssertionError("VM option schema is out of sync with configuration metadata")

    class CustomPipeline(Pipeline):
        pass

    pipeline = build_pipeline_from_config({"passes": ["remove_comment"]}, CustomPipeline,
                                          show_header=False)
    assert type(pipeline) is CustomPipeline
    assert pipeline.add(RemoveCommentPass()) is pipeline
    assert pipeline.run('-- comment\nprint(42)').strip() == 'print(42)'

    for path in (ROOT / "obfuscator").rglob("*.py"):
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path), feature_version=(3, 12))
    print("typing-regression-ok generic inference, invalid configurations, Python 3.12 syntax")


if __name__ == "__main__":
    main()
