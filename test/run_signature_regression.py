from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

from obfuscator import Pipeline, build_pipeline_from_config
from obfuscator.passes import output_signature
from obfuscator.passes.output_signature import OutputSignaturePass, strip_comment_tokens
from obfuscator.registry import ConfigError, validate_config


LUA = ROOT_DIR / "bin" / ("lua.exe" if os.name == "nt" else "lua")
if not LUA.exists():
    LUA = Path(shutil.which("lua5.3") or shutil.which("lua53") or shutil.which("lua") or "lua")


def config(passes: list[str], signature: dict) -> dict:
    return {
        "passes": passes,
        "vm_output_passes": [],
        "packer_output_passes": [],
        "vm_options": {
            "dispatcher_type": "ifelseif",
            "blob_form": "string",
            "vm_count": 1,
            "fake_handlers": False,
            "mutate_handlers": False,
            "junk_instructions": False,
            "junk_rate": 0.0,
        },
        "signature": signature,
    }


def execute(source: str) -> tuple[int, bytes, bytes]:
    with tempfile.TemporaryDirectory(prefix="karity-signature-") as temp:
        path = Path(temp) / "output.lua"
        path.write_text(source, encoding="utf-8")
        result = subprocess.run([str(LUA), str(path)], capture_output=True, timeout=120)
    return result.returncode, result.stdout.replace(b"\r\n", b"\n"), result.stderr


def assert_runtime(passes: list[str], signature: dict) -> str:
    pipeline = build_pipeline_from_config(config(passes, signature), Pipeline)
    output = pipeline.run("local x=20+22; print(x)")
    result = execute(output)
    if result != (0, b"42\n", b""):
        raise AssertionError(f"runtime mismatch for {passes}: {result!r}")
    return output


def main() -> int:
    with (
        patch.object(output_signature.random, "random", return_value=0.49),
        patch.object(output_signature, "_generated_compound_name", return_value="Compound"),
        patch.object(output_signature, "_generated_syllable_name", return_value="Syllable"),
    ):
        if output_signature._generated_name() != "Compound":
            raise AssertionError("compound name generator did not receive its 50% branch")

    with (
        patch.object(output_signature.random, "random", return_value=0.5),
        patch.object(output_signature, "_generated_compound_name", return_value="Compound"),
        patch.object(output_signature, "_generated_syllable_name", return_value="Syllable"),
    ):
        if output_signature._generated_name() != "Syllable":
            raise AssertionError("syllable name generator did not receive its 50% branch")

    if strip_comment_tokens("-- alpha --[[beta]] --[=[gamma]=]") != "alpha beta gamma":
        raise AssertionError("comment token stripping failed")

    if OutputSignaturePass({"mode": "none"}).run("print(1)") != "print(1)":
        raise AssertionError("none mode changed output")

    custom = {"mode": "custom", "custom": "-- first\n--[[second]]\n--[=[third]=]"}
    custom_output = assert_runtime([], custom)
    if not custom_output.startswith("-- first\n-- second\n-- third\n"):
        raise AssertionError(f"custom signature was not sanitized: {custom_output[:80]!r}")

    generated = {
        "mode": "generated",
        "fake": {
            "sources": ["generated"],
            "generator_patterns": [],
            "custom_pattern": "--[[{name}\nV{version}]]",
        },
    }
    generated_output = assert_runtime([], generated)
    if not generated_output.startswith("--") or generated_output.count("\n") < 2:
        raise AssertionError("generated multiline signature was not emitted")

    for passes in (["vm"], ["pack"], ["vm", "pack"]):
        output = assert_runtime(passes, custom)
        if "karity obfuscator!" in output:
            raise AssertionError(f"legacy public signature leaked for {passes}")

    try:
        validate_config(config([], {"mode": "fake", "fake": {"sources": []}}))
    except ConfigError:
        pass
    else:
        raise AssertionError("empty fake source pool was accepted")

    print("signature-regression-ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
