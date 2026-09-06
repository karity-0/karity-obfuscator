from __future__ import annotations

import json
import random
import subprocess
import sys
from pathlib import Path
from lua_runtime import lua_executable


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

from obfuscator.passes.number_obfuscation import NumberObfuscationPass
from obfuscator.passes.string_obfuscation import StringObfuscationPass
from obfuscator.passes.packer import _obfuscate_packer_output
from obfuscator.pipeline import Pipeline



def main() -> int:
    values = [
        -1, 0, 1, 2, 5, 7, 8, 13, 16, 17, 24, 31, 32, 63, 64,
        127, 128, 255, 256, 4095, 4096, 65535, 0x7FFFFFFF,
        0xFFFFFFFF,
    ]
    values.extend(10_000 + ((i * 2_654_435_761) % 9_990_000) for i in range(128))
    generator = NumberObfuscationPass()
    lines: list[str] = []
    case = 0

    def run_number_batch(batch: list[str], first_case: int) -> int:
        result = subprocess.run(
            [lua_executable(), "-"],
            cwd=ROOT_DIR,
            input=("\n".join(batch) + "\n").encode(),
            capture_output=True,
            timeout=60,
        )
        if result.returncode != 0:
            stderr = result.stderr.decode(errors="replace")
            sys.stderr.write(
                f"number regression cases {first_case}-{first_case + len(batch) - 1} "
                f"failed: rc={result.returncode} stderr={stderr[:1000]!r}\n"
            )
        return result.returncode

    for seed in range(128):
        random.seed(seed)
        for value in values:
            case += 1
            expr = generator._fmt_int_expr(value, random.randint(1, 3))
            lines.append(
                f"if ({expr})~={value} then "
                f"error('case {case} seed {seed} expected {value}') end"
            )
            # Keeping each Lua chunk modest avoids parser/allocator failures in
            # the bundled Windows Lua while exercising the same expressions.
            if len(lines) == 512:
                returncode = run_number_batch(lines, case - len(lines) + 1)
                if returncode != 0:
                    return returncode or 1
                lines.clear()
    if lines:
        returncode = run_number_batch(lines, case - len(lines) + 1)
        if returncode != 0:
            return returncode or 1
    print(f"number-obf-ok {case}")

    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-/.: "
    text = "".join(alphabet[(i * 37 + i // 3) % len(alphabet)] for i in range(768))
    source = f"io.write({json.dumps(text)})"
    for seed in range(128):
        random.seed(seed)
        pipeline = Pipeline(show_header=False)
        pipeline.add(StringObfuscationPass())
        pipeline.add(NumberObfuscationPass())
        transformed = pipeline.run(source)
        runtime = subprocess.run(
            [lua_executable(), "-"],
            cwd=ROOT_DIR,
            input=transformed.encode(),
            capture_output=True,
            timeout=10,
        )
        if runtime.returncode != 0 or runtime.stdout != text.encode():
            sys.stderr.write(
                f"string+number regression at seed {seed}: rc={runtime.returncode} "
                f"stdout={runtime.stdout[:80]!r} stderr={runtime.stderr[:200]!r}\n"
            )
            return runtime.returncode or 1
    print("string-number-ok 128")

    packer_passes = [
        "boolean_obf", "table_obf", "string_obf", "number_obf",
        "rename_obf", "localize_globals", "minify",
    ]
    loader_source = f"return function() local marker=0;io.write({json.dumps(text)});return marker end"
    for seed in range(16):
        random.seed(seed)
        transformed = _obfuscate_packer_output(loader_source, packer_passes)
        runtime = subprocess.run(
            [lua_executable(), "-"],
            cwd=ROOT_DIR,
            input=(f"local f=(function()\n{transformed}\nend)();f()\n").encode(),
            capture_output=True,
            timeout=10,
        )
        if runtime.returncode != 0 or runtime.stdout != text.encode():
            sys.stderr.write(
                f"packer-output regression at seed {seed}: rc={runtime.returncode} "
                f"stdout={runtime.stdout[:80]!r} stderr={runtime.stderr[:200]!r} "
                f"source={transformed[:500]!r}\n"
            )
            return runtime.returncode or 1
    print("packer-output-ok 16")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
