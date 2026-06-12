import sys
import time
import json
import argparse
from pathlib import Path

from obfuscator\
    import (
        Pipeline, build_pipeline_from_config
    )


def load_config(path: str = "config.json") -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def build_pipeline(config: dict) -> Pipeline:
    return build_pipeline_from_config(config, Pipeline, show_header=False)


def parse_args():
    parser = argparse.ArgumentParser(description="lua obfuscator")
    parser.add_argument("input",              help="input lua script")
    parser.add_argument("-o", "--output",     help="output lua script")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="print debug info")
    return parser.parse_args()


def read_script(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        print(f"error: input script '{path}' not found.", file=sys.stderr)
        sys.exit(1)


def resolve_output_path(input_path: str, output_arg: str | None) -> Path:
    if output_arg:
        return Path(output_arg)
    p = Path(input_path)
    return p.with_name(f"{p.stem}_obfuscated{p.suffix}")


def write_script(path: Path, script: str) -> None:
    try:
        path.write_text(script, encoding="utf-8")
    except Exception as e:
        print(f"error: cannot write '{path}': {e}", file=sys.stderr)
        sys.exit(1)


def main():
    sys.setrecursionlimit(5000)
    
    args        = parse_args()
    script      = read_script(args.input)
    output_path = resolve_output_path(args.input, args.output)

    print("obfuscating..")

    start_time      = time.perf_counter()

    config          = load_config()
    pipeline        = build_pipeline(config)
    output_script   = pipeline.run(script, args.verbose)

    elapsed         = time.perf_counter() - start_time

    print(f"saving → {output_path}")
    write_script(output_path, output_script)
    print(f"obfuscation completed in {elapsed:.3f}s")


if __name__ == "__main__":
    main()