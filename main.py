import sys
import argparse
from pathlib import Path

from obfuscator import Pipeline, StringEncodePass


def build_pipeline() -> Pipeline:
    return (
        Pipeline()
        .add(StringEncodePass())
    )


def parse_args():
    parser = argparse.ArgumentParser(description="lua obfuscator")
    parser.add_argument("input",              help="input lua script")
    parser.add_argument("-o", "--output",     help="output lua script")
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
    args        = parse_args()
    script      = read_script(args.input)
    output_path = resolve_output_path(args.input, args.output)

    print("obfuscating..")
    pipeline        = build_pipeline()
    output_script   = pipeline.run(script)

    print(f"saving → {output_path}")
    write_script(output_path, output_script)


if __name__ == "__main__":
    main()