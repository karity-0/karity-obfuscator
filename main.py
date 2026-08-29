import argparse
import copy
import json
import random
import sys
import time
from pathlib import Path

from obfuscator import Pipeline, build_pipeline_from_config, __version__
from obfuscator.profiling import Profiler
from obfuscator.registry import (
    ConfigError,
    ReleaseCheckError,
    get_pass_names,
    get_profile_names,
    resolve_config_profile,
    validate_config,
    validate_release_config,
)


def load_config(path: str = "config.json") -> dict:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"error: config file '{path}' not found.", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"error: invalid json in '{path}': {e}", file=sys.stderr)
        sys.exit(1)


def build_pipeline(config: dict) -> Pipeline:
    return build_pipeline_from_config(config, Pipeline)


def parse_args():
    parser = argparse.ArgumentParser(description="lua obfuscator")
    parser.add_argument("input", nargs="?", help="input lua script")
    parser.add_argument("-o", "--output", help="output lua script")
    parser.add_argument("-c", "--config", default="config.json", help="config json path")
    parser.add_argument(
        "--profile",
        help="config profile name; 'max' is experimental and has no build-time or output-size target",
    )
    parser.add_argument("--passes", help="override top-level passes with a comma-separated list")
    parser.add_argument("--vm-output-passes", help="override vm_output_passes with a comma-separated list")
    parser.add_argument("--packer-output-passes", help="override packer_output_passes with a comma-separated list")
    parser.add_argument(
        "--vm-option",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="override one vm_options value; can be repeated",
    )
    parser.add_argument("--print-config", action="store_true", help="print resolved config and exit")
    parser.add_argument("--release-check", action="store_true", help="fail unless the resolved config is suitable for release")
    parser.add_argument("--profile-report", help="write pass timing and size profile JSON to this path, or '-' for stdout")
    parser.add_argument("--list-passes", action="store_true", help="print known pass names")
    parser.add_argument("--list-profiles", action="store_true", help="print profiles in the config")
    parser.add_argument("--seed", type=int, help="seed python's random module for reproducible builds")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="print debug info")
    parser.add_argument("--version", action="version", version=f"Karity Obfuscator {__version__}",)
    return parser.parse_args()


def parse_pass_list(value: str) -> list[str]:
    return [name.strip() for name in value.split(",") if name.strip()]


def parse_option_value(value: str):
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def apply_cli_overrides(config: dict, args) -> dict:
    config = copy.deepcopy(config)

    overrides = (
        ("passes", args.passes),
        ("vm_output_passes", args.vm_output_passes),
        ("packer_output_passes", args.packer_output_passes),
    )
    for key, value in overrides:
        if value is not None:
            config[key] = parse_pass_list(value)

    if args.vm_option:
        vm_options = dict(config.get("vm_options", {}))
        for item in args.vm_option:
            if "=" not in item:
                raise ConfigError(f"--vm-option must be KEY=VALUE, got '{item}'")
            key, value = item.split("=", 1)
            key = key.strip()
            if not key:
                raise ConfigError("--vm-option key cannot be empty")
            vm_options[key] = parse_option_value(value.strip())
        config["vm_options"] = vm_options

    return config


def print_passes() -> None:
    for group in ("pre", "base", "post"):
        names = ", ".join(get_pass_names(group))
        print(f"{group}: {names}")


def print_profiles(config: dict) -> None:
    names = get_profile_names(config)
    if not names:
        print("no profiles found in this config")
        return

    selected = config.get("profile")
    for name in names:
        marker = " *" if name == selected else ""
        if name == "high":
            note = " (recommended for strong practical builds)"
        elif name == "max":
            note = " (experimental; research/extreme builds)"
        else:
            note = ""
        print(f"{name}{marker}{note}")


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

    args = parse_args()
    if args.list_passes:
        print_passes()
        return

    config_root = load_config(args.config)
    if args.list_profiles:
        print_profiles(config_root)
        return

    if args.seed is not None:
        random.seed(args.seed)

    try:
        config = resolve_config_profile(config_root, args.profile)
        config = apply_cli_overrides(config, args)
        validate_config(config)
        if args.release_check:
            if args.seed is not None:
                raise ReleaseCheckError("release-check failed:\n- --seed is for reproducible test builds and cannot be used for release")
            validate_release_config(config)
    except ConfigError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
    except ReleaseCheckError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.print_config:
        print(json.dumps(config, indent=4, ensure_ascii=False))
        return

    if not args.input:
        print("error: input lua script is required.", file=sys.stderr)
        sys.exit(2)

    script = read_script(args.input)
    output_path = resolve_output_path(args.input, args.output)

    profile = config.get("_profile")
    print(f"obfuscating.. profile={profile}" if profile else "obfuscating..")

    start_time = time.perf_counter()

    profiler = Profiler() if args.profile_report else None
    pipeline = build_pipeline(config)
    output_script = pipeline.run(script, args.verbose, profiler=profiler)

    elapsed = time.perf_counter() - start_time

    print(f"saving {output_path}")
    write_script(output_path, output_script)
    if profiler:
        report = {
            "profile": profile,
            "seeded": args.seed is not None,
            **profiler.as_dict(),
        }
        report_text = json.dumps(report, indent=4, ensure_ascii=False)
        if args.profile_report == "-":
            print(report_text)
        else:
            Path(args.profile_report).write_text(report_text + "\n", encoding="utf-8")
            print(f"profile report saved to {args.profile_report}")
    print(f"obfuscation completed in {elapsed:.3f}s")


if __name__ == "__main__":
    main()
