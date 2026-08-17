from __future__ import annotations

import time
from typing import Union

from luaparser import ast

from .passes.base import BasePass, PostPass, PrePass, Replacement
from .profiling import ProfileRecord, Profiler
from .verbosity import Verbosity


PassType = Union[BasePass, PrePass, PostPass]


def info_message(step: str, p: PassType, message: str):
    print(f"[{step}] {p.__class__.__name__}: {message}")


def _size(src: str) -> int:
    return len(src.encode("utf-8"))


def _format_record(record: ProfileRecord) -> str:
    message = (
        f"{record.elapsed:.3f}s "
        f"{record.input_bytes}->{record.output_bytes} bytes "
        f"(delta {record.output_bytes - record.input_bytes:+})"
    )
    if record.parser:
        message += f" parser={record.parser}"
    if record.replacements is not None:
        message += f" replacements={record.replacements}"
    return message


class Pipeline:
    HEADER = "-- obfuscated using karity obfuscator!\n"

    def __init__(self, show_header: bool = True):
        self._pre_passes: list[PrePass] = []
        self._passes: list[BasePass] = []
        self._post_passes: list[PostPass] = []
        self.show_header = show_header

    def add(self, pass_: BasePass | PrePass) -> Pipeline:
        if isinstance(pass_, PrePass):
            self._pre_passes.append(pass_)
        elif isinstance(pass_, PostPass):
            self._post_passes.append(pass_)
        else:
            self._passes.append(pass_)
        return self

    def run(self, script: str, verbose: int = 0, profiler: Profiler | None = None) -> str:
        for pre in self._pre_passes:
            before = _size(script)
            start = time.perf_counter()
            script = pre.run(script)
            elapsed = time.perf_counter() - start
            record = ProfileRecord("PRE", pre.__class__.__name__, elapsed, before, _size(script))
            if profiler:
                profiler.add(record)
            if verbose >= Verbosity.NORMAL:
                info_message("PRE", pre, _format_record(record))

        for pass_ in self._passes:
            before = _size(script)
            start = time.perf_counter()
            parser = getattr(pass_, "parser", "luaparser")
            if parser == "treesitter":
                from .passes.ts_utils import parse as _ts_parse

                tree = _ts_parse(script)
            else:
                tree = ast.parse(script)
            replacements = pass_.run(script, tree)
            script = self._apply(script, replacements)
            elapsed = time.perf_counter() - start
            record = ProfileRecord(
                "BASE",
                pass_.__class__.__name__,
                elapsed,
                before,
                _size(script),
                parser=parser,
                replacements=len(replacements),
            )
            if profiler:
                profiler.add(record)
            if verbose >= Verbosity.NORMAL:
                info_message("BASE", pass_, _format_record(record))
            if verbose > Verbosity.DEBUG:
                new_tree = ast.parse(script)
                print(ast.to_pretty_str(new_tree))

        for post in self._post_passes:
            before = _size(script)
            start = time.perf_counter()
            script = post.run(script)
            elapsed = time.perf_counter() - start
            details = getattr(post, "last_profile", [])
            record = ProfileRecord(
                "POST",
                post.__class__.__name__,
                elapsed,
                before,
                _size(script),
                details=details,
            )
            if profiler:
                profiler.add(record)
            if verbose >= Verbosity.NORMAL:
                info_message("POST", post, _format_record(record))
                if verbose >= Verbosity.DEBUG:
                    for detail in details:
                        print(f"  - {detail['phase']}: {detail['elapsed']:.3f}s")

        return f"{self.HEADER}{script}" if self.show_header else script

    def _apply(self, src: str, replacements: list[Replacement]) -> str:
        if not replacements:
            return src
        parts: list[str] = []
        pos = 0
        for r in sorted(replacements, key=lambda r: r.start):
            parts.append(src[pos:r.start])
            parts.append(r.new_text)
            pos = r.end + 1
        parts.append(src[pos:])
        return "".join(parts)
