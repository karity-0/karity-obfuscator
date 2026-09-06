from __future__ import annotations

import time
from typing import Union

from luaparser import ast

from .passes.base import BasePass, PostPass, PrePass, Replacement
from .passes.output_signature import DEFAULT_SIGNATURE, OutputSignaturePass
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
    HEADER = DEFAULT_SIGNATURE

    def __init__(self, show_header: bool = True):
        self.rename_options = None
        self._pre_passes: list[PrePass] = []
        self._passes: list[BasePass] = []
        self._post_passes: list[PostPass] = []
        self.show_header = show_header
        self._output_signature: OutputSignaturePass | None = (
            OutputSignaturePass() if show_header else None
        )

    def add(self, pass_: BasePass | PrePass | PostPass) -> Pipeline:
        if isinstance(pass_, OutputSignaturePass):
            self._output_signature = pass_
        elif isinstance(pass_, PrePass):
            self._pre_passes.append(pass_)
        elif isinstance(pass_, PostPass):
            self._post_passes.append(pass_)
        else:
            self._passes.append(pass_)
        return self

    def run(self, script: str, verbose: int = 0, profiler: Profiler | None = None) -> str:
        from .names import RENAME_OPTIONS
        token = RENAME_OPTIONS.set(self.rename_options) if self.rename_options is not None else None
        try:
            return self._run(script, verbose, profiler)
        finally:
            if token is not None:
                RENAME_OPTIONS.reset(token)

    def _run(self, script: str, verbose: int = 0, profiler: Profiler | None = None) -> str:
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

        # Renaming is an emission step: collect every generated base-pass helper
        # before choosing final names. Localization resolves lexical bindings on
        # its own, so it does not need an earlier rename to distinguish globals.
        from .passes.rename_obfuscation import RenameObfuscationPass
        renamers = [p for p in self._passes if isinstance(p, RenameObfuscationPass)]
        base_passes = [p for p in self._passes if not isinstance(p, RenameObfuscationPass)]
        if renamers:
            base_passes.append(renamers[-1])
        for pass_ in base_passes:
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

        if self._output_signature is None:
            return script

        before = _size(script)
        start = time.perf_counter()
        script = self._output_signature.run(script)
        record = ProfileRecord(
            "POST", self._output_signature.__class__.__name__,
            time.perf_counter() - start, before, _size(script),
        )
        if profiler:
            profiler.add(record)
        if verbose >= Verbosity.NORMAL:
            info_message("POST", self._output_signature, _format_record(record))
        return script

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
