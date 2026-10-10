from __future__ import annotations

# Load processing dependencies only when the corresponding feature is used.
__lazy_modules__ = {
    "luaparser",
    "obfuscator.passes.rename_obfuscation",
    "obfuscator.toolchain",
    "obfuscator.vm.targets.profile",
}

import time
from typing import Self, TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from .passes.literal_mosaic import LiteralMosaic

from luaparser import ast

from .data_types import JSONValue
from .config_types import ObfuscatorConfig, RenameOptions
from .toolchain import LuaToolchain
from .vm.targets.profile import TargetProfile
from .passes.base import BasePass, PostPass, PrePass, Replacement
from .passes.output_signature import DEFAULT_SIGNATURE, OutputSignaturePass
from .profiling import ProfileRecord, Profiler
from .verbosity import Verbosity
from .passes.rename_obfuscation import RenameObfuscationPass
from .passes.numeric_provenance import join_code


type PassType = BasePass | PrePass | PostPass


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
        self.rename_options: RenameOptions | None = None
        self._pre_passes: list[PrePass] = []
        self._passes: list[BasePass] = []
        self._post_passes: list[PostPass] = []
        self.show_header = show_header
        self.selection_config: ObfuscatorConfig = {}
        self.mosaic_scope: LiteralMosaic | None = None
        self.last_mosaic_metrics: dict[str, Any] = {}
        self.target_profile: TargetProfile
        self.toolchain: LuaToolchain
        self.last_selection_report: list[dict[str, JSONValue]] = []
        self._output_signature: OutputSignaturePass | None = (
            OutputSignaturePass() if show_header else None
        )

    def add(self, pass_: PassType) -> Self:
        if isinstance(pass_, OutputSignaturePass):
            self._output_signature = pass_
        elif isinstance(pass_, PrePass):
            self._pre_passes.append(pass_)
        elif isinstance(pass_, PostPass):
            self._post_passes.append(pass_)
        else:
            self._passes.append(pass_)
        return self

    def run(
        self,
        script: str,
        verbose: int = 0,
        profiler: Profiler | None = None,
    ) -> str:
        from .names import RENAME_OPTIONS
        from .passes.literal_mosaic import LiteralMosaic, use_mosaic
        from .passes.mosaic_metrics import DiversityMetrics

        mosaic = self.mosaic_scope or LiteralMosaic(
            lua_version=getattr(getattr(self,'target_profile',None),'lua_version','5.3'),
            options=self.selection_config.get('literal_mosaic',{}),
            metrics=DiversityMetrics(profiler is not None or self.selection_config.get('literal_mosaic',{}).get('diversity_metrics',False)))
        if profiler is not None and mosaic.metrics.enabled:
            profiler.literal_mosaic = mosaic.metrics

        token = (
            RENAME_OPTIONS.set(self.rename_options)
            if self.rename_options is not None
            else None
        )
        try:
            with use_mosaic(mosaic):
                return self._run(script, verbose, profiler)
        finally:
            self.last_mosaic_metrics = mosaic.metrics.report() if mosaic.metrics.enabled else {}
            if token is not None:
                RENAME_OPTIONS.reset(token)

    def _run(
        self,
        script: str,
        verbose: int = 0,
        profiler: Profiler | None = None,
    ) -> str:
        from .selection_runtime import SelectionRuntime

        selection = SelectionRuntime(self, script)
        script = selection.plan.source if selection.enabled else script
        self.last_selection_report = selection.plan.report
        for pre in self._pre_passes:
            before = _size(script)
            start = time.perf_counter()
            script = selection.run_pre(pre, script) if selection.enabled else pre.run(script)
            elapsed = time.perf_counter() - start

            record = ProfileRecord(
                "PRE",
                pre.__class__.__name__,
                elapsed,
                before,
                _size(script),
            )

            if profiler:
                profiler.add(record)

            if verbose >= Verbosity.NORMAL:
                info_message("PRE", pre, _format_record(record))

        # Renaming is an emission step: collect every generated base-pass helper
        # before choosing final names. Localization resolves lexical bindings on
        # its own, so it does not need an earlier rename to distinguish globals.
        renamers = [
            p
            for p in self._passes
            if isinstance(p, RenameObfuscationPass)
        ]
        base_passes = [
            p
            for p in self._passes
            if not isinstance(p, RenameObfuscationPass)
        ]

        if renamers:
            base_passes.append(renamers[-1])

        if selection.enabled:
            base_passes = selection.base_passes(base_passes)

        if self.mosaic_scope is None:
            from dataclasses import replace
            from .registry import PASS_REGISTRY
            from .passes.literal_mosaic import ACTIVE
            service = ACTIVE.get()
            assert service is not None
            class_names = {cast(Any,info).class_name:name for name,info in PASS_REGISTRY.items()}
            service.policy = replace(service.policy, passes=frozenset(
                class_names.get(type(p).__name__,'') for p in base_passes))
            service.selection = selection.plan if selection.enabled else None

        for pass_ in base_passes:
            before = _size(script)
            start = time.perf_counter()
            if selection.enabled:
                script = selection.prepare_base(pass_, script)

            parser = getattr(pass_, "parser", "luaparser")

            if parser == "treesitter":
                from .passes.ts_utils import parse as _ts_parse

                tree = _ts_parse(script)
            else:
                tree = ast.parse(script)

            replacements = (selection.run_base(pass_, script, tree) if selection.enabled
                            else pass_.run(script, tree))
            script = (selection.plan.apply(script, replacements) if selection.enabled
                      else self._apply(script, replacements))

            elapsed = time.perf_counter() - start

            record = ProfileRecord(
                "BASE",
                pass_.__class__.__name__,
                elapsed,
                before,
                _size(script),
                parser=parser,
                replacements=len(replacements),
                details=getattr(pass_, "last_profile", []),
            )

            if profiler:
                profiler.add(record)

            if verbose >= Verbosity.NORMAL:
                info_message("BASE", pass_, _format_record(record))

            if verbose > Verbosity.DEBUG:
                new_tree = ast.parse(script)
                print(ast.to_pretty_str(new_tree))

        post_passes = selection.post_passes(self._post_passes) if selection.enabled else self._post_passes
        for post in post_passes:
            before = _size(script)
            start = time.perf_counter()

            script = selection.run_post(post, script) if selection.enabled else post.run(script)

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
                        print(
                            f"  - {detail['phase']}: "
                            f"{detail['elapsed']:.3f}s"
                        )

        if self._output_signature is None:
            return script

        before = _size(script)
        start = time.perf_counter()

        script = self._output_signature.run(script)

        record = ProfileRecord(
            "POST",
            self._output_signature.__class__.__name__,
            time.perf_counter() - start,
            before,
            _size(script),
        )

        if profiler:
            profiler.add(record)

        if verbose >= Verbosity.NORMAL:
            info_message(
                "POST",
                self._output_signature,
                _format_record(record),
            )

        return script

    def _apply(
        self,
        src: str,
        replacements: list[Replacement],
    ) -> str:
        if not replacements:
            return src

        parts: list[str] = []
        pos = 0

        # Replacement uses inclusive end coordinates.
        #
        # end < start represents a zero-width insertion. Insertions must be
        # emitted before a normal replacement starting at the same source
        # position, and must not consume any source characters.
        #
        # Keep the original caller order between multiple insertions at the
        # same position.
        indexed = list(enumerate(replacements))

        ordered = sorted(
            indexed,
            key=lambda item: (
                item[1].start,
                0 if item[1].end < item[1].start else 1,
                item[0],
            ),
        )

        for _, replacement in ordered:
            start = replacement.start
            end = replacement.end
            is_insertion = end < start

            if start < pos:
                kind = "insertion" if is_insertion else "replacement"
                raise RuntimeError(
                    f"overlapping {kind} at {start}:{end}, "
                    f"previous end={pos - 1}"
                )

            parts.append(src[pos:start])
            parts.append(replacement.new_text)

            if is_insertion:
                # Move the cursor up to the insertion point but consume
                # nothing. A normal replacement may therefore still begin
                # at the exact same source position.
                pos = start
            else:
                pos = end + 1

        parts.append(src[pos:])
        return join_code(parts)
