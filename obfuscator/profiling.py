from __future__ import annotations

from dataclasses import dataclass, field
import time
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Callable, cast, TYPE_CHECKING
from collections.abc import Iterator

if TYPE_CHECKING:
    from .passes.mosaic_metrics import DiversityMetrics

from .data_types import JSONValue, ProfileDetail

# A build-local observer sees real boundaries, including nested VM/output
# pipelines. It is absent in CLI builds and never changes profiling records.
_PROGRESS: ContextVar[tuple[Callable[[dict[str, Any]], None], list[int]] | None] = ContextVar('build_progress', default=None)
_PHASE: ContextVar[int | None] = ContextVar('build_phase', default=None)
_PHASE_NAMES: ContextVar[tuple[str, ...]] = ContextVar('build_phase_names', default=())


@contextmanager
def observe_build(listener: Callable[[dict[str, Any]], None]) -> Iterator[None]:
    token = _PROGRESS.set((listener, [0]))
    phase_token = _PHASE.set(None)
    names_token = _PHASE_NAMES.set(())
    try:
        yield
    finally:
        _PHASE_NAMES.reset(names_token)
        _PHASE.reset(phase_token)
        _PROGRESS.reset(token)


@contextmanager
def phase_scope(name: str) -> Iterator[None]:
    observer = _PROGRESS.get()
    if observer is None:
        yield
        return
    listener, sequence = observer
    names = _PHASE_NAMES.get()
    if name.startswith(('source:', 'post:')) and 'output:transforms' in names:
        name = 'output:' + name.split(':', 1)[1]
    sequence[0] += 1
    identity = sequence[0]
    parent = _PHASE.get()
    started = time.perf_counter()
    token = _PHASE.set(identity)
    names_token = _PHASE_NAMES.set((*names, name))
    def notify(status, **extra):
        # Display/bridge failures must not alter a transformation.
        try:
            listener({'id': identity, 'parent': parent, 'phase': name,
                      'status': status, **extra})
        except Exception:
            pass
    notify('running')
    try:
        yield
    except BaseException:
        notify('error', elapsed=time.perf_counter() - started)
        raise
    else:
        notify('success', elapsed=time.perf_counter() - started)
    finally:
        _PHASE_NAMES.reset(names_token)
        _PHASE.reset(token)


def run_phase[T, **P](name: str, function: Callable[P, T], *args: P.args, **kwargs: P.kwargs) -> T:
    with phase_scope(name):
        return function(*args, **kwargs)


@dataclass
class ProfileRecord:
    step: str
    name: str
    elapsed: float
    input_bytes: int
    output_bytes: int
    parser: str | None = None
    replacements: int | None = None
    details: list[ProfileDetail] = field(default_factory=list)

    def as_dict(self) -> dict[str, JSONValue]:
        data: dict[str, JSONValue] = {
            "step": self.step,
            "name": self.name,
            "elapsed": round(self.elapsed, 6),
            "input_bytes": self.input_bytes,
            "output_bytes": self.output_bytes,
            "delta_bytes": self.output_bytes - self.input_bytes,
        }
        if self.parser is not None:
            data["parser"] = self.parser
        if self.replacements is not None:
            data["replacements"] = self.replacements
        if self.details:
            data["details"] = cast(JSONValue, self.details)
        return data


class Profiler:
    def __init__(self) -> None:
        self.records: list[ProfileRecord] = []
        self.literal_mosaic: DiversityMetrics | None = None

    def add(self, record: ProfileRecord) -> None:
        self.records.append(record)

    def as_dict(self) -> dict[str, JSONValue]:
        total = sum(record.elapsed for record in self.records)
        result: dict[str, JSONValue] = {
            "total_elapsed": round(total, 6),
            "passes": [record.as_dict() for record in self.records],
        }
        if self.literal_mosaic is not None:
            result['literal_mosaic'] = self.literal_mosaic.report()
        return result


class PhaseTimer:
    def __init__(self, name: str, sink: list[ProfileDetail]):
        self.name = name
        self.sink = sink
        self.start = 0.0

    def __enter__(self):
        self.start = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc, tb):
        elapsed = time.perf_counter() - self.start
        self.sink.append({"phase": self.name, "elapsed": round(elapsed, 6)})
        return False
