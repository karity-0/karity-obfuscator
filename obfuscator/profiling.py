from __future__ import annotations

from dataclasses import dataclass, field
import time
from typing import cast, TYPE_CHECKING

if TYPE_CHECKING:
    from .passes.mosaic_metrics import DiversityMetrics

from .data_types import JSONValue, ProfileDetail


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
