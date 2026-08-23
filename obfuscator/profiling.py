from __future__ import annotations

from dataclasses import dataclass, field
import time
from typing import Any


@dataclass
class ProfileRecord:
    step: str
    name: str
    elapsed: float
    input_bytes: int
    output_bytes: int
    parser: str | None = None
    replacements: int | None = None
    details: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        data = {
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
            data["details"] = self.details
        return data


class Profiler:
    def __init__(self):
        self.records: list[ProfileRecord] = []

    def add(self, record: ProfileRecord) -> None:
        self.records.append(record)

    def as_dict(self) -> dict[str, Any]:
        total = sum(record.elapsed for record in self.records)
        return {
            "total_elapsed": round(total, 6),
            "passes": [record.as_dict() for record in self.records],
        }


class PhaseTimer:
    def __init__(self, name: str, sink: list[dict[str, Any]]):
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
