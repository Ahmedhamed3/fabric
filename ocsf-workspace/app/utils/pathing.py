from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class OutputPaths:
    base_dir: Path
    hostname: str

    def daily_events_path(self, when: datetime | None = None) -> Path:
        timestamp = when or datetime.now(timezone.utc)
        return (
            self.base_dir
            / self.hostname
            / f"{timestamp:%Y}"
            / f"{timestamp:%m}"
            / f"{timestamp:%d}"
            / "events.ndjson"
        )


def build_output_paths(base_dir: str | Path, hostname: str) -> OutputPaths:
    return OutputPaths(base_dir=Path(base_dir), hostname=hostname)


def build_elastic_output_path(
    base_dir: str | Path, index: str, when: datetime | None = None
) -> Path:
    timestamp = when or datetime.now(timezone.utc)
    return (
        Path(base_dir)
        / "local"
        / index
        / f"{timestamp:%Y}"
        / f"{timestamp:%m}"
        / f"{timestamp:%d}"
        / "events.ndjson"
    )
