from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Iterable


DEBUG_PIPELINE_ENV = "OCSF_DEBUG_PIPELINE"


def debug_pipeline_enabled() -> bool:
    value = os.getenv(DEBUG_PIPELINE_ENV, "").strip().lower()
    return value in {"1", "true", "yes", "on"}


def resolve_debug_input(env_var: str, default_path: str | Path) -> Path:
    override = os.getenv(env_var, "").strip()
    if override:
        return Path(override)
    return Path(default_path)


def read_ndjson(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def write_ndjson(path: Path, payloads: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for payload in payloads:
            handle.write(json.dumps(payload))
            handle.write("\n")
