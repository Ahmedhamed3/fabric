from __future__ import annotations

import os
from pathlib import Path


DEBUG_ARTIFACT_ENV = "FABRIC_DEBUG_PIPELINE"


def debug_artifacts_enabled() -> bool:
    value = os.getenv(DEBUG_ARTIFACT_ENV, "").strip().lower()
    return value in {"1", "true", "yes", "on"}


def mirror_path(path: Path, source_root: str | Path, target_root: str | Path) -> Path:
    source_root = Path(source_root)
    target_root = Path(target_root)
    try:
        relative = path.relative_to(source_root)
    except ValueError:
        return target_root / path.name
    return target_root / relative
