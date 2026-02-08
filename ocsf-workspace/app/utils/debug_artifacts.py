from __future__ import annotations

import os
from pathlib import Path


DEBUG_ARTIFACT_ENV = "FABRIC_DEBUG_PIPELINE"
DEBUG_PIPELINE_ENV = "OCSF_DEBUG_PIPELINE"


def debug_artifacts_enabled() -> bool:
    for env_name in (DEBUG_ARTIFACT_ENV, DEBUG_PIPELINE_ENV):
        value = os.getenv(env_name, "").strip().lower()
        if value in {"1", "true", "yes", "on"}:
            return True
    return False


def mirror_path(path: Path, source_root: str | Path, target_root: str | Path) -> Path:
    source_root = Path(source_root)
    target_root = Path(target_root)
    try:
        relative = path.relative_to(source_root)
    except ValueError:
        return target_root / path.name
    return target_root / relative
