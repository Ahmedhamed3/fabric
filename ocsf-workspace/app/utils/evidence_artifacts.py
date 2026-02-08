from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

PERSIST_ARTIFACT_ENV = "PIPELINE_PERSIST_ARTIFACTS"
RAW_BASE = Path("out/raw")
ENVELOPE_BASE = Path("out/envelope")
OCSF_BASE = Path("out/ocsf")
VALIDATION_BASE = Path("out/validation")


def persist_artifacts_enabled() -> bool:
    value = os.getenv(PERSIST_ARTIFACT_ENV)
    if value is None:
        return True
    normalized = value.strip().lower()
    if normalized in {"0", "false", "no", "off"}:
        return False
    if normalized in {"1", "true", "yes", "on"}:
        return True
    return True


def persist_evidence_artifacts(
    *,
    evidence_id: str,
    raw_event: Optional[Any],
    envelope: Optional[Dict[str, Any]],
    ocsf_event: Optional[Dict[str, Any]],
    validation_report: Optional[Dict[str, Any]],
) -> None:
    if not evidence_id or not persist_artifacts_enabled():
        return
    if raw_event is not None:
        _write_json(RAW_BASE / f"{evidence_id}.json", raw_event)
    if envelope is not None:
        _write_json(ENVELOPE_BASE / f"{evidence_id}.json", envelope)
    if ocsf_event is not None:
        _write_json(OCSF_BASE / f"{evidence_id}.json", ocsf_event)
    if validation_report is not None:
        _write_json(VALIDATION_BASE / f"{evidence_id}.json", validation_report)


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    with temp_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False)
    temp_path.replace(path)
