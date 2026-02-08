from __future__ import annotations

import logging
import os
from typing import Any, Callable, Dict, Optional

from app.utils.evidence_hashing import apply_evidence_hashing
from app.utils.evidence_metadata import emit_evidence_metadata, resolve_evidence_api_url


logger = logging.getLogger(__name__)


def ensure_evidence_api_url() -> None:
    resolved = resolve_evidence_api_url()
    if not resolved:
        return
    os.environ["EVIDENCE_API_URL"] = resolved


def emit_evidence_metadata_for_event(
    raw_event: Dict[str, Any],
    ocsf_event: Dict[str, Any],
    *,
    ocsf_schema: Optional[str] = None,
    ocsf_version: Optional[str] = None,
    log: Optional[Callable[[str], None]] = None,
) -> None:
    try:
        hash_result = apply_evidence_hashing(
            raw_event,
            ocsf_event,
            ocsf_schema=ocsf_schema,
            ocsf_version=ocsf_version,
        )
        emit_evidence_metadata(hash_result.evidence_commit, raw_envelope=raw_event)
    except Exception as exc:  # noqa: BLE001
        message = f"[EVIDENCE-META] failed to emit metadata: {exc}"
        if log is not None:
            log(message)
        else:
            logger.warning(message)
