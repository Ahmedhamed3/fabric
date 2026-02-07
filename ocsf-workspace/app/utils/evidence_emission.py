from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Optional

from app.utils.evidence_hashing import apply_evidence_hashing
from app.utils.evidence_metadata import emit_evidence_metadata


logger = logging.getLogger(__name__)


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
        emit_evidence_metadata(hash_result.evidence_commit)
    except Exception as exc:  # noqa: BLE001
        message = f"[EVIDENCE-META] failed to emit metadata: {exc}"
        if log is not None:
            log(message)
        else:
            logger.warning(message)
