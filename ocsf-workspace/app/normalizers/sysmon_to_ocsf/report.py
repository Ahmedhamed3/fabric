from __future__ import annotations

from typing import Any, Dict, List, Optional


def build_report(
    *,
    raw_event: Dict[str, Any],
    ocsf_event: Optional[Dict[str, Any]],
    supported: bool,
    validation_errors: List[str],
    mapping_attempted: bool = False,
    missing_fields: Optional[List[str]] = None,
) -> Dict[str, Any]:
    ids = raw_event.get("ids") or {}
    missing_fields = missing_fields or []
    report = {
        "record_id": ids.get("record_id"),
        "dedupe_hash": ids.get("dedupe_hash"),
        "event_id": ids.get("event_id"),
        "supported": supported,
        "schema_valid": bool(ocsf_event) and not validation_errors if supported else False,
        "validation_errors": validation_errors,
        "mapped": ocsf_event is not None,
    }
    if missing_fields:
        report["missing_fields"] = missing_fields
        report["message"] = f"Unmapped: missing required fields: {', '.join(missing_fields)}"
    if not supported:
        report["status"] = "unmapped" if mapping_attempted else "unsupported"
    elif ocsf_event is None:
        report["status"] = "unmapped"
    elif validation_errors:
        report["status"] = "invalid"
    else:
        report["status"] = "valid"
    return report
