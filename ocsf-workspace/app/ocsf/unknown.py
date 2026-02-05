from datetime import datetime, timezone
from typing import Any, Dict, Optional


def _to_iso8601_utc(value: Optional[Any]) -> str:
    if value is None:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, str):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat().replace("+00:00", "Z")
        except Exception:
            pass
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except Exception:
            return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _extract_time_value(event: Dict[str, Any]) -> Optional[Any]:
    for key in ("time", "ts", "timestamp", "UtcTime", "createdDateTime"):
        value = event.get(key)
        if value is not None:
            return value
    time_created = event.get("TimeCreated")
    if isinstance(time_created, dict):
        return time_created.get("SystemTime")
    return None


def map_unknown_event_to_ocsf(event: Dict[str, Any], *, reason: Optional[str] = None) -> Dict[str, Any]:
    unmapped: Dict[str, Any] = {"original_event": event}
    if reason:
        unmapped["reason"] = reason
    return {
        "activity_id": 0,
        "category_uid": 0,
        "class_uid": 0,
        "type_uid": 0,
        "time": _to_iso8601_utc(_extract_time_value(event)),
        "metadata": {"product": "Unknown"},
        "unmapped": unmapped,
    }


def map_parse_error_to_ocsf(
    *,
    raw_line: str,
    error_message: str,
    ingestion_time: str,
) -> Dict[str, Any]:
    return {
        "activity_id": 0,
        "category_uid": 0,
        "class_uid": 0,
        "type_uid": 0,
        "time": ingestion_time,
        "metadata": {"product": "ParseError"},
        "unmapped": {
            "original_line": raw_line,
            "parse_error": error_message,
        },
    }
