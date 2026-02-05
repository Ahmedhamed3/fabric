from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Iterable

from app.utils.timeutil import to_utc_iso

def local_timezone_name() -> str:
    offset = datetime.now().astimezone().strftime("%z") or "+0000"
    return f"UTC{offset}"


def map_security_severity(level: int | None) -> str:
    if level == 1:
        return "critical"
    if level == 2:
        return "high"
    if level == 3:
        return "medium"
    if level == 4:
        return "low"
    return "information"


def compute_dedupe_hash(
    source_type: str,
    hostname: str,
    record_id: int | None,
    event_id: int | None,
    observed_utc: str,
    provider: str | None,
    computer: str | None,
    channel: str | None,
) -> str:
    payload = "|".join(
        [
            source_type,
            hostname,
            str(record_id or ""),
            str(event_id or ""),
            observed_utc,
            provider or "",
            computer or "",
            channel or "",
        ]
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def validate_raw_event_v1(envelope: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if envelope.get("envelope_version") != "1.0":
        errors.append("envelope_version must be '1.0'")
    source = envelope.get("source")
    if not isinstance(source, dict):
        errors.append("source must be an object")
    else:
        for key in ("type", "vendor", "product"):
            if not source.get(key):
                errors.append(f"source.{key} is required")
    event = envelope.get("event")
    if not isinstance(event, dict):
        errors.append("event must be an object")
    else:
        time_block = event.get("time")
        if not isinstance(time_block, dict):
            errors.append("event.time must be an object")
        else:
            if not time_block.get("observed_utc"):
                errors.append("event.time.observed_utc is required")
            if not time_block.get("created_utc"):
                errors.append("event.time.created_utc is required")
    ids = envelope.get("ids")
    if not isinstance(ids, dict):
        errors.append("ids must be an object")
    else:
        if "dedupe_hash" not in ids or not ids.get("dedupe_hash"):
            errors.append("ids.dedupe_hash is required")
    host = envelope.get("host")
    if not isinstance(host, dict):
        errors.append("host must be an object")
    severity = envelope.get("severity")
    if not isinstance(severity, str) or not severity:
        errors.append("severity must be a non-empty string")
    tags = envelope.get("tags")
    if not isinstance(tags, list):
        errors.append("tags must be a list")
    raw = envelope.get("raw")
    if not isinstance(raw, dict):
        errors.append("raw must be an object")
    else:
        if not raw.get("format"):
            errors.append("raw.format is required")
        if "data" not in raw:
            errors.append("raw.data is required")
    return errors


def compute_elastic_dedupe_hash(
    index: str | None,
    doc_id: str | None,
    observed_utc: str,
    source_subset: dict[str, Any],
) -> str:
    payload = {
        "index": index or "",
        "id": doc_id or "",
        "timestamp": observed_utc,
        "source": source_subset,
    }
    digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def map_ecs_severity(event_severity: int | None, log_level: str | None) -> str:
    if event_severity is not None:
        if event_severity >= 9:
            return "critical"
        if event_severity >= 7:
            return "high"
        if event_severity >= 4:
            return "medium"
        if event_severity >= 2:
            return "low"
        return "information"
    if log_level:
        normalized = log_level.lower()
        if normalized in {"fatal", "critical", "panic", "emergency"}:
            return "critical"
        if normalized in {"error", "err"}:
            return "high"
        if normalized in {"warn", "warning"}:
            return "medium"
        if normalized in {"info", "information", "notice"}:
            return "low"
        if normalized in {"debug", "trace"}:
            return "information"
    return "information"


def build_elastic_raw_event(
    hit: dict[str, Any],
    *,
    now_utc: str,
    hostname: str,
    timezone_name: str,
) -> dict[str, Any]:
    source = hit.get("_source") or {}
    fields = hit.get("fields") or {}
    observed_utc = _extract_observed_utc(source, fields, now_utc)
    channel = _extract_channel(hit, source)
    event_severity = _extract_int(source, ("event", "severity"))
    log_level = _extract_str(source, ("log", "level"))
    severity = map_ecs_severity(event_severity, log_level)
    ids_activity = _extract_first_id(source, ("event", "id"), ("trace", "id"), ("transaction", "id"))
    if not ids_activity:
        related = _extract_list(source, ("related", "id"))
        ids_activity = related[0] if related else None
    event_code = _extract_str(source, ("event", "code"))
    event_action = _extract_str(source, ("event", "action"))
    event_id = event_code or (_non_numeric(event_action) if event_action else None)
    source_subset = _extract_stable_source_subset(source)
    dedupe_hash = compute_elastic_dedupe_hash(
        hit.get("_index"),
        hit.get("_id"),
        observed_utc,
        source_subset,
    )
    raw_data = dict(hit)
    raw_data["_source"] = source
    raw_data["_index"] = hit.get("_index")
    raw_data["_id"] = hit.get("_id")
    timezone_value = _extract_str(source, ("event", "timezone")) or timezone_name
    host_name = _extract_host_name(source) or hostname
    host_os = _extract_host_os(source)
    return {
        "envelope_version": "1.0",
        "source": {
            "type": "elastic",
            "vendor": "elastic",
            "product": "elastic-stack",
            "channel": channel,
            "collector": {
                "name": "elastic-connector",
                "instance_id": f"{hostname}:elastic",
                "host": hostname,
            },
        },
        "event": {
            "time": {
                "observed_utc": observed_utc,
                "created_utc": now_utc,
            }
        },
        "ids": {
            "record_id": hit.get("_id"),
            "event_id": event_id,
            "activity_id": ids_activity,
            "correlation_id": ids_activity,
            "dedupe_hash": dedupe_hash,
        },
        "host": {
            "hostname": host_name,
            "os": host_os,
            "timezone": timezone_value,
        },
        "severity": severity,
        "tags": ["live", "elastic"],
        "raw": {
            "format": "json",
            "data": raw_data,
            "rendered_message": source.get("message"),
        },
    }


def _extract_observed_utc(source: dict[str, Any], fields: dict[str, Any], now_utc: str) -> str:
    timestamp = source.get("@timestamp")
    if not timestamp:
        field_ts = fields.get("@timestamp")
        if isinstance(field_ts, list) and field_ts:
            timestamp = field_ts[0]
        elif isinstance(field_ts, str):
            timestamp = field_ts
    if timestamp and isinstance(timestamp, str):
        return to_utc_iso(timestamp) or now_utc
    return now_utc


def _extract_channel(hit: dict[str, Any], source: dict[str, Any]) -> str | None:
    data_stream = source.get("data_stream")
    if isinstance(data_stream, dict):
        dataset = data_stream.get("dataset")
        namespace = data_stream.get("namespace")
        stream_type = data_stream.get("type")
        if dataset and namespace and stream_type:
            return f"{stream_type}-{dataset}-{namespace}"
        if dataset:
            return str(dataset)
    index = hit.get("_index")
    return str(index) if index is not None else None


def _extract_int(source: dict[str, Any], path: Iterable[str]) -> int | None:
    value = _extract_value(source, path)
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _extract_str(source: dict[str, Any], path: Iterable[str]) -> str | None:
    value = _extract_value(source, path)
    if isinstance(value, str) and value:
        return value
    return None


def _extract_list(source: dict[str, Any], path: Iterable[str]) -> list[Any]:
    value = _extract_value(source, path)
    if isinstance(value, list):
        return value
    return []


def _extract_value(source: dict[str, Any], path: Iterable[str]) -> Any:
    cursor: Any = source
    for key in path:
        if not isinstance(cursor, dict):
            return None
        cursor = cursor.get(key)
    return cursor


def _extract_first_id(source: dict[str, Any], *paths: Iterable[str]) -> str | None:
    for path in paths:
        value = _extract_str(source, path)
        if value:
            return value
    return None


def _extract_host_name(source: dict[str, Any]) -> str | None:
    for path in (("host", "name"), ("host", "hostname"), ("agent", "hostname"), ("agent", "name")):
        value = _extract_str(source, path)
        if value:
            return value
    return None


def _extract_host_os(source: dict[str, Any]) -> str | None:
    for path in (("host", "os", "name"), ("host", "os", "full"), ("host", "os", "platform")):
        value = _extract_str(source, path)
        if value:
            return value
    return None


def _extract_stable_source_subset(source: dict[str, Any]) -> dict[str, Any]:
    subset_keys = ("event", "log", "host", "agent", "trace", "transaction", "related", "message", "tags", "labels")
    subset: dict[str, Any] = {}
    for key in subset_keys:
        if key in source:
            subset[key] = source[key]
    return subset


def _non_numeric(value: str) -> str | None:
    return value if value and not value.isdigit() else None


def build_security_raw_event(
    raw_record: dict[str, Any],
    observed_utc: str,
    hostname: str,
    timezone_name: str,
) -> dict[str, Any]:
    record_id = raw_record.get("record_id")
    event_id = raw_record.get("event_id")
    created_utc = raw_record.get("time_created_utc")
    provider = raw_record.get("provider")
    channel = raw_record.get("channel") or "Security"
    severity = map_security_severity(raw_record.get("level"))
    dedupe_hash = compute_dedupe_hash(
        "security",
        hostname,
        record_id,
        event_id,
        observed_utc,
        provider,
        raw_record.get("computer"),
        channel,
    )
    return {
        "envelope_version": "1.0",
        "source": {
            "type": "security",
            "vendor": "microsoft",
            "product": "windows-security-auditing",
            "channel": "Security",
            "collector": {
                "name": "security-connector",
                "instance_id": f"{hostname}:security",
                "host": hostname,
            },
        },
        "event": {
            "time": {
                "observed_utc": observed_utc,
                "created_utc": created_utc,
            }
        },
        "ids": {
            "record_id": record_id,
            "event_id": event_id,
            "activity_id": raw_record.get("activity_id"),
            "correlation_id": raw_record.get("correlation_id"),
            "dedupe_hash": dedupe_hash,
        },
        "host": {
            "hostname": hostname,
            "os": "windows",
            "timezone": timezone_name,
        },
        "severity": severity,
        "tags": ["live", "security"],
        "raw": {
            "format": "json",
            "data": raw_record,
            "rendered_message": raw_record.get("rendered_message"),
            "xml": raw_record.get("raw_xml"),
        },
    }
