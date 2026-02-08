from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, JSONResponse


router = APIRouter()

STATIC_DIR = Path("app/static/pipeline-ui")
INDEX_PATH = STATIC_DIR / "index.html"


class PipelineSource:
    def __init__(
        self,
        name: str,
        key: str,
        raw_base: str,
        envelope_base: str,
        ocsf_base: str,
        validation_base: str,
    ) -> None:
        self.name = name
        self.key = key
        self.raw_base = Path(raw_base)
        self.envelope_base = Path(envelope_base)
        self.ocsf_base = Path(ocsf_base)
        self.validation_base = Path(validation_base)


PIPELINE_SOURCES = [
    PipelineSource(
        name="sysmon",
        key="sysmon",
        raw_base="out/raw/endpoint/windows_sysmon",
        envelope_base="out/envelope/endpoint/windows_sysmon",
        ocsf_base="out/ocsf/endpoint/windows_sysmon",
        validation_base="out/validation/endpoint/windows_sysmon",
    ),
    PipelineSource(
        name="windows-security",
        key="security",
        raw_base="out/raw/endpoint/windows_security",
        envelope_base="out/envelope/endpoint/windows_security",
        ocsf_base="out/ocsf/endpoint/windows_security",
        validation_base="out/validation/endpoint/windows_security",
    ),
    PipelineSource(
        name="elastic",
        key="elastic",
        raw_base="out/raw/siem/elastic",
        envelope_base="out/envelope/siem/elastic",
        ocsf_base="out/ocsf/siem/elastic",
        validation_base="out/validation/siem/elastic",
    ),
]


@router.get("/ui/pipeline")
def pipeline_ui() -> FileResponse:
    if not INDEX_PATH.exists():
        raise HTTPException(status_code=404, detail="Pipeline UI not found.")
    return FileResponse(INDEX_PATH)


@router.get("/api/debug/pipeline/events")
def pipeline_events(limit: int = 50) -> JSONResponse:
    safe_limit = max(1, min(limit, 200))
    aggregated: Deque[Dict[str, Any]] = _collect_raw_events(safe_limit)
    envelope_cache: Dict[Path, Dict[str, Dict[str, Any]]] = {}
    ocsf_cache: Dict[Path, Dict[str, Dict[str, Any]]] = {}
    report_cache: Dict[Path, Dict[str, Dict[str, Any]]] = {}

    enriched: List[Dict[str, Any]] = []
    for entry in aggregated:
        raw_event = entry["raw_event"]
        source = entry["source_obj"]
        raw_path = entry["raw_path"]
        envelope_event, ocsf_event, report = _resolve_stage_outputs(
            raw_event,
            source,
            raw_path,
            envelope_cache=envelope_cache,
            ocsf_cache=ocsf_cache,
            report_cache=report_cache,
        )
        payload = {
            "event_key": entry["event_key"],
            "time": entry["time"],
            "source": entry["source"],
            "record_id": entry["record_id"],
            "class_uid": (ocsf_event or {}).get("class_uid"),
            "type_uid": (ocsf_event or {}).get("type_uid"),
            "validation_status": (report or {}).get("status"),
            "raw": _raw_payload(entry["raw_event"]),
            "envelope": envelope_event,
            "ocsf": ocsf_event,
            "validation": report,
        }
        enriched.append(payload)

    aggregated_list = enriched
    if len(aggregated_list) > safe_limit:
        aggregated_list = aggregated_list[-safe_limit:]
    message = None
    if not aggregated_list:
        message = "No pipeline events found. Ensure raw outputs exist under out/raw."
    return JSONResponse({"events": aggregated_list, "message": message})


def _collect_raw_events(limit: int) -> Deque[Dict[str, Any]]:
    from collections import deque

    aggregated: Deque[Dict[str, Any]] = deque(maxlen=limit)
    for source in PIPELINE_SOURCES:
        for raw_path in _list_raw_paths(source.raw_base):
            for raw_event in _read_ndjson(raw_path):
                source_type = _extract_source_type(raw_event, source)
                record_id = _extract_record_id(raw_event)
                observed_time = _extract_event_time(raw_event)
                event_key = _build_event_key(source_type, record_id, observed_time)
                aggregated.append(
                    {
                        "event_key": event_key,
                        "time": _format_event_time(raw_event),
                        "source": source_type,
                        "record_id": record_id,
                        "raw": raw_event,
                        "raw_event": raw_event,
                        "raw_path": raw_path,
                        "source_obj": source,
                    }
                )
    return aggregated


def _list_raw_paths(base_dir: Path) -> List[Path]:
    if not base_dir.exists():
        return []
    candidates = list(base_dir.rglob("*.ndjson"))
    return sorted(candidates, key=lambda path: (path.stat().st_mtime, str(path)))


def _read_ndjson(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def _resolve_output_paths(
    raw_path: Path,
    source: PipelineSource,
) -> tuple[Optional[Path], Optional[Path]]:
    try:
        relative = raw_path.relative_to(source.raw_base)
    except ValueError:
        return None, None
    ocsf_path = source.ocsf_base / relative
    report_path = (source.validation_base / relative).with_suffix(".report.ndjson")
    return (ocsf_path if ocsf_path.exists() else None, report_path if report_path.exists() else None)


def _index_by_key(
    events: Iterable[Dict[str, Any]],
    source: PipelineSource,
    *,
    record_lookup: bool = False,
) -> Dict[str, Dict[str, Any]]:
    indexed: Dict[str, Dict[str, Any]] = {}
    for event in events:
        source_type = _extract_source_type(event, source, fallback=source.key)
        record_id = _extract_record_id(event)
        observed_time = _extract_event_time(event)
        for key in _build_lookup_keys(source_type, record_id, observed_time, record_lookup=record_lookup):
            indexed.setdefault(key, event)
    return indexed


def _resolve_stage_outputs(
    raw_event: Dict[str, Any],
    source: PipelineSource,
    raw_path: Path,
    *,
    envelope_cache: Dict[Path, Dict[str, Dict[str, Any]]],
    ocsf_cache: Dict[Path, Dict[str, Dict[str, Any]]],
    report_cache: Dict[Path, Dict[str, Dict[str, Any]]],
) -> tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    ocsf_path, report_path = _resolve_output_paths(raw_path, source)
    envelope_path = _resolve_envelope_path(raw_path, source)
    source_type = _extract_source_type(raw_event, source)
    record_id = _extract_record_id(raw_event)
    observed_time = _extract_event_time(raw_event)
    lookup_keys = _build_lookup_keys(source_type, record_id, observed_time, record_lookup=True)

    envelope_event = None
    if envelope_path:
        envelope_index = envelope_cache.get(envelope_path)
        if envelope_index is None:
            envelope_index = _index_by_key(_read_ndjson(envelope_path), source, record_lookup=True)
            envelope_cache[envelope_path] = envelope_index
        envelope_event = _lookup_by_keys(envelope_index, lookup_keys)

    ocsf_event = None
    if ocsf_path:
        ocsf_index = ocsf_cache.get(ocsf_path)
        if ocsf_index is None:
            ocsf_index = _index_ocsf_events(_read_ndjson(ocsf_path), source)
            ocsf_cache[ocsf_path] = ocsf_index
        ocsf_event = _lookup_by_keys(ocsf_index, lookup_keys)

    report = None
    if report_path:
        report_index = report_cache.get(report_path)
        if report_index is None:
            reports = _read_ndjson(report_path)
            report_index = _index_by_key(reports, source, record_lookup=True)
            report_cache[report_path] = report_index
        report = _lookup_by_keys(report_index, lookup_keys)

    return envelope_event, ocsf_event, report


def _resolve_envelope_path(raw_path: Path, source: PipelineSource) -> Optional[Path]:
    try:
        relative = raw_path.relative_to(source.raw_base)
    except ValueError:
        return None
    envelope_path = source.envelope_base / relative
    return envelope_path if envelope_path.exists() else None


def _build_event_key(source_type: str, record_id: Any, observed_time: Optional[str]) -> str:
    record_text = "null" if record_id is None else str(record_id)
    observed_text = observed_time if observed_time is not None else "null"
    return f"{source_type}|{record_text}|{observed_text}"

def _build_lookup_keys(
    source_type: str,
    record_id: Any,
    observed_time: Optional[str],
    *,
    record_lookup: bool,
) -> List[str]:
    if record_id is None:
        return []
    keys = [_build_event_key(source_type, record_id, observed_time)]
    if record_lookup:
        keys.append(_build_event_key(source_type, record_id, None))
    return keys


def _lookup_by_keys(index: Dict[str, Dict[str, Any]], keys: List[str]) -> Optional[Dict[str, Any]]:
    for key in keys:
        hit = index.get(key)
        if hit is not None:
            return hit
    return None


def _extract_source_type(raw_event: Dict[str, Any], source: PipelineSource, fallback: Optional[str] = None) -> str:
    raw_source = raw_event.get("source") if isinstance(raw_event, dict) else None
    source_type = None
    if isinstance(raw_source, dict):
        source_type = raw_source.get("type")
    source_type = source_type or fallback or source.key
    if not source_type:
        return source.key
    normalized = str(source_type).lower()
    if "sysmon" in normalized:
        return "sysmon"
    if "security" in normalized:
        return "security"
    if "elastic" in normalized:
        return "elastic"
    return source_type


def _extract_record_id(raw_event: Dict[str, Any]) -> Any:
    if not isinstance(raw_event, dict):
        return None
    ids = raw_event.get("ids") or {}
    if "record_id" in ids:
        return ids.get("record_id")
    if "record_id" in raw_event:
        return raw_event.get("record_id")
    event_block = raw_event.get("event") or {}
    if "record_id" in event_block:
        return event_block.get("record_id")
    raw_block = raw_event.get("raw") or {}
    raw_data = raw_block.get("data") if isinstance(raw_block, dict) else None
    if isinstance(raw_data, dict) and "record_id" in raw_data:
        return raw_data.get("record_id")
    return None


def _extract_event_time(raw_event: Dict[str, Any]) -> Optional[str]:
    if not isinstance(raw_event, dict):
        return None
    time_block = (raw_event.get("event") or {}).get("time") or {}
    for key in ("observed_utc", "created_utc"):
        if time_block.get(key):
            return time_block.get(key)
    for key in ("time_created_utc", "timestamp", "time"):
        if raw_event.get(key):
            return raw_event.get(key)
    raw_block = raw_event.get("raw") or {}
    if isinstance(raw_block, dict):
        raw_data = raw_block.get("data")
        if isinstance(raw_data, dict):
            for key in ("time_created_utc", "timestamp", "time"):
                if raw_data.get(key):
                    return raw_data.get(key)
    return None


def _format_event_time(raw_event: Dict[str, Any]) -> Optional[str]:
    return _extract_event_time(raw_event)


def _raw_payload(raw_event: Dict[str, Any] | Any) -> Any:
    if not isinstance(raw_event, dict):
        return raw_event
    payload = raw_event.get("raw")
    return payload if payload is not None else raw_event


def _index_ocsf_events(
    events: Iterable[Dict[str, Any]],
    source: PipelineSource,
) -> Dict[str, Dict[str, Any]]:
    indexed: Dict[str, Dict[str, Any]] = {}
    for event in events:
        forensics = event.get("forensics") or {}
        source_block = forensics.get("source") or {}
        source_type = source_block.get("type") or source.key
        record_id = forensics.get("raw_record_id")
        observed_time = _extract_event_time(event)
        if record_id is None:
            continue
        for key in _build_lookup_keys(
            _extract_source_type({"source": {"type": source_type}}, source, fallback=source.key),
            record_id,
            observed_time,
            record_lookup=True,
        ):
            indexed.setdefault(key, event)
    return indexed
