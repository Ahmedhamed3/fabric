from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, JSONResponse


router = APIRouter()

STATIC_DIR = Path("app/static/pipeline-ui")
INDEX_PATH = STATIC_DIR / "index.html"


class PipelineSource:
    def __init__(self, name: str, raw_base: str, ocsf_base: str) -> None:
        self.name = name
        self.raw_base = Path(raw_base)
        self.ocsf_base = Path(ocsf_base)


PIPELINE_SOURCES = [
    PipelineSource(
        name="sysmon",
        raw_base="out/raw/endpoint/windows_sysmon",
        ocsf_base="out/ocsf/endpoint/windows_sysmon",
    ),
    PipelineSource(
        name="windows-security",
        raw_base="out/raw/endpoint/windows_security",
        ocsf_base="out/ocsf/endpoint/windows_security",
    ),
    PipelineSource(
        name="elastic",
        raw_base="out/raw/siem/elastic",
        ocsf_base="out/ocsf/siem/elastic",
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
    ocsf_cache: Dict[Path, Dict[tuple[str, str], Dict[str, Any]]] = {}
    report_cache: Dict[Path, Tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]] = {}

    enriched: List[Dict[str, Any]] = []
    for entry in aggregated:
        raw_event = entry["raw_envelope"]
        source = entry["source_obj"]
        raw_path = entry["raw_path"]
        ocsf_event, report = _resolve_stage_outputs(
            raw_event,
            source,
            raw_path,
            ocsf_cache=ocsf_cache,
            report_cache=report_cache,
        )
        if ocsf_event is None:
            report = None
        payload = {
            "event_key": entry["event_key"],
            "time": entry["time"],
            "source": entry["source"],
            "record_id": entry["record_id"],
            "class_uid": (ocsf_event or {}).get("class_uid"),
            "type_uid": (ocsf_event or {}).get("type_uid"),
            "validation_status": (report or {}).get("status"),
            "raw": entry["raw"],
            "envelope": entry["envelope"],
            "ocsf": ocsf_event,
            "validation": report,
        }
        enriched.append(payload)

    aggregated_list = enriched
    if len(aggregated_list) > safe_limit:
        aggregated_list = aggregated_list[-safe_limit:]
    message = None
    if not aggregated_list:
        message = "No pipeline events found. Ensure raw and OCSF outputs exist under out/raw and out/ocsf."
    return JSONResponse({"events": aggregated_list, "message": message})


def _collect_raw_events(limit: int) -> Deque[Dict[str, Any]]:
    from collections import deque

    aggregated: Deque[Dict[str, Any]] = deque(maxlen=limit)
    for source in PIPELINE_SOURCES:
        for raw_path in _list_raw_paths(source.raw_base):
            for raw_event in _read_ndjson(raw_path):
                ids = raw_event.get("ids") or {}
                source_type = (raw_event.get("source") or {}).get("type") or source.name
                record_id = ids.get("record_id")
                observed_time = _raw_event_observed_time(raw_event)
                event_key = _build_event_key(source_type, record_id, observed_time)
                aggregated.append(
                    {
                        "event_key": event_key,
                        "time": _raw_event_time(raw_event),
                        "source": source_type,
                        "record_id": record_id,
                        "raw": _extract_raw_payload(raw_event),
                        "envelope": _extract_envelope(raw_event),
                        "raw_envelope": raw_event,
                        "raw_path": raw_path,
                        "source_obj": source,
                    }
                )
    return aggregated


def _list_raw_paths(base_dir: Path) -> List[Path]:
    if not base_dir.exists():
        return []
    candidates = list(base_dir.rglob("events.ndjson"))
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
    report_path = ocsf_path.with_suffix(".report.ndjson")
    return (ocsf_path if ocsf_path.exists() else None, report_path if report_path.exists() else None)


def _index_reports(reports: Iterable[Dict[str, Any]]) -> tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    by_dedupe: Dict[str, Dict[str, Any]] = {}
    by_record: Dict[str, Dict[str, Any]] = {}
    for report in reports:
        dedupe = report.get("dedupe_hash")
        record_id = report.get("record_id")
        if dedupe:
            by_dedupe[dedupe] = report
        if record_id is not None:
            by_record[str(record_id)] = report
    return by_dedupe, by_record


def _index_ocsf_events(events: Iterable[Dict[str, Any]]) -> Dict[tuple[str, str], Dict[str, Any]]:
    indexed: Dict[tuple[str, str], Dict[str, Any]] = {}
    for event in events:
        forensics = event.get("forensics") or {}
        source = forensics.get("source") or {}
        source_type = source.get("type")
        record_id = forensics.get("raw_record_id")
        if not source_type or record_id is None:
            continue
        indexed[(source_type, str(record_id))] = event
    return indexed


def _resolve_stage_outputs(
    raw_event: Dict[str, Any],
    source: PipelineSource,
    raw_path: Path,
    *,
    ocsf_cache: Dict[Path, Dict[tuple[str, str], Dict[str, Any]]],
    report_cache: Dict[Path, Tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]],
) -> tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    ocsf_path, report_path = _resolve_output_paths(raw_path, source)
    ids = raw_event.get("ids") or {}
    record_id = ids.get("record_id")
    source_type = (raw_event.get("source") or {}).get("type") or source.name

    ocsf_event = None
    if ocsf_path:
        ocsf_index = ocsf_cache.get(ocsf_path)
        if ocsf_index is None:
            ocsf_index = _index_ocsf_events(_read_ndjson(ocsf_path))
            ocsf_cache[ocsf_path] = ocsf_index
        if record_id is not None:
            ocsf_event = ocsf_index.get((source_type, str(record_id)))

    report = None
    if report_path:
        report_index = report_cache.get(report_path)
        if report_index is None:
            reports = _read_ndjson(report_path)
            report_index = _index_reports(reports)
            report_cache[report_path] = report_index
        report_by_dedupe, report_by_record = report_index
        dedupe_hash = ids.get("dedupe_hash")
        if dedupe_hash:
            report = report_by_dedupe.get(dedupe_hash)
        if report is None and record_id is not None:
            report = report_by_record.get(str(record_id))

    return ocsf_event, report


def _extract_raw_payload(raw_event: Dict[str, Any]) -> Any:
    if "raw" in raw_event:
        return raw_event.get("raw")
    return raw_event


def _extract_envelope(raw_event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not isinstance(raw_event, dict):
        return None
    required_keys = ("envelope_version", "source", "event", "raw")
    if all(key in raw_event for key in required_keys):
        return raw_event
    return None


def _raw_event_observed_time(raw_event: Dict[str, Any]) -> Optional[str]:
    time_block = (raw_event.get("event") or {}).get("time") or {}
    return time_block.get("observed_utc")


def _build_event_key(source_type: str, record_id: Any, observed_time: Optional[str]) -> str:
    record_text = "null" if record_id is None else str(record_id)
    observed_text = observed_time if observed_time is not None else "null"
    return f"{source_type}|{record_text}|{observed_text}"


def _raw_event_time(raw_event: Dict[str, Any]) -> Optional[str]:
    time_block = (raw_event.get("event") or {}).get("time") or {}
    return time_block.get("observed_utc") or time_block.get("created_utc")
