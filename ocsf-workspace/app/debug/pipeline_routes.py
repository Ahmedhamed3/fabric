from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, JSONResponse

from app.utils.http_status import tail_ndjson

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
    aggregated: List[Dict[str, Any]] = []

    for source in PIPELINE_SOURCES:
        raw_path = _latest_raw_path(source.raw_base)
        if raw_path is None:
            continue
        ocsf_path, report_path = _resolve_output_paths(raw_path, source)

        raw_events = tail_ndjson(raw_path, safe_limit)
        reports = tail_ndjson(report_path, safe_limit) if report_path else []
        ocsf_events = tail_ndjson(ocsf_path, safe_limit) if ocsf_path else []

        report_by_dedupe, report_by_record = _index_reports(reports)
        ocsf_by_record = _index_ocsf_events(ocsf_events)

        for raw_event in raw_events:
            ids = raw_event.get("ids") or {}
            source_type = (raw_event.get("source") or {}).get("type") or source.name
            record_id = ids.get("record_id")
            dedupe_hash = ids.get("dedupe_hash")

            report = None
            if dedupe_hash:
                report = report_by_dedupe.get(dedupe_hash)
            if report is None and record_id is not None:
                report = report_by_record.get(str(record_id))

            ocsf_event = None
            if record_id is not None:
                ocsf_event = ocsf_by_record.get((source_type, str(record_id)))

            payload = {
                "time": _raw_event_time(raw_event),
                "source": source_type,
                "record_id": record_id,
                "class_uid": (ocsf_event or {}).get("class_uid"),
                "type_uid": (ocsf_event or {}).get("type_uid"),
                "validation_status": (report or {}).get("status"),
                "raw_event": _extract_raw_payload(raw_event),
                "raw_envelope": raw_event,
                "ocsf_event": ocsf_event,
                "validation_report": report,
            }
            aggregated.append(payload)

    aggregated.sort(key=lambda item: _parse_time(item.get("time")), reverse=True)
    if len(aggregated) > safe_limit:
        aggregated = aggregated[:safe_limit]
    message = None
    if not aggregated:
        message = "No pipeline events found. Ensure raw and OCSF outputs exist under out/raw and out/ocsf."
    return JSONResponse({"events": aggregated, "message": message})


def _latest_raw_path(base_dir: Path) -> Optional[Path]:
    if not base_dir.exists():
        return None
    candidates = list(base_dir.rglob("events.ndjson"))
    if not candidates:
        return None
    return max(candidates, key=lambda path: path.stat().st_mtime)


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


def _extract_raw_payload(raw_event: Dict[str, Any]) -> Any:
    raw = raw_event.get("raw") or {}
    if "data" in raw:
        return raw.get("data")
    if "xml" in raw:
        return raw.get("xml")
    return None


def _raw_event_time(raw_event: Dict[str, Any]) -> Optional[str]:
    time_block = (raw_event.get("event") or {}).get("time") or {}
    return time_block.get("observed_utc") or time_block.get("created_utc")


def _parse_time(value: Optional[str]) -> datetime:
    if not value:
        return datetime.min.replace(tzinfo=timezone.utc)
    text = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)
