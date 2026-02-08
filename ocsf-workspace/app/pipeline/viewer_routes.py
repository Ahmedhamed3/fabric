from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
import urllib.parse
import urllib.request

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from app.utils.evidence_metadata import resolve_evidence_api_url

logger = logging.getLogger(__name__)

router = APIRouter()

EVIDENCE_EVENTS_PATH = "/api/v1/evidence/events"


@dataclass(frozen=True)
class PipelineArtifactSource:
    name: str
    raw_base: Path
    envelope_base: Path
    ocsf_base: Path
    validation_base: Path


PIPELINE_SOURCES = [
    PipelineArtifactSource(
        name="sysmon",
        raw_base=Path("out/raw/endpoint/windows_sysmon"),
        envelope_base=Path("out/envelope/endpoint/windows_sysmon"),
        ocsf_base=Path("out/ocsf/endpoint/windows_sysmon"),
        validation_base=Path("out/validation/endpoint/windows_sysmon"),
    ),
    PipelineArtifactSource(
        name="windows-security",
        raw_base=Path("out/raw/endpoint/windows_security"),
        envelope_base=Path("out/envelope/endpoint/windows_security"),
        ocsf_base=Path("out/ocsf/endpoint/windows_security"),
        validation_base=Path("out/validation/endpoint/windows_security"),
    ),
    PipelineArtifactSource(
        name="elastic",
        raw_base=Path("out/raw/siem/elastic"),
        envelope_base=Path("out/envelope/siem/elastic"),
        ocsf_base=Path("out/ocsf/siem/elastic"),
        validation_base=Path("out/validation/siem/elastic"),
    ),
]


@router.get("/api/pipeline/viewer/metadata")
def pipeline_viewer_metadata(limit: int = 50) -> JSONResponse:
    safe_limit = max(1, min(limit, 200))
    base_url = resolve_evidence_api_url()
    events_url = _resolve_events_url(base_url)
    if not events_url:
        return JSONResponse({"events": [], "message": "Evidence API URL is not configured."})

    url = f"{events_url}?{urllib.parse.urlencode({'limit': safe_limit})}"
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        logger.warning("[PIPELINE] Evidence metadata fetch failed: %s", exc)
        return JSONResponse(
            {
                "events": [],
                "message": f"Unable to reach Evidence API at {events_url}.",
                "evidence_api_url": base_url,
            }
        )

    events = _coerce_events(payload)
    message = None
    if isinstance(payload, dict):
        message = payload.get("message")
    if not message and not events:
        message = "No evidence metadata found. Ensure the pipeline emitted events."
    return JSONResponse(
        {
            "events": events,
            "message": message,
            "evidence_api_url": base_url,
        }
    )


@router.get("/api/pipeline/viewer/lookup")
def pipeline_viewer_lookup(evidence_id: str) -> JSONResponse:
    evidence_id = (evidence_id or "").strip()
    if not evidence_id:
        raise HTTPException(status_code=400, detail="evidence_id is required")

    raw_event = _scan_artifacts(_raw_dirs(), evidence_id)
    envelope_event = _scan_artifacts(_envelope_dirs(), evidence_id)
    ocsf_event = _scan_artifacts(_ocsf_dirs(), evidence_id)
    validation_event = _scan_artifacts(_validation_dirs(), evidence_id)

    return JSONResponse(
        {
            "evidence_id": evidence_id,
            "raw": raw_event,
            "envelope": envelope_event,
            "ocsf": ocsf_event,
            "validation": validation_event,
        }
    )


def _resolve_events_url(base_url: str) -> str:
    clean = base_url.strip().rstrip("/")
    if not clean:
        return ""
    if clean.endswith(EVIDENCE_EVENTS_PATH):
        return clean
    return f"{clean}{EVIDENCE_EVENTS_PATH}"


def _coerce_events(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        return [event for event in payload if isinstance(event, dict)]
    if isinstance(payload, dict):
        events = payload.get("events")
        if isinstance(events, list):
            return [event for event in events if isinstance(event, dict)]
    return []


def _raw_dirs() -> List[Path]:
    return [source.raw_base for source in PIPELINE_SOURCES]


def _envelope_dirs() -> List[Path]:
    return [source.envelope_base for source in PIPELINE_SOURCES]


def _ocsf_dirs() -> List[Path]:
    return [source.ocsf_base for source in PIPELINE_SOURCES]


def _validation_dirs() -> List[Path]:
    return [source.validation_base for source in PIPELINE_SOURCES]


def _scan_artifacts(directories: Iterable[Path], evidence_id: str) -> Optional[Dict[str, Any]]:
    normalized = str(evidence_id)
    found = None
    for base_dir in directories:
        for path in _list_ndjson_paths(base_dir):
            for event in _read_ndjson(path):
                extracted = _extract_evidence_id(event)
                if extracted is None:
                    continue
                if str(extracted) == normalized:
                    found = event
    return found


def _list_ndjson_paths(base_dir: Path) -> List[Path]:
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
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                yield payload


def _extract_evidence_id(event: Dict[str, Any]) -> Optional[str]:
    if not isinstance(event, dict):
        return None
    direct = event.get("evidence_id")
    if direct:
        return str(direct)
    ids = event.get("ids") or {}
    if ids.get("evidence_id"):
        return str(ids.get("evidence_id"))
    forensics = event.get("forensics") or {}
    if forensics.get("evidence_id"):
        return str(forensics.get("evidence_id"))
    evidence_commit = event.get("evidence_commit") or {}
    if evidence_commit.get("evidence_id"):
        return str(evidence_commit.get("evidence_id"))
    raw = event.get("raw") or {}
    if isinstance(raw, dict):
        raw_ids = raw.get("ids") or {}
        if raw_ids.get("evidence_id"):
            return str(raw_ids.get("evidence_id"))
    return None
