from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
import urllib.parse
import urllib.request

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from app.utils.evidence_metadata import resolve_evidence_api_url

logger = logging.getLogger(__name__)

router = APIRouter()

EVIDENCE_EVENTS_PATH = "/api/v1/evidence/events"
ARTIFACT_RAW_BASE = Path("out/raw")
ARTIFACT_ENVELOPE_BASE = Path("out/envelope")
ARTIFACT_OCSF_BASE = Path("out/ocsf")
ARTIFACT_VALIDATION_BASE = Path("out/validation")


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

    # 🔴 FIX: Evidence API returns metadata under "items"
    raw_items = payload.get("items", []) if isinstance(payload, dict) else []
    events = _coerce_events(raw_items)

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

    raw_event = _read_artifact(ARTIFACT_RAW_BASE, evidence_id)
    envelope_event = _read_artifact(ARTIFACT_ENVELOPE_BASE, evidence_id)
    ocsf_event = _read_artifact(ARTIFACT_OCSF_BASE, evidence_id)
    validation_event = _read_artifact(ARTIFACT_VALIDATION_BASE, evidence_id)

    return JSONResponse(
        {
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


def _coerce_events(items: Any) -> List[Dict[str, Any]]:
    """
    Accepts Evidence API 'items' and returns UI-safe event dicts.
    No filtering. No validation. No inference.
    """
    if not isinstance(items, list):
        return []
    return [event for event in items if isinstance(event, dict)]


def _read_artifact(base_dir: Path, evidence_id: str) -> Optional[Dict[str, Any]]:
    path = base_dir / f"{evidence_id}.json"
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    if isinstance(payload, dict):
        return payload
    return None
