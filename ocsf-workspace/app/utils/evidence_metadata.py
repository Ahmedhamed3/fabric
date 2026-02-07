from __future__ import annotations

import json
import logging
import os
import threading
import urllib.request
from typing import Any, Dict


logger = logging.getLogger(__name__)


def _resolve_events_url(base_url: str) -> str:
    clean = base_url.strip().rstrip("/")
    if not clean:
        return ""
    if clean.endswith("/api/v1/evidence/events"):
        return clean
    return f"{clean}/api/v1/evidence/events"


def _build_metadata(evidence_commit: Dict[str, Any]) -> Dict[str, Any]:
    source = evidence_commit.get("source") or {}
    timestamps = evidence_commit.get("timestamps") or {}
    ocsf = evidence_commit.get("ocsf") or {}
    raw = evidence_commit.get("raw") or {}
    linkage = evidence_commit.get("linkage") or {}
    raw_envelope = raw.get("envelope") or {}
    raw_payload = raw.get("payload") or {}
    return {
        "evidence_id": evidence_commit.get("evidence_id"),
        "source": {
            "type": source.get("type"),
            "vendor": source.get("vendor"),
            "product": source.get("product"),
            "channel": source.get("channel"),
        },
        "timestamps": {
            "observed_utc": timestamps.get("observed_utc"),
        },
        "ocsf": {
            "class_uid": ocsf.get("class_uid"),
            "type_uid": ocsf.get("type_uid"),
        },
        "hashes": {
            "raw_envelope_hash": raw_envelope.get("hash_sha256"),
            "raw_payload_hash": raw_payload.get("hash_sha256"),
            "ocsf_hash": ocsf.get("hash_sha256"),
        },
        "linkage": {
            "record_id": linkage.get("record_id"),
            "dedupe_hash": linkage.get("dedupe_hash"),
        },
    }


def _post_metadata_sync(metadata: Dict[str, Any], evidence_api_url: str) -> None:
    request = urllib.request.Request(
        evidence_api_url,
        data=json.dumps(metadata).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10):
        return None


def emit_evidence_metadata(evidence_commit: Dict[str, Any]) -> None:
    evidence_api_url = _resolve_events_url(os.getenv("EVIDENCE_API_URL", ""))
    if not evidence_api_url:
        return
    metadata = _build_metadata(evidence_commit)
    evidence_id = metadata.get("evidence_id") or "unknown"
    source_type = (metadata.get("source") or {}).get("type") or "unknown"

    def _worker() -> None:
        try:
            _post_metadata_sync(metadata, evidence_api_url)
            logger.info("[EVIDENCE-META] emitted evidence_id=%s source=%s", evidence_id, source_type)
        except Exception as exc:
            logger.warning("[EVIDENCE-META] failed emit evidence_id=%s: %s", evidence_id, exc)

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()
