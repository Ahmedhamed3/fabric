from __future__ import annotations

import copy
import hashlib
import importlib
import json
from dataclasses import dataclass
from typing import Any, Dict, Optional

from app.utils.timeutil import utc_now_iso


CANONICALIZATION_NAME = "rfc8785"
HASH_ALGORITHM = "SHA-256"


def canonicalize_json(value: Any) -> bytes:
    """
    Canonicalize JSON using RFC 8785-style rules (sorted keys, UTF-8, no whitespace).
    """
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def hash_sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _evidence_id(raw_envelope: Dict[str, Any]) -> Optional[str]:
    ids = raw_envelope.get("ids") or {}
    if ids.get("evidence_id"):
        return ids.get("evidence_id")
    return _generate_evidence_id(raw_envelope)


def _generate_uuidv7() -> Optional[str]:
    for module_name in ("uuid6", "uuid7"):
        if importlib.util.find_spec(module_name) is None:
            continue
        module = importlib.import_module(module_name)
        uuid7 = getattr(module, "uuid7", None)
        if uuid7:
            return f"uuidv7:{uuid7()}"
    return None


def _generate_evidence_id(raw_envelope: Dict[str, Any]) -> str:
    """
    Evidence identity is distinct from dedupe identity (restart safety).
    UUIDv7 is preferred for evidence_id because it is unique, time-ordered, and intentionally non-deterministic.
    If UUIDv7 is unavailable, fall back to a deterministic sha256 over collector + record + observed time.
    """
    uuid_v7 = _generate_uuidv7()
    if uuid_v7:
        return uuid_v7
    source = _raw_source(raw_envelope)
    collector = source.get("collector") or {}
    instance_id = collector.get("instance_id") or ""
    ids = raw_envelope.get("ids") or {}
    record_id = ids.get("record_id") or ""
    time_block = _time_block(raw_envelope)
    observed_utc = time_block.get("observed_utc") or ""
    payload = f"evidence|{instance_id}|{record_id}|{observed_utc}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def _time_block(raw_envelope: Dict[str, Any]) -> Dict[str, Any]:
    event = raw_envelope.get("event") or {}
    return event.get("time") or {}


def _raw_source(raw_envelope: Dict[str, Any]) -> Dict[str, Any]:
    source = raw_envelope.get("source")
    return source if isinstance(source, dict) else {}


@dataclass(frozen=True)
class EvidenceHashResult:
    raw_envelope: Dict[str, Any]
    ocsf_event: Dict[str, Any]
    evidence_commit: Dict[str, Any]


def compute_evidence_commit(
    raw_envelope: Dict[str, Any],
    ocsf_event: Dict[str, Any],
    *,
    ocsf_schema: Optional[str] = None,
    ocsf_version: Optional[str] = None,
    hashed_utc: Optional[str] = None,
    canonicalization: str = CANONICALIZATION_NAME,
    hash_alg: str = HASH_ALGORITHM,
    raw_hash_sha256: Optional[str] = None,
    raw_payload_hash_sha256: Optional[str] = None,
    ocsf_hash_sha256: Optional[str] = None,
    raw_size_bytes: Optional[int] = None,
    raw_payload_size_bytes: Optional[int] = None,
    raw_payload_format: Optional[str] = None,
) -> Dict[str, Any]:
    raw_bytes = canonicalize_json(raw_envelope)
    ocsf_bytes = canonicalize_json(ocsf_event)
    raw_hash = raw_hash_sha256 or hash_sha256_hex(raw_bytes)
    raw_payload_bytes, raw_format = _raw_payload_bytes(raw_envelope)
    raw_payload_hash = raw_payload_hash_sha256 or hash_sha256_hex(raw_payload_bytes)
    ocsf_hash = ocsf_hash_sha256 or hash_sha256_hex(ocsf_bytes)
    ids = raw_envelope.get("ids") or {}
    time_block = _time_block(raw_envelope)
    ocsf_schema_value = ocsf_schema or None
    ocsf_version_value = ocsf_version or (ocsf_event.get("metadata") or {}).get("version")
    raw_envelope_entry = {
        "hash_sha256": raw_hash,
        "size_bytes": raw_size_bytes if raw_size_bytes is not None else len(raw_bytes),
        "format": "json",
    }
    raw_payload_entry = {
        "hash_sha256": raw_payload_hash,
        "size_bytes": raw_payload_size_bytes if raw_payload_size_bytes is not None else len(raw_payload_bytes),
        "format": raw_payload_format or raw_format,
    }
    return {
        "commit_version": "1.0",
        "evidence_id": _evidence_id(raw_envelope),
        "source": _raw_source(raw_envelope),
        "timestamps": {
            "observed_utc": time_block.get("observed_utc"),
            "created_utc": time_block.get("created_utc"),
            "hashed_utc": hashed_utc or utc_now_iso(),
        },
        "raw": {
            "envelope": raw_envelope_entry,
            "payload": raw_payload_entry,
        },
        # Deprecated: raw.envelope supersedes raw_envelope; keep for UI backward compatibility.
        "raw_envelope": {**raw_envelope_entry, "deprecated": True},
        "ocsf": {
            "hash_sha256": ocsf_hash,
            "schema": ocsf_schema_value,
            "version": ocsf_version_value,
            "class_uid": ocsf_event.get("class_uid"),
            "type_uid": ocsf_event.get("type_uid"),
        },
        "linkage": {
            "record_id": ids.get("record_id"),
            "correlation_id": ids.get("correlation_id"),
            "dedupe_hash": ids.get("dedupe_hash"),
        },
        "integrity": {
            "canonicalization": canonicalization,
            "hash_alg": hash_alg,
        },
    }


def apply_evidence_hashing(
    raw_envelope: Dict[str, Any],
    ocsf_event: Dict[str, Any],
    *,
    ocsf_schema: Optional[str] = None,
    ocsf_version: Optional[str] = None,
    hashed_utc: Optional[str] = None,
) -> EvidenceHashResult:
    raw_copy = copy.deepcopy(raw_envelope)
    ocsf_copy = copy.deepcopy(ocsf_event)
    raw_ids = raw_copy.setdefault("ids", {})
    evidence_id = _evidence_id(raw_copy)
    raw_ids.setdefault("evidence_id", evidence_id)

    ocsf_hash = hash_sha256_hex(canonicalize_json(ocsf_copy))
    metadata = ocsf_copy.setdefault("metadata", {})
    metadata["uid"] = f"sha256:{ocsf_hash}"
    raw_copy.setdefault("derived", {})["ocsf_event_hash"] = ocsf_hash
    raw_copy["derived"]["ocsf_schema"] = ocsf_schema
    raw_copy["derived"]["ocsf_version"] = ocsf_version or (ocsf_copy.get("metadata") or {}).get("version")

    raw_payload_bytes, raw_payload_format = _raw_payload_bytes(raw_copy)
    raw_payload_hash = hash_sha256_hex(raw_payload_bytes)
    raw_bytes = canonicalize_json(raw_copy)
    raw_hash = hash_sha256_hex(raw_bytes)
    ids = raw_copy.get("ids") or {}
    ocsf_copy.setdefault("forensics", {})
    ocsf_copy["forensics"].update(
        {
            "evidence_id": evidence_id,
            "raw_envelope_hash": raw_hash,
            "raw_payload_hash": raw_payload_hash,
            "raw_record_id": ids.get("record_id"),
            "source": _raw_source(raw_copy),
        }
    )

    evidence_commit = compute_evidence_commit(
        raw_copy,
        ocsf_copy,
        ocsf_schema=ocsf_schema,
        ocsf_version=ocsf_version,
        hashed_utc=hashed_utc,
        raw_hash_sha256=raw_hash,
        raw_payload_hash_sha256=raw_payload_hash,
        ocsf_hash_sha256=ocsf_hash,
        raw_size_bytes=len(raw_bytes),
        raw_payload_size_bytes=len(raw_payload_bytes),
        raw_payload_format=raw_payload_format,
    )
    return EvidenceHashResult(
        raw_envelope=raw_copy,
        ocsf_event=ocsf_copy,
        evidence_commit=evidence_commit,
    )


def _raw_payload_bytes(raw_envelope: Dict[str, Any]) -> tuple[bytes, Optional[str]]:
    raw = raw_envelope.get("raw") or {}
    payload = raw.get("data")
    raw_format = raw.get("format")
    # Envelope hash covers the canonicalized JSON envelope; payload hash covers only the raw payload bytes/string.
    if payload is None:
        return b"", raw_format
    if isinstance(payload, bytes):
        return payload, raw_format
    if isinstance(payload, str):
        return payload.encode("utf-8"), raw_format
    return canonicalize_json(payload), raw_format or "json"
