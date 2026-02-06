from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_utc(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def floor_to_window(value: datetime, window_minutes: int) -> datetime:
    minute = (value.minute // window_minutes) * window_minutes
    return value.replace(minute=minute, second=0, microsecond=0)


def canonical_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass
class BundleFlushResult:
    bundle_id: str
    raw_ndjson: str
    ocsf_ndjson: str
    manifest: Dict[str, Any]


class TimeWindowBundler:
    def __init__(self, window_minutes: int = 5) -> None:
        self.window_minutes = window_minutes
        self._windows: Dict[Tuple[str, str, datetime], Dict[str, Any]] = {}

    def add_event(
        self,
        *,
        raw_envelope: Dict[str, Any],
        ocsf_event: Dict[str, Any],
        source: Dict[str, Any],
        event_time_utc: Optional[str] = None,
    ) -> None:
        host = str(source.get("host") or "unknown-host")
        source_type = str(source.get("type") or "unknown-source")
        event_time = parse_utc(event_time_utc) or parse_utc(ocsf_event.get("time")) or utc_now()
        window_start = floor_to_window(event_time, self.window_minutes)
        key = (host, source_type, window_start)

        if key not in self._windows:
            self._windows[key] = {
                "raw": [],
                "ocsf": [],
                "class_uid_counts": {},
                "source": source,
                "window_start": window_start,
                "window_end": window_start + timedelta(minutes=self.window_minutes),
            }

        slot = self._windows[key]
        slot["raw"].append(raw_envelope)
        slot["ocsf"].append(ocsf_event)
        class_uid = str(ocsf_event.get("class_uid") or "unknown")
        slot["class_uid_counts"][class_uid] = slot["class_uid_counts"].get(class_uid, 0) + 1

    def flush_ready(self, now: Optional[datetime] = None) -> List[BundleFlushResult]:
        current = now or utc_now()
        ready_keys = [key for key, value in self._windows.items() if value["window_end"] <= current]
        ready_keys.sort(key=lambda item: item[2])

        output: List[BundleFlushResult] = []
        for key in ready_keys:
            slot = self._windows.pop(key)
            output.append(self._build_bundle(slot))
        return output

    def _build_bundle(self, slot: Dict[str, Any]) -> BundleFlushResult:
        raw_ndjson = "\n".join(canonical_json(row) for row in slot["raw"]) + "\n"
        ocsf_ndjson = "\n".join(canonical_json(row) for row in slot["ocsf"]) + "\n"
        source = slot["source"]
        start_utc = utc_iso(slot["window_start"])
        end_utc = utc_iso(slot["window_end"])
        ocsf_hash = sha256_hex(ocsf_ndjson)
        bundle_id = sha256_hex("".join([
            str(source.get("host") or "unknown-host"),
            str(source.get("type") or "unknown-source"),
            start_utc,
            end_utc,
            ocsf_hash,
        ]))

        manifest = {
            "bundle_id": bundle_id,
            "bundle_type": "ocsf_log_bundle",
            "time_window": {
                "start_utc": start_utc,
                "end_utc": end_utc,
            },
            "event_count": len(slot["ocsf"]),
            "source": {
                "type": source.get("type"),
                "vendor": source.get("vendor"),
                "product": source.get("product"),
                "channel": source.get("channel"),
                "host": source.get("host"),
                "collector": {
                    "name": (source.get("collector") or {}).get("name"),
                    "instance_id": (source.get("collector") or {}).get("instance_id"),
                },
            },
            "ocsf": {
                "version": source.get("ocsf_version"),
                "class_uid_counts": slot["class_uid_counts"],
            },
            "hashes": {
                "raw_bundle": {
                    "sha256": sha256_hex(raw_ndjson),
                    "size_bytes": len(raw_ndjson.encode("utf-8")),
                },
                "ocsf_bundle": {
                    "sha256": ocsf_hash,
                    "size_bytes": len(ocsf_ndjson.encode("utf-8")),
                },
            },
            "storage": {
                "raw_ref": f"local://bundles/{bundle_id}/raw.ndjson",
                "ocsf_ref": f"local://bundles/{bundle_id}/ocsf.ndjson",
            },
            "integrity": {
                "hash_algorithm": "SHA-256",
                "canonicalization": "rfc8785",
                "bundle_strategy": "time_window_5m",
                "created_utc": utc_iso(utc_now()),
            },
        }

        return BundleFlushResult(
            bundle_id=bundle_id,
            raw_ndjson=raw_ndjson,
            ocsf_ndjson=ocsf_ndjson,
            manifest=manifest,
        )
