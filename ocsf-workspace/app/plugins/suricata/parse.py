import json
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Iterator, Optional


@dataclass
class SuricataAlertNormalized:
    timestamp: Optional[Any]
    src_ip: Optional[str]
    src_port: Optional[int]
    dest_ip: Optional[str]
    dest_port: Optional[int]
    proto: Optional[str]
    signature: Optional[str]
    category: Optional[str]
    severity: Optional[int]
    flow_id: Optional[int]
    original_event: Dict[str, Any]


def _safe_int(value: Any) -> Optional[int]:
    try:
        if value is None:
            return None
        return int(value)
    except Exception:
        return None


def _extract_fields(ev: Dict[str, Any]) -> SuricataAlertNormalized:
    alert = ev.get("alert") if isinstance(ev.get("alert"), dict) else {}

    timestamp = ev.get("timestamp") or ev.get("time")
    src_ip = ev.get("src_ip")
    src_port = _safe_int(ev.get("src_port"))
    dest_ip = ev.get("dest_ip") or ev.get("dst_ip")
    dest_port = _safe_int(ev.get("dest_port") or ev.get("dst_port"))
    proto = ev.get("proto") or ev.get("protocol")

    signature = alert.get("signature") if isinstance(alert, dict) else None
    category = alert.get("category") if isinstance(alert, dict) else None
    severity = _safe_int(alert.get("severity") if isinstance(alert, dict) else None)

    flow_id = _safe_int(ev.get("flow_id"))

    return SuricataAlertNormalized(
        timestamp=timestamp,
        src_ip=str(src_ip) if src_ip is not None else None,
        src_port=src_port,
        dest_ip=str(dest_ip) if dest_ip is not None else None,
        dest_port=dest_port,
        proto=str(proto) if proto is not None else None,
        signature=str(signature) if signature is not None else None,
        category=str(category) if category is not None else None,
        severity=severity,
        flow_id=flow_id,
        original_event=dict(ev),
    )


def normalize_suricata_event(ev: Dict[str, Any]) -> SuricataAlertNormalized:
    return _extract_fields(ev)


def iter_suricata_events_from_events(
    events: Iterable[Dict[str, Any]],
) -> Iterator[SuricataAlertNormalized]:
    for ev in events:
        if not isinstance(ev, dict):
            continue
        if ev.get("event_type") != "alert":
            continue
        yield _extract_fields(ev)


def iter_suricata_events(file_path: str) -> Iterator[SuricataAlertNormalized]:
    """
    Yield Suricata alert events from eve.json JSONL.
    """
    with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if not line.startswith("{"):
                continue
            try:
                ev = json.loads(line)
            except Exception:
                continue
            if not isinstance(ev, dict):
                continue
            if ev.get("event_type") != "alert":
                continue
            yield _extract_fields(ev)
