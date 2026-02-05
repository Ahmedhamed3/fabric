from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.ocsf.constants import (
    DEFAULT_SEVERITY_ID,
    SECURITY_FINDING_ACTIVITY_ALERT_ID,
    SECURITY_FINDING_CLASS_UID,
    calc_type_uid,
)
from app.plugins.suricata.parse import SuricataAlertNormalized


def _to_iso8601_utc(ts: Optional[Any]) -> str:
    if ts is None:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(ts, str):
        normalized = ts.replace("Z", "+00:00")
        if normalized.endswith("+0000"):
            normalized = f"{normalized[:-5]}+00:00"
        try:
            dt = datetime.fromisoformat(normalized)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except Exception:
            return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _map_severity_id(severity: Optional[int]) -> int:
    if severity is None:
        return DEFAULT_SEVERITY_ID
    try:
        if severity <= 0:
            return DEFAULT_SEVERITY_ID
        return int(severity)
    except Exception:
        return DEFAULT_SEVERITY_ID


def map_suricata_alert_to_ocsf(ev: SuricataAlertNormalized) -> Dict[str, Any]:
    type_uid = calc_type_uid(SECURITY_FINDING_CLASS_UID, SECURITY_FINDING_ACTIVITY_ALERT_ID)

    finding: Dict[str, Any] = {
        "title": ev.signature or "Suricata alert",
    }
    if ev.category:
        finding["category"] = ev.category

    src_endpoint: Dict[str, Any] = {}
    if ev.src_ip:
        src_endpoint["ip"] = ev.src_ip
    if ev.src_port is not None:
        src_endpoint["port"] = ev.src_port

    dst_endpoint: Dict[str, Any] = {}
    if ev.dest_ip:
        dst_endpoint["ip"] = ev.dest_ip
    if ev.dest_port is not None:
        dst_endpoint["port"] = ev.dest_port

    network: Dict[str, Any] = {}
    if ev.proto:
        network["transport"] = ev.proto

    unmapped: Dict[str, Any] = {"original_event": ev.original_event}
    if ev.flow_id is not None:
        unmapped["flow_id"] = ev.flow_id

    ocsf_event: Dict[str, Any] = {
        "activity_id": SECURITY_FINDING_ACTIVITY_ALERT_ID,
        "class_uid": SECURITY_FINDING_CLASS_UID,
        "type_uid": type_uid,
        "time": _to_iso8601_utc(ev.timestamp),
        "severity_id": _map_severity_id(ev.severity),
        "metadata": {
            "product": "Suricata",
        },
        "finding": finding,
        "unmapped": unmapped,
    }

    if src_endpoint:
        ocsf_event["src_endpoint"] = src_endpoint
    if dst_endpoint:
        ocsf_event["dst_endpoint"] = dst_endpoint
    if network:
        ocsf_event["network"] = network

    return ocsf_event
