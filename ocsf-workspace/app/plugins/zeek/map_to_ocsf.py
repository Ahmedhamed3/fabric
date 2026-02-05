from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.ocsf.constants import calc_type_uid
from app.plugins.zeek.parse import ZeekDNSNormalized

DNS_ACTIVITY_CLASS_UID = 1006
DNS_ACTIVITY_QUERY_ID = 1


def _to_iso8601_utc(ts: Optional[Any]) -> str:
    if ts is None:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(ts, str):
        try:
            return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat().replace("+00:00", "Z")
        except Exception:
            pass
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except Exception:
            return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def map_zeek_dns_to_ocsf(ev: ZeekDNSNormalized) -> Dict[str, Any]:
    type_uid = calc_type_uid(DNS_ACTIVITY_CLASS_UID, DNS_ACTIVITY_QUERY_ID)

    dns: Dict[str, Any] = {}
    if ev.query:
        dns["question"] = {"name": ev.query}
    if ev.answers:
        dns["answers"] = [{"data": answer} for answer in ev.answers]

    ocsf_event: Dict[str, Any] = {
        "activity_id": DNS_ACTIVITY_QUERY_ID,
        "class_uid": DNS_ACTIVITY_CLASS_UID,
        "type_uid": type_uid,
        "time": _to_iso8601_utc(ev.ts),
        "metadata": {"product": "Zeek"},
        "unmapped": {"original_event": ev.original_event},
    }

    if dns:
        ocsf_event["dns"] = dns
    if ev.id_orig_h:
        ocsf_event["src_endpoint"] = {"ip": ev.id_orig_h}
    if ev.id_resp_h:
        ocsf_event["dst_endpoint"] = {"ip": ev.id_resp_h}

    return ocsf_event
