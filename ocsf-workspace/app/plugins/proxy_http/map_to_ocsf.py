from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.ocsf.constants import (
    CATEGORY_UID_NETWORK,
    HTTP_ACTIVITY_CLASS_UID,
    HTTP_ACTIVITY_REQUEST_ID,
    calc_type_uid,
)
from app.plugins.proxy_http.parse import ProxyHttpNormalized


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


def map_proxy_http_to_ocsf(ev: ProxyHttpNormalized) -> Dict[str, Any]:
    type_uid = calc_type_uid(HTTP_ACTIVITY_CLASS_UID, HTTP_ACTIVITY_REQUEST_ID)

    http: Dict[str, Any] = {}
    if ev.method:
        http["method"] = ev.method
    if ev.url:
        http["url"] = ev.url
    if ev.status is not None:
        http["status_code"] = ev.status
    if ev.user_agent:
        http["user_agent"] = ev.user_agent
    if ev.bytes_in is not None:
        http["bytes_in"] = ev.bytes_in
    if ev.bytes_out is not None:
        http["bytes_out"] = ev.bytes_out

    network: Dict[str, Any] = {}
    if ev.client_ip:
        network["src_endpoint"] = {"ip": ev.client_ip}
    if ev.dst_ip or ev.dst_host:
        dst: Dict[str, Any] = {}
        if ev.dst_ip:
            dst["ip"] = ev.dst_ip
        if ev.dst_host:
            dst["hostname"] = ev.dst_host
        network["dst_endpoint"] = dst

    ocsf_event: Dict[str, Any] = {
        "activity_id": HTTP_ACTIVITY_REQUEST_ID,
        "category_uid": CATEGORY_UID_NETWORK,
        "class_uid": HTTP_ACTIVITY_CLASS_UID,
        "type_uid": type_uid,
        "time": _to_iso8601_utc(ev.time),
        "metadata": {"product": "Proxy"},
        "unmapped": {"original_event": ev.original_event},
    }

    if http:
        ocsf_event["http"] = http
    if network:
        ocsf_event["network"] = network

    return ocsf_event
