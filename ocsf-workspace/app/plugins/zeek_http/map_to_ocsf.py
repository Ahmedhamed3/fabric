from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.ocsf.constants import (
    CATEGORY_UID_NETWORK,
    HTTP_ACTIVITY_CLASS_UID,
    HTTP_ACTIVITY_REQUEST_ID,
    calc_type_uid,
)
from app.plugins.zeek_http.parse import ZeekHttpNormalized


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


def _build_url(host: Optional[str], uri: Optional[str]) -> Optional[str]:
    if uri:
        lower = uri.lower()
        if lower.startswith("http://") or lower.startswith("https://"):
            return uri
        if "://" in lower:
            return uri
    if host:
        if uri:
            if uri.startswith("/"):
                path = uri
            else:
                path = f"/{uri}"
            return f"http://{host}{path}"
        return f"http://{host}"
    return uri


def map_zeek_http_to_ocsf(ev: ZeekHttpNormalized) -> Dict[str, Any]:
    type_uid = calc_type_uid(HTTP_ACTIVITY_CLASS_UID, HTTP_ACTIVITY_REQUEST_ID)

    http: Dict[str, Any] = {}
    if ev.method:
        http["method"] = ev.method
    url = _build_url(ev.host, ev.uri)
    if url:
        http["url"] = url
    if ev.status_code is not None:
        http["status_code"] = ev.status_code
    if ev.user_agent:
        http["user_agent"] = ev.user_agent
    if ev.request_body_len is not None:
        http["bytes_out"] = ev.request_body_len
    if ev.response_body_len is not None:
        http["bytes_in"] = ev.response_body_len

    network: Dict[str, Any] = {}
    if ev.id_orig_h or ev.id_orig_p is not None:
        src: Dict[str, Any] = {}
        if ev.id_orig_h:
            src["ip"] = ev.id_orig_h
        if ev.id_orig_p is not None:
            src["port"] = ev.id_orig_p
        network["src_endpoint"] = src
    if ev.id_resp_h or ev.id_resp_p is not None:
        dst: Dict[str, Any] = {}
        if ev.id_resp_h:
            dst["ip"] = ev.id_resp_h
        if ev.id_resp_p is not None:
            dst["port"] = ev.id_resp_p
        network["dst_endpoint"] = dst

    ocsf_event: Dict[str, Any] = {
        "activity_id": HTTP_ACTIVITY_REQUEST_ID,
        "category_uid": CATEGORY_UID_NETWORK,
        "class_uid": HTTP_ACTIVITY_CLASS_UID,
        "type_uid": type_uid,
        "time": _to_iso8601_utc(ev.ts),
        "metadata": {"product": "Zeek"},
        "unmapped": {"original_event": ev.original_event},
    }

    if http:
        ocsf_event["http"] = http
    if network:
        ocsf_event["network"] = network

    return ocsf_event
