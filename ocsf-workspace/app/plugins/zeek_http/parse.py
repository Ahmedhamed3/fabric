import json
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Iterator, Optional


@dataclass
class ZeekHttpNormalized:
    ts: Optional[Any]
    method: Optional[str]
    host: Optional[str]
    uri: Optional[str]
    status_code: Optional[int]
    user_agent: Optional[str]
    request_body_len: Optional[int]
    response_body_len: Optional[int]
    id_orig_h: Optional[str]
    id_resp_h: Optional[str]
    id_orig_p: Optional[int]
    id_resp_p: Optional[int]
    original_event: Dict[str, Any]


def _safe_int(value: Any) -> Optional[int]:
    try:
        if value is None:
            return None
        return int(value)
    except Exception:
        return None


def _as_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    try:
        return str(value)
    except Exception:
        return None


def _extract_fields(ev: Dict[str, Any]) -> ZeekHttpNormalized:
    return ZeekHttpNormalized(
        ts=ev.get("ts"),
        method=_as_str(ev.get("method")),
        host=_as_str(ev.get("host")),
        uri=_as_str(ev.get("uri")),
        status_code=_safe_int(ev.get("status_code")),
        user_agent=_as_str(ev.get("user_agent")),
        request_body_len=_safe_int(ev.get("request_body_len")),
        response_body_len=_safe_int(ev.get("response_body_len")),
        id_orig_h=_as_str(ev.get("id.orig_h")),
        id_resp_h=_as_str(ev.get("id.resp_h")),
        id_orig_p=_safe_int(ev.get("id.orig_p")),
        id_resp_p=_safe_int(ev.get("id.resp_p")),
        original_event=dict(ev),
    )


def normalize_zeek_http_event(ev: Dict[str, Any]) -> ZeekHttpNormalized:
    return _extract_fields(ev)


def iter_zeek_http_events_from_events(
    events: Iterable[Dict[str, Any]],
) -> Iterator[ZeekHttpNormalized]:
    for ev in events:
        if isinstance(ev, dict):
            yield _extract_fields(ev)


def iter_zeek_http_events(file_path: str) -> Iterator[ZeekHttpNormalized]:
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
            if isinstance(ev, dict):
                yield _extract_fields(ev)
