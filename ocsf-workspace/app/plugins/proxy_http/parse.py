import json
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Iterator, Optional


@dataclass
class ProxyHttpNormalized:
    time: Optional[Any]
    client_ip: Optional[str]
    dst_ip: Optional[str]
    dst_host: Optional[str]
    method: Optional[str]
    url: Optional[str]
    status: Optional[int]
    bytes_in: Optional[int]
    bytes_out: Optional[int]
    user_agent: Optional[str]
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


def _extract_fields(ev: Dict[str, Any]) -> ProxyHttpNormalized:
    return ProxyHttpNormalized(
        time=ev.get("time") or ev.get("timestamp"),
        client_ip=_as_str(ev.get("client_ip") or ev.get("src_ip")),
        dst_ip=_as_str(ev.get("dst_ip")),
        dst_host=_as_str(ev.get("dst_host") or ev.get("host")),
        method=_as_str(ev.get("method")),
        url=_as_str(ev.get("url")),
        status=_safe_int(ev.get("status") or ev.get("status_code")),
        bytes_in=_safe_int(ev.get("bytes_in")),
        bytes_out=_safe_int(ev.get("bytes_out")),
        user_agent=_as_str(ev.get("user_agent")),
        original_event=dict(ev),
    )


def normalize_proxy_http_event(ev: Dict[str, Any]) -> ProxyHttpNormalized:
    return _extract_fields(ev)


def iter_proxy_http_events_from_events(
    events: Iterable[Dict[str, Any]],
) -> Iterator[ProxyHttpNormalized]:
    for ev in events:
        if isinstance(ev, dict):
            yield _extract_fields(ev)


def iter_proxy_http_events(file_path: str) -> Iterator[ProxyHttpNormalized]:
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
