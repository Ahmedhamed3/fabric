import json
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Iterator, List, Optional


@dataclass
class ZeekDNSNormalized:
    ts: Optional[Any]
    uid: Optional[str]
    id_orig_h: Optional[str]
    id_resp_h: Optional[str]
    proto: Optional[str]
    query: Optional[str]
    answers: Optional[List[str]]
    rcode: Optional[int]
    rcode_name: Optional[str]
    original_event: Dict[str, Any]


def _normalize_answers(value: Any) -> Optional[List[str]]:
    if value is None:
        return None
    if isinstance(value, list):
        return [str(item) for item in value if item is not None]
    if isinstance(value, str):
        return [value]
    return [str(value)]


def _safe_int(value: Any) -> Optional[int]:
    try:
        if value is None:
            return None
        return int(value)
    except Exception:
        return None


def _extract_fields(ev: Dict[str, Any]) -> ZeekDNSNormalized:
    ts = ev.get("ts")
    uid = ev.get("uid")
    id_orig_h = ev.get("id.orig_h")
    id_resp_h = ev.get("id.resp_h")
    proto = ev.get("proto")
    query = ev.get("query")
    answers = _normalize_answers(ev.get("answers"))
    rcode = _safe_int(ev.get("rcode"))
    rcode_name = ev.get("rcode_name")

    return ZeekDNSNormalized(
        ts=ts,
        uid=str(uid) if uid is not None else None,
        id_orig_h=str(id_orig_h) if id_orig_h is not None else None,
        id_resp_h=str(id_resp_h) if id_resp_h is not None else None,
        proto=str(proto) if proto is not None else None,
        query=str(query) if query is not None else None,
        answers=answers,
        rcode=rcode,
        rcode_name=str(rcode_name) if rcode_name is not None else None,
        original_event=dict(ev),
    )


def normalize_zeek_dns_event(ev: Dict[str, Any]) -> ZeekDNSNormalized:
    return _extract_fields(ev)


def iter_zeek_dns_events_from_events(
    events: Iterable[Dict[str, Any]],
) -> Iterator[ZeekDNSNormalized]:
    for ev in events:
        if isinstance(ev, dict):
            yield _extract_fields(ev)


def iter_zeek_dns_events(file_path: str) -> Iterator[ZeekDNSNormalized]:
    """
    Yield normalized Zeek DNS events from JSONL.
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
            if isinstance(ev, dict):
                yield _extract_fields(ev)
