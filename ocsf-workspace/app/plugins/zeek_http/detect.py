from typing import Any, List, Tuple


def _looks_like_zeek_http(ev: Any) -> bool:
    if not isinstance(ev, dict):
        return False
    has_method = "method" in ev
    has_host = "host" in ev
    has_uri = "uri" in ev
    has_src_dst = any(key in ev for key in ("id.orig_h", "id.resp_h"))
    has_ts = "ts" in ev
    has_status = "status_code" in ev
    has_ua = "user_agent" in ev
    has_sizes = any(key in ev for key in ("request_body_len", "response_body_len"))

    primary_match = has_method and has_host and has_uri and has_src_dst
    secondary_match = has_ts and has_src_dst and (has_status or has_ua or has_sizes)
    return primary_match or secondary_match


def score_events(events: List[dict]) -> Tuple[float, str]:
    if not events:
        return 0.0, "No events provided for detection."

    total = 0
    matched = 0
    for ev in events:
        if not isinstance(ev, dict):
            continue
        total += 1
        if _looks_like_zeek_http(ev):
            matched += 1

    if total == 0:
        return 0.0, "No JSON objects to score."

    score = matched / total
    reason = f"Matched {matched}/{total} events with Zeek HTTP fields."
    return score, reason
