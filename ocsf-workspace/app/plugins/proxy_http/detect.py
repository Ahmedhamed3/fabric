from typing import Any, List, Tuple


def _looks_like_proxy_http(ev: Any) -> bool:
    if not isinstance(ev, dict):
        return False
    has_url = "url" in ev
    has_method = "method" in ev
    has_status = "status" in ev or "status_code" in ev
    has_client = "client_ip" in ev or "src_ip" in ev
    has_bytes = any(key in ev for key in ("bytes_in", "bytes_out"))
    has_ua = "user_agent" in ev

    primary_match = has_url and has_method and (has_status or has_client)
    secondary_match = has_client and has_url and (has_bytes or has_ua)
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
        if _looks_like_proxy_http(ev):
            matched += 1

    if total == 0:
        return 0.0, "No JSON objects to score."

    score = matched / total
    reason = f"Matched {matched}/{total} events with proxy HTTP fields."
    return score, reason
