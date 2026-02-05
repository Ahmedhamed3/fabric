import json
from pathlib import Path
from typing import Any, List, Tuple


def detect_zeek_dns_json(file_path: str) -> bool:
    """
    Detect Zeek DNS JSONL by looking for common DNS keys.
    """
    def _looks_like_dns(ev: Any) -> bool:
        return (
            isinstance(ev, dict)
            and "query" in ev
            and ("id.orig_h" in ev or "rcode_name" in ev)
        )

    try:
        p = Path(file_path)
        if p.suffix.lower() not in [".json", ".jsonl", ".ndjson", ".log", ".txt"]:
            return False

        checked = 0
        matched = 0
        with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
            for line in f:
                if checked >= 10:
                    break
                line = line.strip()
                if not line:
                    continue
                if not line.startswith("{"):
                    continue
                checked += 1
                try:
                    ev = json.loads(line)
                except Exception:
                    continue
                if _looks_like_dns(ev):
                    matched += 1
                    if matched >= 2:
                        return True
        return matched > 0
    except Exception:
        return False


def score_events(events: List[dict]) -> Tuple[float, str]:
    if not events:
        return 0.0, "No events provided for detection."

    total = 0
    matched = 0
    for ev in events:
        if not isinstance(ev, dict):
            continue
        total += 1
        has_query = "query" in ev
        has_hosts = any(key in ev for key in ("id.orig_h", "id.resp_h"))
        has_rcode = "rcode_name" in ev or "rcode" in ev
        if has_query and (has_hosts or has_rcode):
            matched += 1

    if total == 0:
        return 0.0, "No JSON objects to score."

    score = matched / total
    reason = f"Matched {matched}/{total} events with Zeek DNS fields."
    return score, reason
