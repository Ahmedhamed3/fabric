import json
from pathlib import Path
from typing import Any, List, Tuple


def detect_suricata_eve_json(file_path: str) -> bool:
    """
    Detect Suricata eve.json JSONL (one object per line).

    Returns True if at least one of the first few lines parses as JSON and
    contains an "event_type" key.
    """
    try:
        path = Path(file_path)
        if path.suffix.lower() not in [".json", ".jsonl", ".ndjson", ".log", ".txt"]:
            return False

        with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
            parsed = 0
            for line in f:
                if parsed >= 3:
                    break
                line = line.strip()
                if not line:
                    continue
                if not line.startswith("{"):
                    return False
                try:
                    ev: Any = json.loads(line)
                except Exception:
                    continue
                parsed += 1
                if isinstance(ev, dict) and "event_type" in ev:
                    return True
        return False
    except Exception:
        return False


def score_events(events: List[dict]) -> Tuple[float, str]:
    if not events:
        return 0.0, "No events provided for detection."

    total = 0
    alert_matches = 0
    event_type_matches = 0
    alert_block = 0
    for ev in events:
        if not isinstance(ev, dict):
            continue
        total += 1
        if "event_type" in ev:
            event_type_matches += 1
            if ev.get("event_type") == "alert":
                alert_matches += 1
        if isinstance(ev.get("alert"), dict):
            alert_block += 1

    if total == 0:
        return 0.0, "No JSON objects to score."

    score = alert_matches / total
    if alert_matches and alert_block:
        score = min(1.0, score + 0.2)

    reason = (
        f"Matched {alert_matches}/{total} events with event_type=alert "
        f"({event_type_matches} had event_type key)."
    )
    return score, reason
