import json
from pathlib import Path
from typing import Any, Iterable, List, Tuple

def detect_sysmon_json(file_path: str) -> bool:
    """
    Detects Sysmon JSON (array or JSONL) by looking for typical keys.
    """
    def _has_event_id(ev: Any) -> bool:
        return isinstance(ev, dict) and any(key in ev for key in ("EventID", "EventId", "event_id"))

    def _events_from_wrapper(obj: Any) -> Iterable[Any]:
        if isinstance(obj, dict):
            events = obj.get("Events") or obj.get("events")
            if isinstance(events, list):
                return events
        return []

    try:
        p = Path(file_path)
        if p.suffix.lower() not in [".json", ".jsonl", ".ndjson", ".log", ".txt"]:
            return False

        with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
            first = ""
            for line in f:
                line = line.strip()
                if line:
                    first = line
                    break

        if not first:
            return False

        if first.startswith("["):
            try:
                with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    return any(_has_event_id(ev) for ev in data)
                if isinstance(data, dict):
                    return any(_has_event_id(ev) for ev in _events_from_wrapper(data))
                return False
            except Exception:
                return False

        if first.startswith("{"):
            try:
                with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    if _has_event_id(data):
                        return True
                    return any(_has_event_id(ev) for ev in _events_from_wrapper(data))
                if isinstance(data, list):
                    return any(_has_event_id(ev) for ev in data)
                return False
            except Exception:
                pass

            try:
                with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or not line.startswith("{"):
                            continue
                        try:
                            ev = json.loads(line)
                        except Exception:
                            continue
                        if _has_event_id(ev):
                            return True
                return False
            except Exception:
                return False

        return False
    except Exception:
        return False


def score_events(events: List[dict]) -> Tuple[float, str]:
    if not events:
        return 0.0, "No events provided for detection."

    total = 0
    matched = 0
    with_metadata = 0
    target_event_ids = {7, 8, 10, 12, 13, 14}
    target_matches = 0
    for ev in events:
        if not isinstance(ev, dict):
            continue
        total += 1
        if any(key in ev for key in ("EventID", "EventId", "event_id")):
            matched += 1
            event_id = ev.get("EventID") or ev.get("EventId") or ev.get("event_id")
            try:
                if int(event_id) in target_event_ids:
                    target_matches += 1
            except (TypeError, ValueError):
                pass
            if isinstance(ev.get("EventData"), dict) or any(
                key in ev for key in ("UtcTime", "TimeCreated", "Timestamp")
            ):
                with_metadata += 1

    if total == 0:
        return 0.0, "No JSON objects to score."

    score = matched / total
    if matched and with_metadata:
        score = min(1.0, score + 0.2)
    if target_matches:
        score = min(1.0, score + 0.1)

    reason = f"Matched {matched}/{total} events with Sysmon-style EventID keys."
    if with_metadata:
        reason += " EventData/UtcTime fields present."
    if target_matches:
        reason += f" Includes {target_matches} target EventID(s) (7/8/10/12/13/14)."
    return score, reason
