import json
from pathlib import Path
from typing import Any, Iterable, List, Tuple

HASH_KEYS = {"sha256", "sha1", "md5"}
FILE_KEYS = {"file_path", "file_name"}


def _normalize_keys(record: dict[str, Any]) -> dict[str, Any]:
    return {str(key).lower(): value for key, value in record.items()}


def _is_file_artifact_record(record: Any) -> bool:
    if not isinstance(record, dict):
        return False
    normalized = _normalize_keys(record)
    has_hash = any(normalized.get(key) for key in HASH_KEYS)
    has_file = any(normalized.get(key) for key in FILE_KEYS)
    return has_hash and has_file


def _events_from_wrapper(obj: Any) -> Iterable[Any]:
    if isinstance(obj, dict):
        events = obj.get("records") or obj.get("events")
        if isinstance(events, list):
            return events
    return []


def detect_file_artifact_json(file_path: str) -> bool:
    """
    Detects file artifact JSON (array, object, or JSONL) by looking for
    hash + file fields.
    """
    try:
        path = Path(file_path)
        if path.suffix.lower() not in [".json", ".jsonl", ".ndjson", ".log", ".txt"]:
            return False

        with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as handle:
            first = ""
            for line in handle:
                line = line.strip()
                if line:
                    first = line
                    break

        if not first:
            return False

        if first.startswith("["):
            try:
                with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as handle:
                    data = json.load(handle)
                if isinstance(data, list):
                    return any(_is_file_artifact_record(ev) for ev in data)
                if isinstance(data, dict):
                    return any(_is_file_artifact_record(ev) for ev in _events_from_wrapper(data))
                return False
            except Exception:
                return False

        if first.startswith("{"):
            try:
                with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as handle:
                    data = json.load(handle)
                if isinstance(data, dict):
                    if _is_file_artifact_record(data):
                        return True
                    return any(_is_file_artifact_record(ev) for ev in _events_from_wrapper(data))
                if isinstance(data, list):
                    return any(_is_file_artifact_record(ev) for ev in data)
                return False
            except Exception:
                pass

            try:
                with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as handle:
                    for line in handle:
                        line = line.strip()
                        if not line or not line.startswith("{"):
                            continue
                        try:
                            record = json.loads(line)
                        except Exception:
                            continue
                        if _is_file_artifact_record(record):
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
    for ev in events:
        if not isinstance(ev, dict):
            continue
        total += 1
        if _is_file_artifact_record(ev):
            matched += 1

    if total == 0:
        return 0.0, "No JSON objects to score."

    score = matched / total
    reason = f"Matched {matched}/{total} events with file + hash fields."
    return score, reason
