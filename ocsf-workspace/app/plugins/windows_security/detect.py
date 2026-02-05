import json
from pathlib import Path
from typing import Any, Iterable, List, Tuple


AUTH_EVENT_IDS = {4624, 4625}
OBJECT_ACCESS_EVENT_ID = 4663
TARGET_EVENT_IDS = AUTH_EVENT_IDS | {OBJECT_ACCESS_EVENT_ID}


def _event_data_to_dict(event_data: Any) -> dict:
    if isinstance(event_data, dict):
        data = event_data.get("Data")
        if isinstance(data, list):
            return _event_data_to_dict(data)
        return event_data
    if isinstance(event_data, list):
        result: dict = {}
        for item in event_data:
            if not isinstance(item, dict):
                continue
            name = item.get("Name") or item.get("name")
            value = item.get("Value")
            if value is None:
                value = item.get("#text") or item.get("text")
            if name:
                result[str(name)] = value
        return result
    return {}


def _properties_to_event_data(properties: Any) -> dict:
    if isinstance(properties, dict):
        data = properties.get("Data") or properties.get("data")
        if isinstance(data, list):
            return _event_data_to_dict(data)
        return _event_data_to_dict(properties)
    if isinstance(properties, list):
        result: dict = {}
        for item in properties:
            if not isinstance(item, dict):
                continue
            name = item.get("Name") or item.get("name")
            value = item.get("Value")
            if value is None:
                value = item.get("value") or item.get("#text") or item.get("text")
            if name:
                result[str(name)] = value
        return result
    return {}


def _extract_event_data(ev: dict) -> dict:
    if isinstance(ev.get("EventData"), (dict, list)):
        return _event_data_to_dict(ev.get("EventData"))
    if isinstance(ev.get("Properties"), (dict, list)):
        return _properties_to_event_data(ev.get("Properties"))
    event_wrapper = ev.get("Event")
    if isinstance(event_wrapper, dict):
        event_data = event_wrapper.get("EventData")
        if isinstance(event_data, (dict, list)):
            return _event_data_to_dict(event_data)
        properties = event_wrapper.get("Properties")
        if isinstance(properties, (dict, list)):
            return _properties_to_event_data(properties)
    return {}


def detect_windows_security_json(file_path: str) -> bool:
    """
    Detects Windows Security Event JSON (array, JSONL, or wrapper dict).
    Supports EventID 4624/4625/4663 with EventData and TimeCreated.
    """

    def _safe_int(value: Any) -> int:
        try:
            return int(value)
        except Exception:
            return -1

    def _get_nested(ev: dict, *keys: str) -> Any:
        current: Any = ev
        for key in keys:
            if not isinstance(current, dict):
                return None
            current = current.get(key)
        return current

    def _has_required_fields(ev: Any) -> bool:
        if not isinstance(ev, dict):
            return False
        event_id = _safe_int(
            ev.get("EventID")
            or _get_nested(ev, "System", "EventID")
            or _get_nested(ev, "Event", "System", "EventID")
        )
        if event_id not in TARGET_EVENT_IDS:
            return False
        event_data = _extract_event_data(ev)
        if event_data is None:
            return False
        time_created = (
            ev.get("TimeCreated")
            or _get_nested(ev, "System", "TimeCreated")
            or _get_nested(ev, "Event", "System", "TimeCreated")
        )
        if time_created is None:
            return False
        if event_id == OBJECT_ACCESS_EVENT_ID:
            channel = (
                ev.get("Channel")
                or _get_nested(ev, "System", "Channel")
                or _get_nested(ev, "Event", "System", "Channel")
            )
            source_name = (
                ev.get("SourceName")
                or _get_nested(ev, "System", "Provider", "Name")
                or _get_nested(ev, "Event", "System", "Provider", "Name")
            )
            object_name = event_data.get("ObjectName") or ev.get("ObjectName")
            access_mask = event_data.get("AccessMask") or ev.get("AccessMask")
            access_list = event_data.get("AccessList") or ev.get("AccessList")
            has_channel = channel == "Security" or source_name == "Microsoft-Windows-Security-Auditing"
            return bool(has_channel and (object_name or access_mask or access_list))
        return True

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
                    return any(_has_required_fields(ev) for ev in data)
                if isinstance(data, dict):
                    return any(_has_required_fields(ev) for ev in _events_from_wrapper(data))
                return False
            except Exception:
                return False

        if first.startswith("{"):
            try:
                with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    if _has_required_fields(data):
                        return True
                    return any(_has_required_fields(ev) for ev in _events_from_wrapper(data))
                if isinstance(data, list):
                    return any(_has_required_fields(ev) for ev in data)
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
                        if _has_required_fields(ev):
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

    def _safe_int(value: Any) -> int:
        try:
            return int(value)
        except Exception:
            return -1

    def _get_nested(ev: dict, *keys: str) -> Any:
        current: Any = ev
        for key in keys:
            if not isinstance(current, dict):
                return None
            current = current.get(key)
        return current

    total = 0
    matched = 0
    with_payload = 0
    matched_object_access = 0
    for ev in events:
        if not isinstance(ev, dict):
            continue
        total += 1
        event_id = _safe_int(
            ev.get("EventID")
            or _get_nested(ev, "System", "EventID")
            or _get_nested(ev, "Event", "System", "EventID")
        )
        if event_id not in TARGET_EVENT_IDS:
            continue
        matched += 1
        event_data = _extract_event_data(ev)
        time_created = (
            ev.get("TimeCreated")
            or _get_nested(ev, "System", "TimeCreated")
            or _get_nested(ev, "Event", "System", "TimeCreated")
        )
        if event_data is not None and time_created is not None:
            with_payload += 1
        if event_id == OBJECT_ACCESS_EVENT_ID:
            channel = (
                ev.get("Channel")
                or _get_nested(ev, "System", "Channel")
                or _get_nested(ev, "Event", "System", "Channel")
            )
            source_name = (
                ev.get("SourceName")
                or _get_nested(ev, "System", "Provider", "Name")
                or _get_nested(ev, "Event", "System", "Provider", "Name")
            )
            object_name = event_data.get("ObjectName") or ev.get("ObjectName")
            access_mask = event_data.get("AccessMask") or ev.get("AccessMask")
            access_list = event_data.get("AccessList") or ev.get("AccessList")
            if (channel == "Security" or source_name == "Microsoft-Windows-Security-Auditing") and (
                object_name or access_mask or access_list
            ):
                matched_object_access += 1

    if total == 0:
        return 0.0, "No JSON objects to score."

    score = matched / total
    if matched and with_payload:
        score = min(1.0, score + 0.2)
    if matched_object_access:
        score = min(1.0, score + 0.2)

    reason = f"Matched {matched}/{total} events with EventID 4624/4625/4663."
    if with_payload:
        reason += " EventData and TimeCreated fields present."
    if matched_object_access:
        reason += " Object access fields present for EventID 4663."
    return score, reason
