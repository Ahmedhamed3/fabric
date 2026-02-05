import json
from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Any, Dict, Iterable, Iterator, List, Optional, Union


@dataclass
class WindowsSecurityNormalized:
    event_id: int
    time_created: str
    target_user_name: Optional[str] = None
    target_domain_name: Optional[str] = None
    logon_type: Optional[str] = None
    ip_address: Optional[str] = None
    workstation_name: Optional[str] = None
    status: Optional[str] = None
    failure_reason: Optional[str] = None
    original_event: Optional[Dict[str, Any]] = None


@dataclass
class WindowsSecurityObjectAccessNormalized:
    event_id: int
    time_created: str
    computer: Optional[str] = None
    subject_username: Optional[str] = None
    subject_domain: Optional[str] = None
    subject_sid: Optional[str] = None
    logon_id: Optional[str] = None
    object_type: Optional[str] = None
    object_name: Optional[str] = None
    process_name: Optional[str] = None
    process_id: Optional[str] = None
    access_mask: Optional[str] = None
    access_list: Optional[List[str]] = None
    original_event: Optional[Dict[str, Any]] = None


WindowsSecurityEventNormalized = Union[WindowsSecurityNormalized, WindowsSecurityObjectAccessNormalized]


def _to_iso8601_utc(ts: Optional[Any]) -> str:
    if not ts:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(ts, dict):
        ts = ts.get("SystemTime") or ts.get("system_time") or ts.get("time")
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(ts, str):
        normalized = ts.replace("Z", "+00:00")
        if normalized.endswith("+0000"):
            normalized = f"{normalized[:-5]}+00:00"
        try:
            dt = datetime.fromisoformat(normalized)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except Exception:
            return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except Exception:
        return -1


def _event_data_to_dict(event_data: Any) -> Dict[str, Any]:
    if isinstance(event_data, dict):
        data = event_data.get("Data")
        if isinstance(data, list):
            return _event_data_to_dict(data)
        return event_data
    if isinstance(event_data, list):
        result: Dict[str, Any] = {}
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


def _properties_to_event_data(properties: Any) -> Dict[str, Any]:
    if isinstance(properties, dict):
        data = properties.get("Data") or properties.get("data")
        if isinstance(data, list):
            return _event_data_to_dict(data)
        return _event_data_to_dict(properties)
    if isinstance(properties, list):
        result: Dict[str, Any] = {}
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


def _extract_event_data(ev: Dict[str, Any]) -> Dict[str, Any]:
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


def _get_nested(ev: Dict[str, Any], *keys: str) -> Any:
    current: Any = ev
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _extract_fields(ev: Dict[str, Any]) -> WindowsSecurityNormalized:
    event_id = _safe_int(
        ev.get("EventID")
        or _get_nested(ev, "System", "EventID")
        or _get_nested(ev, "Event", "System", "EventID")
    )
    time_created = (
        ev.get("TimeCreated")
        or _get_nested(ev, "System", "TimeCreated")
        or _get_nested(ev, "Event", "System", "TimeCreated")
        or ev.get("Timestamp")
    )

    event_data = _extract_event_data(ev)

    target_user_name = event_data.get("TargetUserName") or ev.get("TargetUserName")
    target_domain_name = event_data.get("TargetDomainName") or ev.get("TargetDomainName")
    logon_type = event_data.get("LogonType") or ev.get("LogonType")
    ip_address = event_data.get("IpAddress") or event_data.get("Ip") or ev.get("IpAddress")
    workstation_name = event_data.get("WorkstationName") or ev.get("WorkstationName")
    status = event_data.get("Status") or ev.get("Status")
    failure_reason = event_data.get("FailureReason") or ev.get("FailureReason")

    return WindowsSecurityNormalized(
        event_id=event_id,
        time_created=_to_iso8601_utc(time_created),
        target_user_name=str(target_user_name) if target_user_name else None,
        target_domain_name=str(target_domain_name) if target_domain_name else None,
        logon_type=str(logon_type) if logon_type else None,
        ip_address=str(ip_address) if ip_address else None,
        workstation_name=str(workstation_name) if workstation_name else None,
        status=str(status) if status else None,
        failure_reason=str(failure_reason) if failure_reason else None,
        original_event=dict(ev) if isinstance(ev, dict) else None,
    )


def _normalize_access_list(access_list: Any) -> Optional[List[str]]:
    if access_list is None:
        return None
    if isinstance(access_list, list):
        return [str(entry) for entry in access_list if entry is not None]
    if isinstance(access_list, str):
        cleaned = access_list.strip()
        if not cleaned:
            return None
        tokens = [token for token in re.split(r"[,\s]+", cleaned) if token]
        if tokens and cleaned not in tokens:
            return [cleaned] + tokens
        return tokens or [cleaned]
    return [str(access_list)]


def _extract_object_access_fields(ev: Dict[str, Any]) -> WindowsSecurityObjectAccessNormalized:
    event_id = _safe_int(
        ev.get("EventID")
        or _get_nested(ev, "System", "EventID")
        or _get_nested(ev, "Event", "System", "EventID")
    )
    time_created = (
        ev.get("TimeCreated")
        or _get_nested(ev, "System", "TimeCreated")
        or _get_nested(ev, "Event", "System", "TimeCreated")
        or ev.get("Timestamp")
    )
    computer = (
        ev.get("Computer")
        or _get_nested(ev, "System", "Computer")
        or _get_nested(ev, "Event", "System", "Computer")
    )

    event_data = _extract_event_data(ev)

    subject_username = event_data.get("SubjectUserName") or ev.get("SubjectUserName")
    subject_domain = event_data.get("SubjectDomainName") or ev.get("SubjectDomainName")
    subject_sid = event_data.get("SubjectUserSid") or ev.get("SubjectUserSid")
    logon_id = event_data.get("SubjectLogonId") or ev.get("SubjectLogonId")

    object_type = event_data.get("ObjectType") or ev.get("ObjectType")
    object_name = event_data.get("ObjectName") or ev.get("ObjectName")
    process_name = event_data.get("ProcessName") or ev.get("ProcessName")
    process_id = event_data.get("ProcessId") or ev.get("ProcessId")
    access_mask = event_data.get("AccessMask") or ev.get("AccessMask")
    access_list = _normalize_access_list(event_data.get("AccessList") or ev.get("AccessList"))

    return WindowsSecurityObjectAccessNormalized(
        event_id=event_id,
        time_created=_to_iso8601_utc(time_created),
        computer=str(computer) if computer else None,
        subject_username=str(subject_username) if subject_username else None,
        subject_domain=str(subject_domain) if subject_domain else None,
        subject_sid=str(subject_sid) if subject_sid else None,
        logon_id=str(logon_id) if logon_id else None,
        object_type=str(object_type) if object_type else None,
        object_name=str(object_name) if object_name else None,
        process_name=str(process_name) if process_name else None,
        process_id=str(process_id) if process_id else None,
        access_mask=str(access_mask) if access_mask is not None else None,
        access_list=access_list,
        original_event=dict(ev) if isinstance(ev, dict) else None,
    )


def normalize_windows_security_event(ev: Dict[str, Any]) -> WindowsSecurityEventNormalized:
    event_id = _safe_int(
        ev.get("EventID")
        or _get_nested(ev, "System", "EventID")
        or _get_nested(ev, "Event", "System", "EventID")
    )
    if event_id == 4663:
        return _extract_object_access_fields(ev)
    return _extract_fields(ev)


def iter_windows_security_events_from_events(
    events: Iterable[Dict[str, Any]],
) -> Iterator[WindowsSecurityEventNormalized]:
    for ev in events:
        if isinstance(ev, dict):
            yield normalize_windows_security_event(ev)


def iter_windows_security_events(file_path: str) -> Iterator[WindowsSecurityEventNormalized]:
    with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
        first = f.readline().strip()

    if not first:
        return

    if first.startswith("["):
        with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
            data = json.load(f)
        if isinstance(data, list):
            for ev in data:
                if isinstance(ev, dict):
                    yield normalize_windows_security_event(ev)
        return

    if first.startswith("{"):
        try:
            with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
                data = json.load(f)
            if isinstance(data, dict):
                events = data.get("Events") or data.get("events")
                if isinstance(events, list):
                    for ev in events:
                        if isinstance(ev, dict):
                            yield normalize_windows_security_event(ev)
                    return
                yield normalize_windows_security_event(data)
                return
            if isinstance(data, list):
                for ev in data:
                    if isinstance(ev, dict):
                        yield normalize_windows_security_event(ev)
                return
        except Exception:
            pass

    def _gen() -> Iterator[WindowsSecurityNormalized]:
        with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    ev = json.loads(line)
                except Exception:
                    continue
                if isinstance(ev, dict):
                    yield normalize_windows_security_event(ev)

    yield from _gen()
