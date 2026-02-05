import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Iterator, Optional

@dataclass
class SysmonNormalized:
    ts: str
    utc_time: Optional[str] = None
    host: Optional[str] = None
    user: Optional[str] = None
    event_id: int = -1
    pid: Optional[int] = None
    image: Optional[str] = None
    cmd: Optional[str] = None
    parent_pid: Optional[int] = None
    parent_image: Optional[str] = None
    parent_cmd: Optional[str] = None
    parent_process_guid: Optional[str] = None
    integrity_level: Optional[str] = None
    current_directory: Optional[str] = None
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    process_guid: Optional[str] = None
    source_process_guid: Optional[str] = None
    source_pid: Optional[int] = None
    source_image: Optional[str] = None
    target_process_guid: Optional[str] = None
    target_pid: Optional[int] = None
    target_image: Optional[str] = None
    target_filename: Optional[str] = None
    creation_utctime: Optional[str] = None
    rule_name: Optional[str] = None
    query_name: Optional[str] = None
    query_results: Optional[str] = None
    query_status: Optional[str] = None
    image_loaded: Optional[str] = None
    event_type: Optional[str] = None
    target_object: Optional[str] = None
    details: Optional[str] = None
    new_name: Optional[str] = None
    granted_access: Optional[str] = None
    start_address: Optional[str] = None
    start_module: Optional[str] = None
    hashes: Optional[Dict[str, str]] = None
    event_data: Optional[Dict[str, Any]] = None


def parse_sysmon_hashes(value: Any) -> Dict[str, str]:
    hashes: Dict[str, str] = {}
    if isinstance(value, dict):
        items = list(value.items())
    elif isinstance(value, str):
        items = []
        for part in value.split(","):
            if not part:
                continue
            if "=" not in part:
                continue
            key, hash_value = part.split("=", 1)
            items.append((key, hash_value))
    else:
        return hashes

    for key, hash_value in items:
        if key is None:
            continue
        normalized_key = str(key).strip().lower()
        if not normalized_key:
            continue
        if hash_value is None:
            continue
        normalized_value = str(hash_value).strip()
        if not normalized_value:
            continue
        hashes[normalized_key] = normalized_value
    return hashes

def _to_iso8601_z(ts: str) -> str:
    """
    Normalize timestamps to ISO8601 with Z.
    Sysmon JSON often uses 'UtcTime' like '2024-01-01 00:00:00.000'
    or ISO-like forms.
    """
    if not ts:
        # fallback to now
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # Try common Sysmon format: "YYYY-MM-DD HH:MM:SS.sss"
    try:
        dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")
    except Exception:
        pass

    # Try ISO
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:
        # last resort
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def _safe_int(x: Any) -> Optional[int]:
    try:
        if x is None:
            return None
        return int(x)
    except Exception:
        return None

def _value_from_event(ev: Dict[str, Any], event_data: Optional[Dict[str, Any]], *keys: str) -> Optional[Any]:
    for key in keys:
        if key in ev and ev.get(key) is not None:
            return ev.get(key)
        if event_data and key in event_data and event_data.get(key) is not None:
            return event_data.get(key)
    return None

def _extract_fields(ev: Dict[str, Any]) -> SysmonNormalized:
    # Sysmon exports vary. We handle common keys.
    event_id = _safe_int(ev.get("EventID") or ev.get("EventId") or ev.get("event_id")) or -1

    event_data = ev.get("EventData") if isinstance(ev.get("EventData"), dict) else None
    utc_time = _value_from_event(ev, event_data, "UtcTime")

    ts = utc_time or ev.get("TimeCreated") or ev.get("time") or ev.get("Timestamp") or ""

    host = _value_from_event(ev, event_data, "Computer", "Host", "hostname")
    user = _value_from_event(ev, event_data, "User", "UserName", "user")

    pid = _safe_int(
        _value_from_event(
            ev,
            event_data,
            "ProcessId",
            "ProcessID",
            "pid",
            "SourceProcessId",
            "SourceProcessID",
        )
    )
    image = _value_from_event(
        ev,
        event_data,
        "Image",
        "ProcessImage",
        "image",
        "SourceImage",
    )
    cmd = _value_from_event(ev, event_data, "CommandLine", "cmd", "CmdLine")

    parent_pid = _safe_int(_value_from_event(ev, event_data, "ParentProcessId", "ParentProcessID"))
    parent_image = _value_from_event(ev, event_data, "ParentImage", "ParentProcessImage")
    parent_cmd = _value_from_event(ev, event_data, "ParentCommandLine", "ParentCmdLine")
    parent_process_guid = _value_from_event(ev, event_data, "ParentProcessGuid", "ParentProcessGUID")

    src_ip = ev.get("SourceIp") or ev.get("SourceIP") or ev.get("src_ip")
    src_port = _safe_int(ev.get("SourcePort") or ev.get("SourcePortNumber") or ev.get("src_port"))
    dst_ip = ev.get("DestinationIp") or ev.get("DestinationIP") or ev.get("dst_ip")
    dst_port = _safe_int(ev.get("DestinationPort") or ev.get("DestinationPortNumber") or ev.get("dst_port"))
    protocol = ev.get("Protocol") or ev.get("TransportProtocol") or ev.get("protocol")

    process_guid = _value_from_event(
        ev,
        event_data,
        "ProcessGuid",
        "ProcessGUID",
        "SourceProcessGuid",
        "SourceProcessGUID",
    )
    source_process_guid = _value_from_event(ev, event_data, "SourceProcessGuid", "SourceProcessGUID")
    source_pid = _safe_int(_value_from_event(ev, event_data, "SourceProcessId", "SourceProcessID"))
    source_image = _value_from_event(ev, event_data, "SourceImage")
    target_process_guid = _value_from_event(ev, event_data, "TargetProcessGuid", "TargetProcessGUID")
    target_pid = _safe_int(_value_from_event(ev, event_data, "TargetProcessId", "TargetProcessID"))
    target_image = _value_from_event(ev, event_data, "TargetImage")
    target_filename = ev.get("TargetFilename") or ev.get("TargetFileName")
    creation_utctime = ev.get("CreationUtcTime") or ev.get("CreationTime")
    rule_name = ev.get("RuleName") or ev.get("Rule")
    query_name = ev.get("QueryName") or (event_data.get("QueryName") if event_data else None)
    query_results = ev.get("QueryResults") or (event_data.get("QueryResults") if event_data else None)
    query_status = ev.get("QueryStatus") or (event_data.get("QueryStatus") if event_data else None)
    integrity_level = _value_from_event(ev, event_data, "IntegrityLevel")
    current_directory = _value_from_event(ev, event_data, "CurrentDirectory")
    image_loaded = _value_from_event(ev, event_data, "ImageLoaded")
    event_type = _value_from_event(ev, event_data, "EventType")
    target_object = _value_from_event(ev, event_data, "TargetObject")
    details = _value_from_event(ev, event_data, "Details")
    new_name = _value_from_event(ev, event_data, "NewName")
    granted_access = _value_from_event(ev, event_data, "GrantedAccess")
    start_address = _value_from_event(ev, event_data, "StartAddress")
    start_module = _value_from_event(ev, event_data, "StartModule")
    hashes_value = _value_from_event(ev, event_data, "Hashes", "Hash")
    hashes = parse_sysmon_hashes(hashes_value)

    return SysmonNormalized(
        ts=_to_iso8601_z(str(ts)),
        utc_time=str(utc_time) if utc_time else None,
        host=str(host) if host else None,
        user=str(user) if user else None,
        event_id=event_id,
        pid=pid,
        image=str(image) if image else None,
        cmd=str(cmd) if cmd else None,
        parent_pid=parent_pid,
        parent_image=str(parent_image) if parent_image else None,
        parent_cmd=str(parent_cmd) if parent_cmd else None,
        parent_process_guid=str(parent_process_guid) if parent_process_guid else None,
        src_ip=str(src_ip) if src_ip else None,
        src_port=src_port,
        dst_ip=str(dst_ip) if dst_ip else None,
        dst_port=dst_port,
        protocol=str(protocol) if protocol else None,
        process_guid=str(process_guid) if process_guid else None,
        source_process_guid=str(source_process_guid) if source_process_guid else None,
        source_pid=source_pid,
        source_image=str(source_image) if source_image else None,
        target_process_guid=str(target_process_guid) if target_process_guid else None,
        target_pid=target_pid,
        target_image=str(target_image) if target_image else None,
        target_filename=str(target_filename) if target_filename else None,
        creation_utctime=str(creation_utctime) if creation_utctime else None,
        rule_name=str(rule_name) if rule_name else None,
        query_name=str(query_name) if query_name else None,
        query_results=str(query_results) if query_results else None,
        query_status=str(query_status) if query_status else None,
        integrity_level=str(integrity_level) if integrity_level else None,
        current_directory=str(current_directory) if current_directory else None,
        image_loaded=str(image_loaded) if image_loaded else None,
        event_type=str(event_type) if event_type else None,
        target_object=str(target_object) if target_object else None,
        details=str(details) if details else None,
        new_name=str(new_name) if new_name else None,
        granted_access=str(granted_access) if granted_access else None,
        start_address=str(start_address) if start_address else None,
        start_module=str(start_module) if start_module else None,
        hashes=hashes or None,
        event_data=dict(ev) if isinstance(ev, dict) else None,
    )


def normalize_sysmon_event(ev: Dict[str, Any]) -> SysmonNormalized:
    return _extract_fields(ev)


def iter_sysmon_events_from_events(events: Iterable[Dict[str, Any]]) -> Iterator[SysmonNormalized]:
    for ev in events:
        if isinstance(ev, dict):
            yield _extract_fields(ev)

def iter_sysmon_events(file_path: str) -> Iterator[SysmonNormalized]:
    """
    Supports:
      - JSON array file
      - JSONL (one object per line)
      - Wrapper dict {"Events": [...]} (or "events")
    """
    with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
        first = f.readline().strip()

    if not first:
        return

    # JSON array
    if first.startswith("["):
        with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
            data = json.load(f)
        yield from iter_sysmon_events_from_events(data)
        return

    if first.startswith("{"):
        try:
            with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
                data = json.load(f)
            if isinstance(data, dict):
                events = data.get("Events") or data.get("events")
                if isinstance(events, list):
                    yield from iter_sysmon_events_from_events(events)
                    return
                if isinstance(data, dict):
                    yield normalize_sysmon_event(data)
                    return
            if isinstance(data, list):
                yield from iter_sysmon_events_from_events(data)
                return
        except Exception:
            pass

    # JSONL
    def _gen() -> Iterator[SysmonNormalized]:
        with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if not line.startswith("{"):
                    continue
                try:
                    ev = json.loads(line)
                    if isinstance(ev, dict):
                        yield normalize_sysmon_event(ev)
                except Exception:
                    continue

    yield from _gen()
