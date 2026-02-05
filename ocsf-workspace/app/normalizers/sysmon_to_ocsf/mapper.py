from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional
from pathlib import Path

from app.normalizers.sysmon_to_ocsf import taxonomy
from app.normalizers.sysmon_to_ocsf.sysmon_xml import parse_event_data, parse_system_time


@dataclass(frozen=True)
class MappingContext:
    ocsf_version: str


def map_raw_event(raw_event: Dict[str, Any], context: MappingContext) -> Optional[Dict[str, Any]]:
    event_id = _get_event_id(raw_event)
    if event_id == 1:
        return _map_process_activity(raw_event, context)
    if event_id == 5:
        return _map_process_terminate(raw_event, context)
    if event_id == 3:
        return _map_network_activity(raw_event, context)
    if event_id == 22:
        return map_sysmon_eventid22_to_ocsf(raw_event, context)
    if event_id == 11:
        return _map_file_activity(raw_event, context)
    return None


def mapping_attempted(raw_event: Dict[str, Any]) -> bool:
    event_id = _get_event_id(raw_event)
    return event_id in {1, 3, 5, 11, 22}


def missing_required_fields(raw_event: Dict[str, Any]) -> list[str]:
    event_id = _get_event_id(raw_event)
    if event_id == 3:
        event_data = _get_event_data(raw_event)
        time_value = _normalize_sysmon_time(event_data.get("UtcTime")) or _get_event_time(raw_event)
        protocol = _normalize_value(event_data.get("Protocol"))
        if protocol:
            protocol = protocol.lower()
        src_ip = _normalize_value(event_data.get("SourceIp"))
        dst_ip = _normalize_value(event_data.get("DestinationIp"))
        dst_port = _to_int(_normalize_value(event_data.get("DestinationPort")))
        pid = _to_int(_normalize_value(event_data.get("ProcessId")))
        image = _normalize_value(event_data.get("Image"))
        return _missing_required_network_fields(time_value, protocol, src_ip, dst_ip, dst_port, pid, image)
    if event_id == 5:
        event_data = _get_event_data(raw_event)
        observed_time = _normalize_sysmon_time(event_data.get("UtcTime"))
        pid = _to_int(event_data.get("ProcessId"))
        image = event_data.get("Image")
        return _missing_required_process_terminate_fields(observed_time, pid, image)
    if event_id == 11:
        event_data = _get_event_data(raw_event)
        observed_time = _normalize_sysmon_time(event_data.get("UtcTime"))
        pid = _to_int(_normalize_value(event_data.get("ProcessId")))
        process_guid = _normalize_value(event_data.get("ProcessGuid"))
        target_filename = _normalize_value(event_data.get("TargetFilename"))
        return _missing_required_file_fields(observed_time, pid, process_guid, target_filename)
    if event_id == 22:
        event_data = _get_event_data(raw_event)
        observed_time = _normalize_sysmon_time(event_data.get("UtcTime")) or _get_event_time(raw_event)
        query_name = _normalize_value(event_data.get("QueryName"))
        pid = _to_int(_normalize_value(event_data.get("ProcessId")))
        image = _normalize_value(event_data.get("Image"))
        return _missing_required_dns_fields(observed_time, query_name, pid, image)
    return []


def _get_event_id(raw_event: Dict[str, Any]) -> Optional[int]:
    ids = raw_event.get("ids") or {}
    event_id = ids.get("event_id")
    if isinstance(event_id, int):
        return event_id
    if isinstance(event_id, str) and event_id.isdigit():
        return int(event_id)
    return None


def _get_event_time(raw_event: Dict[str, Any]) -> Optional[str]:
    event = raw_event.get("event") or {}
    time_info = event.get("time") or {}
    time_value = time_info.get("created_utc") or time_info.get("observed_utc")
    if time_value:
        return time_value
    xml = _get_raw_xml(raw_event)
    return parse_system_time(xml) if xml else None


def _get_raw_xml(raw_event: Dict[str, Any]) -> str:
    raw = raw_event.get("raw") or {}
    xml = raw.get("xml") or raw.get("data") or ""
    return xml


def _get_event_data(raw_event: Dict[str, Any]) -> Dict[str, str]:
    parsed = raw_event.get("parsed") or {}
    event_data = parsed.get("event_data")
    if isinstance(event_data, dict):
        return {str(k): "" if v is None else str(v) for k, v in event_data.items()}
    xml = _get_raw_xml(raw_event)
    if not xml:
        return {}
    return parse_event_data(xml)


def _split_domain_user(value: Optional[str]) -> Dict[str, str]:
    if not value:
        return {}
    if "\\" in value:
        domain, name = value.split("\\", 1)
        return {"name": name, "domain": domain}
    return {"name": value}


def _to_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _normalize_value(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    if not text or text == "-":
        return None
    return text


def _base_event(raw_event: Dict[str, Any], context: MappingContext, *, category_uid: int, class_uid: int, activity_id: int) -> Dict[str, Any]:
    ids = raw_event.get("ids") or {}
    source = raw_event.get("source") or {}
    host = raw_event.get("host") or {}
    time_value = _get_event_time(raw_event)
    record_id = ids.get("record_id")
    event_code = ids.get("event_id")
    channel = source.get("channel")
    product_name = source.get("product") or "sysmon"
    product = {
        "name": product_name,
        "vendor_name": source.get("vendor"),
        "version": source.get("version"),
    }
    product = {key: value for key, value in product.items() if value}
    # metadata.uid is assigned after hashing to a stable OCSF event hash.
    metadata = {
        "product": product,
        "version": context.ocsf_version,
        "event_code": str(event_code) if event_code is not None else None,
        "original_event_uid": str(record_id) if record_id is not None else None,
        "log_name": channel,
        "log_source": source.get("type"),
        "log_format": "xml",
        "original_time": time_value,
    }
    metadata = {key: value for key, value in metadata.items() if value is not None}
    device = {"type_id": taxonomy.DEVICE_TYPE_UNKNOWN_ID}
    if host.get("hostname"):
        device["hostname"] = host.get("hostname")
    base = {
        "activity_id": activity_id,
        "category_uid": category_uid,
        "class_uid": class_uid,
        "type_uid": taxonomy.to_type_uid(class_uid, activity_id),
        "time": time_value,
        "severity_id": _map_severity_id(raw_event.get("severity")),
        "metadata": metadata,
        "device": device,
    }
    return base


def _map_process_activity(raw_event: Dict[str, Any], context: MappingContext) -> Optional[Dict[str, Any]]:
    event_data = _get_event_data(raw_event)
    process = _build_process_entity(
        pid=_to_int(event_data.get("ProcessId")),
        uid=event_data.get("ProcessGuid"),
        path=event_data.get("Image"),
        cmd_line=event_data.get("CommandLine"),
        created_time=_normalize_sysmon_time(event_data.get("UtcTime")),
    )
    parent = _build_process_entity(
        pid=_to_int(event_data.get("ParentProcessId")),
        uid=event_data.get("ParentProcessGuid"),
        path=event_data.get("ParentImage"),
        cmd_line=event_data.get("ParentCommandLine"),
    )
    if parent:
        process = {**process, "parent_process": parent} if process else {"parent_process": parent}
    actor = _build_actor(
        process=parent or None,
        user=_split_domain_user(event_data.get("User")),
    )
    class_uid = taxonomy.to_class_uid(taxonomy.SYSTEM_CATEGORY_UID, taxonomy.PROCESS_ACTIVITY_UID)
    base = _base_event(
        raw_event,
        context,
        category_uid=taxonomy.SYSTEM_CATEGORY_UID,
        class_uid=class_uid,
        activity_id=taxonomy.PROCESS_ACTIVITY_LAUNCH_ID,
    )
    base["actor"] = actor
    base["process"] = process
    return base


def _map_network_activity(raw_event: Dict[str, Any], context: MappingContext) -> Optional[Dict[str, Any]]:
    event_data = _get_event_data(raw_event)
    observed_time = _normalize_sysmon_time(event_data.get("UtcTime")) or _get_event_time(raw_event)
    protocol = _normalize_value(event_data.get("Protocol"))
    if protocol:
        protocol = protocol.lower()
    src_ip = _normalize_value(event_data.get("SourceIp"))
    src_port = _to_int(_normalize_value(event_data.get("SourcePort")))
    dst_ip = _normalize_value(event_data.get("DestinationIp"))
    dst_port = _to_int(_normalize_value(event_data.get("DestinationPort")))
    pid = _to_int(_normalize_value(event_data.get("ProcessId")))
    image = _normalize_value(event_data.get("Image"))
    missing_fields = _missing_required_network_fields(observed_time, protocol, src_ip, dst_ip, dst_port, pid, image)
    if missing_fields:
        return None
    process = _build_process_entity(
        pid=pid,
        uid=event_data.get("ProcessGuid"),
        path=image,
    )
    actor = _build_actor(process=process, user=_split_domain_user(_normalize_value(event_data.get("User"))))
    src_endpoint = _build_network_endpoint(
        ip=src_ip,
        port=src_port,
    )
    dst_endpoint = _build_network_endpoint(
        ip=dst_ip,
        port=dst_port,
    )
    class_uid = taxonomy.to_class_uid(taxonomy.NETWORK_CATEGORY_UID, taxonomy.NETWORK_ACTIVITY_UID)
    base = _base_event(
        raw_event,
        context,
        category_uid=taxonomy.NETWORK_CATEGORY_UID,
        class_uid=class_uid,
        activity_id=taxonomy.NETWORK_ACTIVITY_OPEN_ID,
    )
    base["connection_info"] = {
        "direction_id": taxonomy.NETWORK_DIRECTION_UNKNOWN_ID,
        "protocol_name": protocol,
    }
    base["actor"] = actor
    base["src_endpoint"] = src_endpoint
    base["dst_endpoint"] = dst_endpoint
    if observed_time:
        base["time"] = observed_time
        base.setdefault("metadata", {})["original_time"] = observed_time
    unmapped_event_data = _extract_unmapped_event_data(
        event_data,
        used_keys={
            "UtcTime",
            "ProcessGuid",
            "ProcessId",
            "Image",
            "User",
            "SourceIp",
            "SourcePort",
            "DestinationIp",
            "DestinationPort",
            "Protocol",
        },
    )
    if unmapped_event_data:
        base.setdefault("unmapped", {})["event_data"] = unmapped_event_data
    return base


def map_sysmon_eventid22_to_ocsf(raw_event: Dict[str, Any], context: MappingContext) -> Optional[Dict[str, Any]]:
    event_id = _get_event_id(raw_event)
    if event_id != 22:
        return None
    event_data = _get_event_data(raw_event)
    observed_time = _normalize_sysmon_time(event_data.get("UtcTime")) or _get_event_time(raw_event)
    query_name = _normalize_value(event_data.get("QueryName"))
    query_type = _normalize_value(event_data.get("QueryType"))
    query_status = _normalize_value(event_data.get("QueryStatus"))
    query_results = _normalize_value(event_data.get("QueryResults"))
    pid = _to_int(_normalize_value(event_data.get("ProcessId")))
    image = _normalize_value(event_data.get("Image"))
    process_guid = _normalize_value(event_data.get("ProcessGuid"))
    user = _normalize_value(event_data.get("User"))
    missing_fields = _missing_required_dns_fields(observed_time, query_name, pid, image)
    if missing_fields:
        return None
    process = _build_process_entity(
        pid=pid,
        uid=process_guid,
        path=image,
    )
    actor = _build_actor(process=process, user=_split_domain_user(user))
    class_uid = taxonomy.to_class_uid(taxonomy.NETWORK_CATEGORY_UID, taxonomy.DNS_ACTIVITY_UID)
    base = _base_event(
        raw_event,
        context,
        category_uid=taxonomy.NETWORK_CATEGORY_UID,
        class_uid=class_uid,
        activity_id=taxonomy.DNS_ACTIVITY_QUERY_ID,
    )
    base["actor"] = actor
    query: Dict[str, Any] = {"hostname": query_name} if query_name else {}
    if query_type:
        query["type"] = query_type
    if query:
        base["query"] = query
    answers = _parse_dns_answers(query_results)
    if answers:
        base["answers"] = answers
    rcode_id = _parse_dns_rcode(query_status)
    if rcode_id is not None:
        base["rcode_id"] = rcode_id
    host = raw_event.get("host") or {}
    if host.get("hostname"):
        base["src_endpoint"] = {"hostname": host.get("hostname")}
    if observed_time:
        base["time"] = observed_time
        base.setdefault("metadata", {})["original_time"] = observed_time
    unmapped_event_data = _extract_unmapped_event_data(
        event_data,
        used_keys={
            "UtcTime",
            "QueryName",
            "QueryType",
            "QueryStatus",
            "QueryResults",
            "ProcessGuid",
            "ProcessId",
            "Image",
            "User",
        },
    )
    if unmapped_event_data:
        base.setdefault("unmapped", {})["event_data"] = unmapped_event_data
    return base


def _map_process_terminate(raw_event: Dict[str, Any], context: MappingContext) -> Optional[Dict[str, Any]]:
    event_data = _get_event_data(raw_event)
    observed_time = _normalize_sysmon_time(event_data.get("UtcTime"))
    pid = _to_int(event_data.get("ProcessId"))
    image = event_data.get("Image")
    missing_fields = _missing_required_process_terminate_fields(observed_time, pid, image)
    if missing_fields:
        return None
    process = _build_process_entity(
        pid=pid,
        uid=event_data.get("ProcessGuid"),
        path=image,
    )
    class_uid = taxonomy.to_class_uid(taxonomy.SYSTEM_CATEGORY_UID, taxonomy.PROCESS_ACTIVITY_UID)
    base = _base_event(
        raw_event,
        context,
        category_uid=taxonomy.SYSTEM_CATEGORY_UID,
        class_uid=class_uid,
        activity_id=taxonomy.PROCESS_ACTIVITY_TERMINATE_ID,
    )
    base["process"] = process
    if observed_time:
        base["time"] = observed_time
        base.setdefault("metadata", {})["original_time"] = observed_time
    unmapped_event_data = _extract_unmapped_event_data(
        event_data,
        used_keys={"ProcessGuid", "ProcessId", "Image", "UtcTime"},
    )
    if unmapped_event_data:
        base.setdefault("unmapped", {})["event_data"] = unmapped_event_data
    return base


def _map_file_activity(raw_event: Dict[str, Any], context: MappingContext) -> Optional[Dict[str, Any]]:
    event_data = _get_event_data(raw_event)
    observed_time = _normalize_sysmon_time(event_data.get("UtcTime"))
    pid = _to_int(_normalize_value(event_data.get("ProcessId")))
    process_guid = _normalize_value(event_data.get("ProcessGuid"))
    target_filename = _normalize_value(event_data.get("TargetFilename"))
    missing_fields = _missing_required_file_fields(observed_time, pid, process_guid, target_filename)
    if missing_fields:
        return None
    image = _normalize_value(event_data.get("Image"))
    command_line = _normalize_value(event_data.get("CommandLine"))
    process = _build_process_entity(
        pid=pid,
        uid=process_guid,
        path=image,
        cmd_line=command_line,
    )
    actor = _build_actor(process=process, user=_split_domain_user(_normalize_value(event_data.get("User"))))
    file_obj = _build_file(path=target_filename)
    hashes = _parse_sysmon_hashes(event_data.get("Hashes"))
    file_hashes: list[Dict[str, Any]] = []
    if hashes.get("sha256"):
        file_hashes.append({"algorithm_id": 3, "algorithm": "SHA-256", "value": hashes["sha256"]})
    if hashes.get("md5"):
        file_hashes.append({"algorithm_id": 1, "algorithm": "MD5", "value": hashes["md5"]})
    if file_hashes:
        file_obj["hashes"] = file_hashes
    class_uid = taxonomy.to_class_uid(taxonomy.SYSTEM_CATEGORY_UID, taxonomy.FILE_ACTIVITY_UID)
    base = _base_event(
        raw_event,
        context,
        category_uid=taxonomy.SYSTEM_CATEGORY_UID,
        class_uid=class_uid,
        activity_id=taxonomy.FILE_ACTIVITY_CREATE_ID,
    )
    base["actor"] = actor
    base["file"] = file_obj
    if observed_time:
        base["time"] = observed_time
        base.setdefault("metadata", {})["original_time"] = observed_time
    unmapped_event_data = _extract_unmapped_event_data(
        event_data,
        used_keys={
            "UtcTime",
            "ProcessId",
            "ProcessGuid",
            "Image",
            "CommandLine",
            "User",
            "TargetFilename",
            "Hashes",
        },
    )
    if unmapped_event_data:
        base.setdefault("unmapped", {})["event_data"] = unmapped_event_data
    return base


def _build_actor(process: Optional[Dict[str, Any]], user: Dict[str, str]) -> Dict[str, Any]:
    actor: Dict[str, Any] = {}
    if process:
        actor["process"] = process
    if user:
        actor["user"] = user
    return actor


def _build_process_entity(
    *,
    pid: Optional[int],
    uid: Optional[str],
    path: Optional[str],
    cmd_line: Optional[str] = None,
    created_time: Optional[str] = None,
) -> Dict[str, Any]:
    entity: Dict[str, Any] = {}
    if pid is not None:
        entity["pid"] = pid
    if uid:
        entity["uid"] = uid
    if path:
        entity["path"] = path
        entity["name"] = Path(path).name
    if cmd_line:
        entity["cmd_line"] = cmd_line
    if created_time:
        entity["created_time"] = created_time
    return entity


def _normalize_sysmon_time(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    value = value.strip()
    if "T" in value and value.endswith("Z"):
        return value
    if " " in value:
        return f"{value.replace(' ', 'T')}Z"
    return value


def _build_network_endpoint(*, ip: Optional[str], port: Optional[int]) -> Dict[str, Any]:
    endpoint: Dict[str, Any] = {}
    if ip:
        endpoint["ip"] = ip
    if port is not None:
        endpoint["port"] = port
    return endpoint


def _build_file(*, path: Optional[str]) -> Dict[str, Any]:
    file_obj: Dict[str, Any] = {"type_id": taxonomy.FILE_TYPE_UNKNOWN_ID}
    if path:
        file_obj["path"] = path
        file_obj["name"] = Path(path).name
    return file_obj


def _parse_dns_answers(value: Optional[str]) -> list[Dict[str, Any]]:
    if not value:
        return []
    results: list[Dict[str, Any]] = []
    for part in str(value).split(";"):
        cleaned = part.strip()
        if not cleaned or cleaned == "-":
            continue
        results.append({"rdata": cleaned})
    return results


def _parse_dns_rcode(value: Optional[str]) -> Optional[int]:
    if not value:
        return None
    try:
        return int(str(value).strip(), 0)
    except (TypeError, ValueError):
        return None


def _missing_required_process_terminate_fields(
    observed_time: Optional[str],
    pid: Optional[int],
    image: Optional[str],
) -> list[str]:
    missing: list[str] = []
    if not observed_time:
        missing.append("UtcTime")
    if pid is None:
        missing.append("ProcessId")
    if not image:
        missing.append("Image")
    return missing


def _missing_required_file_fields(
    observed_time: Optional[str],
    pid: Optional[int],
    process_guid: Optional[str],
    target_filename: Optional[str],
) -> list[str]:
    missing: list[str] = []
    if not observed_time:
        missing.append("UtcTime")
    if pid is None:
        missing.append("ProcessId")
    if not process_guid:
        missing.append("ProcessGuid")
    if not target_filename:
        missing.append("TargetFilename")
    return missing


def _missing_required_network_fields(
    observed_time: Optional[str],
    protocol: Optional[str],
    src_ip: Optional[str],
    dst_ip: Optional[str],
    dst_port: Optional[int],
    pid: Optional[int],
    image: Optional[str],
) -> list[str]:
    missing: list[str] = []
    if not observed_time:
        missing.append("UtcTime")
    if not protocol:
        missing.append("Protocol")
    if not src_ip:
        missing.append("SourceIp")
    if not dst_ip:
        missing.append("DestinationIp")
    if dst_port is None:
        missing.append("DestinationPort")
    if pid is None:
        missing.append("ProcessId")
    if not image:
        missing.append("Image")
    return missing


def _missing_required_dns_fields(
    observed_time: Optional[str],
    query_name: Optional[str],
    pid: Optional[int],
    image: Optional[str],
) -> list[str]:
    missing: list[str] = []
    if not observed_time:
        missing.append("UtcTime")
    if not query_name:
        missing.append("QueryName")
    if pid is None and not image:
        missing.append("ProcessId")
        missing.append("Image")
    return missing


def _extract_unmapped_event_data(event_data: Dict[str, str], *, used_keys: set[str]) -> Dict[str, str]:
    return {key: value for key, value in event_data.items() if key not in used_keys and value}


def _parse_sysmon_hashes(value: Any) -> Dict[str, str]:
    hashes: Dict[str, str] = {}
    if isinstance(value, dict):
        items = list(value.items())
    elif isinstance(value, str):
        items = []
        for part in value.split(","):
            if not part or "=" not in part:
                continue
            key, hash_value = part.split("=", 1)
            items.append((key, hash_value))
    else:
        return hashes

    for key, hash_value in items:
        if key is None or hash_value is None:
            continue
        normalized_key = str(key).strip().lower()
        normalized_value = str(hash_value).strip()
        if not normalized_key or not normalized_value:
            continue
        hashes[normalized_key] = normalized_value
    return hashes


def _map_severity_id(value: Any) -> int:
    if not value:
        return 1
    if isinstance(value, int):
        return value
    text = str(value).lower()
    if text in {"information", "informational"}:
        return 1
    if text in {"low"}:
        return 2
    if text in {"medium"}:
        return 3
    if text in {"high"}:
        return 4
    if text in {"critical"}:
        return 5
    return 0
