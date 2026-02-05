from __future__ import annotations

import ntpath
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional

from app.normalizers.windows_security_to_ocsf import taxonomy
from app.normalizers.windows_security_to_ocsf.windows_security_xml import parse_event_data, parse_system_data

LOGON_TYPE_CAPTIONS = {
    0: "Unknown",
    1: "System",
    2: "Interactive",
    3: "Network",
    4: "Batch",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext",
    9: "NewCredentials",
    10: "RemoteInteractive",
    11: "CachedInteractive",
    12: "CachedRemoteInteractive",
    13: "CachedUnlock",
    99: "Other",
}


@dataclass(frozen=True)
class MappingContext:
    ocsf_version: str


def map_raw_event(raw_event: Dict[str, Any], context: MappingContext) -> Optional[Dict[str, Any]]:
    event_id = _get_event_id(raw_event)
    if event_id in {4624, 4625}:
        return _map_authentication_event(raw_event, context, event_id)
    if event_id == 4688:
        return _map_process_activity(raw_event, context)
    if event_id == 4689:
        return _map_process_termination(raw_event, context)
    if event_id == 4673:
        return _map_privilege_use(raw_event, context)
    if event_id == 4697:
        return _map_service_installed(raw_event, context)
    if event_id == 4698:
        return _map_scheduled_task_created(raw_event, context)
    return None


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
    if not xml:
        return None
    system_data = parse_system_data(xml)
    return system_data.get("time_created")


def _get_raw_xml(raw_event: Dict[str, Any]) -> str:
    raw = raw_event.get("raw") or {}
    raw_xml = raw.get("xml")
    if raw_xml:
        return raw_xml
    raw_data = raw.get("data")
    return raw_data if isinstance(raw_data, str) else ""


def _normalize_value(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, list):
        if not value:
            return None
        value = value[0]
    text = str(value).strip()
    if not text or text == "-":
        return None
    return text


def _to_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        if isinstance(value, str):
            return int(value, 0)
        return int(value)
    except (TypeError, ValueError):
        return None


def _derive_process_name(path: str) -> Optional[str]:
    if not path:
        return None
    name = ntpath.basename(path)
    return name or None


def _split_privileges(value: Optional[str]) -> list[str]:
    if not value:
        return []
    parts = re.split(r"[\s,]+", value.strip())
    return [part for part in parts if part]


def _get_privilege_field(event_data: Dict[str, str]) -> Optional[str]:
    for key in ("PrivilegeList", "Privileges", "Privilege"):
        value = event_data.get(key)
        if value:
            return value
    return None


def _get_event_data(raw_event: Dict[str, Any]) -> Dict[str, str]:
    parsed = raw_event.get("parsed") or {}
    event_data = parsed.get("event_data")
    if isinstance(event_data, dict):
        return {str(k): "" if v is None else str(v) for k, v in event_data.items()}
    raw = raw_event.get("raw") or {}
    raw_format = raw.get("format")
    raw_data = raw.get("data")
    if raw_format == "json" and isinstance(raw_data, dict):
        data = raw_data.get("event_data") or raw_data.get("EventData")
        if isinstance(data, dict):
            return {str(k): "" if v is None else str(v) for k, v in data.items()}
    xml = _get_raw_xml(raw_event)
    if xml:
        return parse_event_data(xml)
    return {}


def _get_system_info(raw_event: Dict[str, Any]) -> Dict[str, str]:
    raw = raw_event.get("raw") or {}
    raw_data = raw.get("data")
    if isinstance(raw_data, dict):
        info: Dict[str, str] = {}
        for key in ("computer", "Computer"):
            value = _normalize_value(raw_data.get(key))
            if value:
                info["computer"] = value
                break
        for key in ("provider", "Provider"):
            value = _normalize_value(raw_data.get(key))
            if value:
                info["provider"] = value
                break
        return info
    xml = _get_raw_xml(raw_event)
    return parse_system_data(xml) if xml else {}


def mapping_attempted(raw_event: Dict[str, Any]) -> bool:
    event_id = _get_event_id(raw_event)
    return event_id in {4624, 4625, 4673, 4688, 4689, 4697, 4698}


def missing_required_fields(raw_event: Dict[str, Any]) -> list[str]:
    event_id = _get_event_id(raw_event)
    if event_id == 4673:
        event_data = _get_event_data(raw_event)
        privilege_value = _normalize_value(_get_privilege_field(event_data))
        privileges = _split_privileges(privilege_value)
        subject_user = _build_user(
            sid=_normalize_value(event_data.get("SubjectUserSid")),
            name=_normalize_value(event_data.get("SubjectUserName")),
            domain=_normalize_value(event_data.get("SubjectDomainName")),
        )
        time_value = _get_event_time(raw_event)
        missing: list[str] = []
        if time_value is None:
            missing.append("Timestamp")
        if not (subject_user.get("uid") or subject_user.get("name")):
            missing.append("SubjectUser")
        if not privileges:
            missing.append("PrivilegeList")
        return missing
    if event_id == 4697:
        event_data = _get_event_data(raw_event)
        time_value = _get_event_time(raw_event)
        service_name = _normalize_value(event_data.get("ServiceName"))
        service_file_name = _normalize_value(event_data.get("ServiceFileName"))
        missing: list[str] = []
        if time_value is None:
            missing.append("Timestamp")
        if service_name is None:
            missing.append("ServiceName")
        if service_file_name is None:
            missing.append("ServiceFileName")
        return missing
    if event_id == 4698:
        event_data = _get_event_data(raw_event)
        time_value = _get_event_time(raw_event)
        task_name = _normalize_value(event_data.get("TaskName"))
        missing = []
        if time_value is None:
            missing.append("Timestamp")
        if task_name is None:
            missing.append("TaskName")
        return missing
    if event_id != 4689:
        return []
    event_data = _get_event_data(raw_event)
    process_pid = _to_int(_normalize_value(event_data.get("ProcessId")))
    process_path = _normalize_value(event_data.get("ProcessName"))
    time_value = _get_event_time(raw_event)
    missing: list[str] = []
    if process_pid is None:
        missing.append("ProcessId")
    if process_path is None:
        missing.append("ProcessName")
    if time_value is None:
        missing.append("Timestamp")
    return missing


def _base_event(
    raw_event: Dict[str, Any],
    context: MappingContext,
    *,
    category_uid: int,
    class_uid: int,
    activity_id: int,
) -> Dict[str, Any]:
    ids = raw_event.get("ids") or {}
    source = raw_event.get("source") or {}
    host = raw_event.get("host") or {}
    time_value = _get_event_time(raw_event)
    record_id = ids.get("record_id")
    event_code = ids.get("event_id")
    channel = source.get("channel")
    product_name = source.get("product") or "windows-security-auditing"
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
        "log_format": (raw_event.get("raw") or {}).get("format"),
        "original_time": time_value,
    }
    metadata = {key: value for key, value in metadata.items() if value is not None}
    device = {"type_id": taxonomy.DEVICE_TYPE_UNKNOWN_ID}
    hostname = host.get("hostname") or _get_system_info(raw_event).get("computer")
    if hostname:
        device["hostname"] = hostname
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


def _map_authentication_event(
    raw_event: Dict[str, Any],
    context: MappingContext,
    event_id: int,
) -> Dict[str, Any]:
    event_data = _get_event_data(raw_event)
    system_info = _get_system_info(raw_event)

    subject_user = _build_user(
        sid=_normalize_value(event_data.get("SubjectUserSid")),
        name=_normalize_value(event_data.get("SubjectUserName")),
        domain=_normalize_value(event_data.get("SubjectDomainName")),
    )
    target_user = _build_user(
        sid=_normalize_value(event_data.get("TargetUserSid")),
        name=_normalize_value(event_data.get("TargetUserName")),
        domain=_normalize_value(event_data.get("TargetDomainName")),
    )
    logon_type_raw = _normalize_value(event_data.get("LogonType"))
    logon_type_id, logon_type = _map_logon_type(logon_type_raw)
    ip_address = _normalize_value(event_data.get("IpAddress"))
    ip_port = _to_int(_normalize_value(event_data.get("IpPort")))
    workstation = _normalize_value(event_data.get("WorkstationName"))

    class_uid = taxonomy.to_class_uid(
        taxonomy.IAM_CATEGORY_UID,
        taxonomy.AUTHENTICATION_ACTIVITY_UID,
    )
    base = _base_event(
        raw_event,
        context,
        category_uid=taxonomy.IAM_CATEGORY_UID,
        class_uid=class_uid,
        activity_id=taxonomy.AUTHENTICATION_LOGON_ID,
    )

    status_id = 1 if event_id == 4624 else 2
    status = "Success" if event_id == 4624 else "Failure"
    base["status_id"] = status_id
    base["status"] = status

    if logon_type_id is not None:
        base["logon_type_id"] = logon_type_id
    if logon_type:
        base["logon_type"] = logon_type

    logon_process = _normalize_value(event_data.get("LogonProcessName"))
    if logon_process:
        base["logon_process"] = {"name": logon_process}

    auth_protocol = _normalize_value(event_data.get("AuthenticationPackageName"))
    if auth_protocol:
        base["auth_protocol"] = auth_protocol

    status_code = _normalize_value(event_data.get("Status"))
    sub_status = _normalize_value(event_data.get("SubStatus"))
    failure_reason = _normalize_value(event_data.get("FailureReason"))
    status_detail = _build_status_detail(failure_reason, status_code, sub_status)
    if status_code:
        base["status_code"] = status_code
    if status_detail:
        base["status_detail"] = status_detail

    actor: Dict[str, Any] = {}
    if subject_user:
        actor["user"] = subject_user
    if actor:
        base["actor"] = actor

    base["user"] = target_user if target_user else {}

    src_endpoint = _build_endpoint(ip_address=ip_address, port=ip_port, hostname=workstation)
    if src_endpoint:
        base["src_endpoint"] = src_endpoint

    dst_hostname = system_info.get("computer") or (raw_event.get("host") or {}).get("hostname")
    dst_endpoint = _build_endpoint(ip_address=None, port=None, hostname=dst_hostname)
    if dst_endpoint:
        base["dst_endpoint"] = dst_endpoint

    logon_id = _normalize_value(event_data.get("LogonId"))
    if logon_id:
        base["session"] = {"uid": logon_id}

    process_name = _normalize_value(event_data.get("ProcessName"))
    if process_name:
        base.setdefault("unmapped", {})["process_name"] = process_name

    return base


def _map_process_activity(
    raw_event: Dict[str, Any],
    context: MappingContext,
) -> Optional[Dict[str, Any]]:
    event_data = _get_event_data(raw_event)
    system_info = _get_system_info(raw_event)

    process_pid = _to_int(_normalize_value(event_data.get("NewProcessId")))
    process_path = _normalize_value(event_data.get("NewProcessName"))
    process_cmd_line = _normalize_value(event_data.get("CommandLine"))

    parent_pid = _to_int(_normalize_value(event_data.get("ParentProcessId")))
    if parent_pid is None:
        parent_pid = _to_int(_normalize_value(event_data.get("ProcessId")))
    parent_path = _normalize_value(event_data.get("ParentProcessName"))
    if parent_path is None:
        parent_path = _normalize_value(event_data.get("ProcessName"))

    user = _build_user(
        sid=_normalize_value(event_data.get("SubjectUserSid")),
        name=_normalize_value(event_data.get("SubjectUserName")),
        domain=_normalize_value(event_data.get("SubjectDomainName")),
    )
    hostname = (raw_event.get("host") or {}).get("hostname") or system_info.get("computer")
    time_value = _get_event_time(raw_event)

    if (
        process_pid is None
        or process_path is None
        or process_cmd_line is None
        or parent_path is None
        or not user.get("name")
        or not user.get("domain")
        or hostname is None
        or time_value is None
    ):
        return None

    process: Dict[str, Any] = {
        "pid": process_pid,
        "path": process_path,
        "cmd_line": process_cmd_line,
    }
    parent_process: Dict[str, Any] = {"path": parent_path}
    if parent_pid is not None:
        parent_process["pid"] = parent_pid
    process["parent_process"] = parent_process

    class_uid = taxonomy.to_class_uid(taxonomy.SYSTEM_CATEGORY_UID, taxonomy.PROCESS_ACTIVITY_UID)
    base = _base_event(
        raw_event,
        context,
        category_uid=taxonomy.SYSTEM_CATEGORY_UID,
        class_uid=class_uid,
        activity_id=taxonomy.PROCESS_ACTIVITY_LAUNCH_ID,
    )
    base["actor"] = {"user": user}
    base["process"] = process
    return base


def _map_process_termination(
    raw_event: Dict[str, Any],
    context: MappingContext,
) -> Optional[Dict[str, Any]]:
    event_data = _get_event_data(raw_event)

    process_pid = _to_int(_normalize_value(event_data.get("ProcessId")))
    process_path = _normalize_value(event_data.get("ProcessName"))
    time_value = _get_event_time(raw_event)
    if process_pid is None or process_path is None or time_value is None:
        return None

    user = _build_user(
        sid=_normalize_value(event_data.get("SubjectUserSid")),
        name=_normalize_value(event_data.get("SubjectUserName")),
        domain=_normalize_value(event_data.get("SubjectDomainName")),
    )
    process_name = _derive_process_name(process_path)

    process: Dict[str, Any] = {
        "pid": process_pid,
        "path": process_path,
    }
    if process_name:
        process["name"] = process_name

    class_uid = taxonomy.to_class_uid(taxonomy.SYSTEM_CATEGORY_UID, taxonomy.PROCESS_ACTIVITY_UID)
    base = _base_event(
        raw_event,
        context,
        category_uid=taxonomy.SYSTEM_CATEGORY_UID,
        class_uid=class_uid,
        activity_id=taxonomy.PROCESS_ACTIVITY_TERMINATE_ID,
    )
    if user:
        base["actor"] = {"user": user}
    base["process"] = process
    return base


def _map_privilege_use(
    raw_event: Dict[str, Any],
    context: MappingContext,
) -> Optional[Dict[str, Any]]:
    event_data = _get_event_data(raw_event)

    subject_user = _build_user(
        sid=_normalize_value(event_data.get("SubjectUserSid")),
        name=_normalize_value(event_data.get("SubjectUserName")),
        domain=_normalize_value(event_data.get("SubjectDomainName")),
    )
    time_value = _get_event_time(raw_event)
    privilege_value = _normalize_value(_get_privilege_field(event_data))
    privileges = _split_privileges(privilege_value)

    if time_value is None or not privileges or not (subject_user.get("uid") or subject_user.get("name")):
        return None

    class_uid = taxonomy.to_class_uid(
        taxonomy.IAM_CATEGORY_UID,
        taxonomy.AUTHORIZE_SESSION_ACTIVITY_UID,
    )
    base = _base_event(
        raw_event,
        context,
        category_uid=taxonomy.IAM_CATEGORY_UID,
        class_uid=class_uid,
        activity_id=taxonomy.AUTHORIZE_SESSION_ASSIGN_PRIVILEGES_ID,
    )
    base["user"] = subject_user
    base["privileges"] = privileges
    if subject_user:
        base["actor"] = {"user": subject_user}

    logon_id = _normalize_value(event_data.get("SubjectLogonId"))
    if logon_id is None:
        logon_id = _normalize_value(event_data.get("LogonId"))
    if logon_id:
        base["session"] = {"uid": logon_id}

    process_pid = _to_int(_normalize_value(event_data.get("ProcessId")))
    process_path = _normalize_value(event_data.get("ProcessName"))
    service_name = _normalize_value(event_data.get("Service"))
    object_server = _normalize_value(event_data.get("ObjectServer"))
    if process_pid is not None or process_path or service_name or object_server:
        process: Dict[str, Any] = {}
        if process_pid is not None:
            process["pid"] = process_pid
        if process_path:
            process["path"] = process_path
            process_name = _derive_process_name(process_path)
            if process_name:
                process["name"] = process_name
        if service_name:
            process["service"] = service_name
        if object_server:
            process["object_server"] = object_server
        base.setdefault("unmapped", {})["process"] = process

    return base


def _map_service_installed(
    raw_event: Dict[str, Any],
    context: MappingContext,
) -> Optional[Dict[str, Any]]:
    event_data = _get_event_data(raw_event)

    time_value = _get_event_time(raw_event)
    service_name = _normalize_value(event_data.get("ServiceName"))
    service_file_name = _normalize_value(event_data.get("ServiceFileName"))
    if time_value is None or service_name is None or service_file_name is None:
        return None

    service_type = _normalize_value(event_data.get("ServiceType"))
    start_type = _normalize_value(event_data.get("StartType"))
    account_name = _normalize_value(event_data.get("AccountName"))

    process_pid = _to_int(_normalize_value(event_data.get("ProcessId")))
    process_name = _derive_process_name(service_file_name)

    actor_user = _build_user(
        sid=_normalize_value(event_data.get("SubjectUserSid")),
        name=_normalize_value(event_data.get("SubjectUserName")),
        domain=_normalize_value(event_data.get("SubjectDomainName")),
    )

    class_uid = taxonomy.to_class_uid(taxonomy.SYSTEM_CATEGORY_UID, taxonomy.PROCESS_ACTIVITY_UID)
    base = _base_event(
        raw_event,
        context,
        category_uid=taxonomy.SYSTEM_CATEGORY_UID,
        class_uid=class_uid,
        activity_id=taxonomy.PROCESS_ACTIVITY_LAUNCH_ID,
    )

    process: Dict[str, Any] = {"path": service_file_name}
    if process_name:
        process["name"] = process_name
    if process_pid is not None:
        process["pid"] = process_pid

    base["process"] = process
    if actor_user:
        base["actor"] = {"user": actor_user}

    unmapped_service: Dict[str, Any] = {"name": service_name}
    if start_type:
        unmapped_service["start_type"] = start_type
    if service_type:
        unmapped_service["service_type"] = service_type
    if account_name:
        unmapped_service["account"] = account_name
    base.setdefault("unmapped", {})["service"] = unmapped_service

    return base


def _map_scheduled_task_created(
    raw_event: Dict[str, Any],
    context: MappingContext,
) -> Optional[Dict[str, Any]]:
    event_data = _get_event_data(raw_event)

    time_value = _get_event_time(raw_event)
    task_name = _normalize_value(event_data.get("TaskName"))
    if time_value is None or task_name is None:
        return None

    task_xml = _normalize_value(event_data.get("TaskContent"))
    if task_xml is None:
        task_xml = _normalize_value(event_data.get("TaskXml"))
    process_path = _normalize_value(event_data.get("ProcessName"))
    process_pid = _to_int(_normalize_value(event_data.get("ProcessId")))

    actor_user = _build_user(
        sid=_normalize_value(event_data.get("SubjectUserSid")),
        name=_normalize_value(event_data.get("SubjectUserName")),
        domain=_normalize_value(event_data.get("SubjectDomainName")),
    )

    class_uid = taxonomy.to_class_uid(taxonomy.SYSTEM_CATEGORY_UID, taxonomy.PROCESS_ACTIVITY_UID)
    base = _base_event(
        raw_event,
        context,
        category_uid=taxonomy.SYSTEM_CATEGORY_UID,
        class_uid=class_uid,
        activity_id=taxonomy.PROCESS_ACTIVITY_LAUNCH_ID,
    )

    process: Dict[str, Any] = {}
    if process_path:
        process["path"] = process_path
        process_name = _derive_process_name(process_path)
        if process_name:
            process["name"] = process_name
    if process_pid is not None:
        process["pid"] = process_pid

    base["process"] = process
    if actor_user:
        base["actor"] = {"user": actor_user}

    unmapped_task: Dict[str, Any] = {"name": task_name}
    if task_xml:
        unmapped_task["xml"] = task_xml
    if process_path:
        unmapped_task["command"] = process_path
    base.setdefault("unmapped", {})["scheduled_task"] = unmapped_task

    return base


def _build_status_detail(
    failure_reason: Optional[str],
    status_code: Optional[str],
    sub_status: Optional[str],
) -> Optional[str]:
    parts = []
    if failure_reason:
        parts.append(failure_reason)
    if status_code:
        parts.append(f"Status: {status_code}")
    if sub_status:
        parts.append(f"SubStatus: {sub_status}")
    if not parts:
        return None
    return "; ".join(parts)


def _build_user(*, sid: Optional[str], name: Optional[str], domain: Optional[str]) -> Dict[str, Any]:
    user: Dict[str, Any] = {}
    if sid:
        user["uid"] = sid
    if name:
        user["name"] = name
    if domain:
        user["domain"] = domain
    return user


def _map_logon_type(value: Optional[str]) -> tuple[Optional[int], Optional[str]]:
    if not value:
        return None, None
    numeric = _to_int(value)
    if numeric is None:
        return 99, value
    caption = LOGON_TYPE_CAPTIONS.get(numeric)
    if caption:
        return numeric, caption
    return 99, value


def _build_endpoint(
    *,
    ip_address: Optional[str],
    port: Optional[int],
    hostname: Optional[str],
) -> Dict[str, Any]:
    endpoint: Dict[str, Any] = {}
    if ip_address:
        endpoint["ip"] = ip_address
    if port is not None:
        endpoint["port"] = port
    if hostname:
        endpoint["hostname"] = hostname
    return endpoint


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
