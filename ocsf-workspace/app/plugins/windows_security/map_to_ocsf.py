import os
from typing import Any, Dict, Optional, Sequence

from app.ocsf.constants import (
    AUTHENTICATION_ACTIVITY_CLASS_UID,
    CATEGORY_UID_SYSTEM,
    DEFAULT_FILE_TYPE_ID,
    FILE_SYSTEM_ACTIVITY_CLASS_UID,
    FILE_SYSTEM_ACTIVITY_DELETE_ID,
    FILE_SYSTEM_ACTIVITY_MODIFY_ID,
    FILE_SYSTEM_ACTIVITY_OTHER_ID,
    FILE_SYSTEM_ACTIVITY_READ_ID,
    calc_type_uid,
)
from app.plugins.windows_security.parse import (
    WindowsSecurityNormalized,
    WindowsSecurityObjectAccessNormalized,
)

AUTH_LOGON_SUCCESS_ID = 1
AUTH_LOGON_FAILURE_ID = 2

FILE_ACCESS_READ = "read"
FILE_ACCESS_WRITE = "write"
FILE_ACCESS_DELETE = "delete"
FILE_ACCESS_UNKNOWN = "unknown"


def _safe_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except Exception:
        return None


def _safe_int_or_hex(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, str):
        candidate = value.strip()
        if candidate.startswith(("0x", "0X")):
            try:
                return int(candidate, 16)
            except Exception:
                return None
    try:
        return int(value)
    except Exception:
        return None


def classify_file_access(access_mask: Any, access_list: Optional[Sequence[str]]) -> str:
    if access_list:
        list_entries = [str(entry) for entry in access_list if entry is not None]
        list_entries_lower = [entry.lower() for entry in list_entries]
        for entry, entry_lower in zip(list_entries, list_entries_lower):
            if "%%1537" in entry or "delete" in entry_lower:
                return FILE_ACCESS_DELETE
        for entry, entry_lower in zip(list_entries, list_entries_lower):
            if any(code in entry for code in ("%%4417", "%%4418", "%%4430")):
                return FILE_ACCESS_WRITE
            if any(keyword in entry_lower for keyword in ("write", "append", "addfile", "addsubdirectory")):
                return FILE_ACCESS_WRITE
        for entry, entry_lower in zip(list_entries, list_entries_lower):
            if "%%4416" in entry or "%%4422" in entry or "%%4424" in entry:
                return FILE_ACCESS_READ
            if any(keyword in entry_lower for keyword in ("read", "listdirectory")):
                return FILE_ACCESS_READ
        return FILE_ACCESS_UNKNOWN

    mask = _safe_int_or_hex(str(access_mask)) if access_mask is not None else None
    if mask is None:
        return FILE_ACCESS_UNKNOWN

    read_bits = {0x1, 0x80, 0x100, 0x20000}
    write_bits = {0x2, 0x4, 0x100, 0x10000, 0x40000, 0x80000}

    if mask & 0x10000:
        return FILE_ACCESS_DELETE
    if any(mask & bit for bit in write_bits):
        return FILE_ACCESS_WRITE
    if any(mask & bit for bit in read_bits):
        return FILE_ACCESS_READ
    return FILE_ACCESS_UNKNOWN


def map_windows_security_authentication_to_ocsf(
    ev: WindowsSecurityNormalized,
) -> Optional[Dict[str, Any]]:
    if ev.event_id not in (4624, 4625):
        return None

    activity_id = AUTH_LOGON_SUCCESS_ID if ev.event_id == 4624 else AUTH_LOGON_FAILURE_ID
    type_uid = calc_type_uid(AUTHENTICATION_ACTIVITY_CLASS_UID, activity_id)

    actor: Dict[str, Any] = {}
    user: Dict[str, Any] = {}
    if ev.target_user_name:
        user["name"] = ev.target_user_name
    if ev.target_domain_name:
        user["domain"] = ev.target_domain_name
    if user:
        actor["user"] = user

    auth: Dict[str, Any] = {
        "result": "success" if ev.event_id == 4624 else "failure",
    }
    logon_type = _safe_int(ev.logon_type) if ev.logon_type else None
    if logon_type is not None:
        auth["logon_type"] = logon_type
    elif ev.logon_type:
        auth["logon_type"] = ev.logon_type

    failure_reason = ev.failure_reason or ev.status
    if ev.event_id == 4625 and failure_reason:
        auth["failure_reason"] = failure_reason

    ocsf_event: Dict[str, Any] = {
        "activity_id": activity_id,
        "class_uid": AUTHENTICATION_ACTIVITY_CLASS_UID,
        "type_uid": type_uid,
        "time": ev.time_created,
        "metadata": {"product": "Windows Security"},
        "auth": auth,
        "unmapped": {"original_event": ev.original_event},
    }

    if actor:
        ocsf_event["actor"] = actor
    if ev.ip_address:
        ocsf_event["src_endpoint"] = {"ip": ev.ip_address}
    if ev.workstation_name:
        ocsf_event["dst_endpoint"] = {"hostname": ev.workstation_name}

    return ocsf_event


def map_windows_security_object_access_to_ocsf(
    ev: WindowsSecurityObjectAccessNormalized,
) -> Optional[Dict[str, Any]]:
    if ev.event_id != 4663:
        return None

    access_type = classify_file_access(ev.access_mask, ev.access_list)
    if access_type == FILE_ACCESS_READ:
        activity_id = FILE_SYSTEM_ACTIVITY_READ_ID
    elif access_type == FILE_ACCESS_WRITE:
        activity_id = FILE_SYSTEM_ACTIVITY_MODIFY_ID
    elif access_type == FILE_ACCESS_DELETE:
        activity_id = FILE_SYSTEM_ACTIVITY_DELETE_ID
    else:
        activity_id = FILE_SYSTEM_ACTIVITY_OTHER_ID

    type_uid = calc_type_uid(FILE_SYSTEM_ACTIVITY_CLASS_UID, activity_id)

    actor: Dict[str, Any] = {}
    user: Dict[str, Any] = {}
    if ev.subject_username:
        user["name"] = ev.subject_username
    if ev.subject_domain:
        user["domain"] = ev.subject_domain
    if ev.subject_sid:
        user["sid"] = ev.subject_sid
    if user:
        actor["user"] = user

    process: Dict[str, Any] = {}
    if ev.process_name:
        process["executable"] = ev.process_name
    pid = _safe_int_or_hex(ev.process_id)
    if pid is not None:
        process["pid"] = pid
    if process:
        actor["process"] = process

    file_obj: Dict[str, Any] = {}
    if ev.object_name:
        file_obj["path"] = ev.object_name
        file_obj["name"] = os.path.basename(ev.object_name)
        file_obj["type_id"] = DEFAULT_FILE_TYPE_ID

    ocsf_event: Dict[str, Any] = {
        "activity_id": activity_id,
        "category_uid": CATEGORY_UID_SYSTEM,
        "class_uid": FILE_SYSTEM_ACTIVITY_CLASS_UID,
        "type_uid": type_uid,
        "time": ev.time_created,
        "metadata": {"product": "Windows Security"},
        "unmapped": {"original_event": ev.original_event},
    }

    if actor:
        ocsf_event["actor"] = actor
    if file_obj:
        ocsf_event["file"] = file_obj
    if ev.computer:
        ocsf_event["device"] = {"hostname": ev.computer}
    if pid is not None:
        ocsf_event["process"] = {"pid": pid}
    if ev.access_mask:
        ocsf_event["unmapped"]["access_mask"] = ev.access_mask
    if ev.access_list:
        ocsf_event["unmapped"]["access_list"] = ev.access_list
    if ev.logon_id:
        ocsf_event["unmapped"]["logon_id"] = ev.logon_id
    if ev.object_type:
        ocsf_event["unmapped"]["object_type"] = ev.object_type

    return ocsf_event
