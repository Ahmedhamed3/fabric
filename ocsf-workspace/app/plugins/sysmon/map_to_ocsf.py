import os
from typing import Any, Dict, Optional

from app.ocsf.constants import (
    CATEGORY_UID_SYSTEM,
    PROCESS_ACTIVITY_CLASS_UID,
    PROCESS_ACTIVITY_LAUNCH_ID,
    PROCESS_ACTIVITY_TERMINATE_ID,
    PROCESS_ACTIVITY_OPEN_ID,
    PROCESS_ACTIVITY_INJECT_ID,
    DEFAULT_SEVERITY_ID,
    DEFAULT_METADATA_PRODUCT,
    DEFAULT_METADATA_VERSION,
    DEFAULT_DEVICE_TYPE_ID,
    DEFAULT_FILE_TYPE_ID,
    FILE_SYSTEM_ACTIVITY_CLASS_UID,
    FILE_SYSTEM_ACTIVITY_CREATE_ID,
    MODULE_ACTIVITY_CLASS_UID,
    MODULE_ACTIVITY_LOAD_ID,
    REGISTRY_KEY_ACTIVITY_CLASS_UID,
    REGISTRY_VALUE_ACTIVITY_CLASS_UID,
    REGISTRY_KEY_ACTIVITY_CREATE_ID,
    REGISTRY_KEY_ACTIVITY_MODIFY_ID,
    REGISTRY_KEY_ACTIVITY_DELETE_ID,
    REGISTRY_KEY_ACTIVITY_RENAME_ID,
    REGISTRY_VALUE_ACTIVITY_SET_ID,
    REGISTRY_VALUE_ACTIVITY_MODIFY_ID,
    REGISTRY_VALUE_ACTIVITY_DELETE_ID,
    calc_type_uid,
)
from app.ocsf.process import build_parent_process, build_process
from app.plugins.sysmon.parse import SysmonNormalized

NETWORK_CATEGORY_UID = 4
NETWORK_ACTIVITY_CLASS_UID = 4001
NETWORK_ACTIVITY_OPEN_ID = 1
NETWORK_ACTIVITY_OPEN_TYPE_UID = 400101
DNS_ACTIVITY_CLASS_UID = 1006
DNS_ACTIVITY_QUERY_ID = 1

def _basename(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    return os.path.basename(path)

def _parse_user(user: Optional[str]) -> Optional[Dict[str, str]]:
    if not user:
        return None
    if "\\" in user:
        domain, name = user.split("\\", 1)
        return {"name": name, "domain": domain}
    if "@" in user:
        name, domain = user.split("@", 1)
        return {"name": name, "domain": domain}
    return {"name": user}

def _safe_int(value: Any) -> Optional[int]:
    try:
        if value is None:
            return None
        return int(value)
    except (TypeError, ValueError):
        return None

def _event_data_value(event_data: Optional[Dict[str, Any]], key: str) -> Optional[Any]:
    if not event_data:
        return None
    nested = event_data.get("EventData")
    if isinstance(nested, dict) and key in nested:
        return nested.get(key)
    return event_data.get(key)

def _build_actor_and_device(ev: SysmonNormalized) -> tuple[Dict[str, Any], Dict[str, Any]]:
    actor: Dict[str, Any] = {}
    user = _parse_user(ev.user)
    if user:
        actor["user"] = user

    process = build_process(
        pid=ev.pid,
        uid=ev.process_guid,
        command_line=ev.cmd,
        executable=ev.image,
        include_file=True,
    )
    if ev.parent_pid is not None or ev.parent_image or ev.parent_cmd or ev.parent_process_guid:
        parent = build_parent_process(
            pid=ev.parent_pid,
            uid=ev.parent_process_guid,
            command_line=ev.parent_cmd,
            executable=ev.parent_image,
        )
        if parent:
            process["parent_process"] = parent
    if process:
        actor["process"] = process

    device: Dict[str, Any] = {"type_id": DEFAULT_DEVICE_TYPE_ID}
    if ev.host:
        device["hostname"] = ev.host

    return actor, device

def _build_target_process(ev: SysmonNormalized) -> Dict[str, Any]:
    return build_process(
        pid=ev.target_pid,
        uid=ev.target_process_guid,
        executable=ev.target_image,
        include_file=True,
    )

def _split_registry_target(target_object: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    if not target_object:
        return None, None
    if "\\" in target_object:
        path, name = target_object.rsplit("\\", 1)
        return path, name
    return target_object, None

def map_sysmon_eventid1_to_ocsf(ev: SysmonNormalized) -> Optional[Dict[str, Any]]:
    """
    Maps ONLY Sysmon EventID 1 (Process Create) -> OCSF process_activity Launch.
    Returns None if event is not EventID 1.
    """
    if ev.event_id != 1:
        return None

    type_uid = calc_type_uid(PROCESS_ACTIVITY_CLASS_UID, PROCESS_ACTIVITY_LAUNCH_ID)

    # Required by system.json: actor + device
    actor: Dict[str, Any] = {}
    if ev.user:
        actor["user"] = {"name": ev.user}  # minimal to satisfy actor

    device: Dict[str, Any] = {"type_id": DEFAULT_DEVICE_TYPE_ID}
    if ev.host:
        device["hostname"] = ev.host

    # Required by process_activity: process (and process constraint wants pid or uid)
    process = build_process(
        pid=ev.pid,
        uid=ev.process_guid,
        command_line=ev.cmd,
        executable=ev.image,
        include_file=True,
    )

    # Parent process (recommended)
    if ev.parent_pid is not None or ev.parent_image or ev.parent_cmd or ev.parent_process_guid:
        parent = build_parent_process(
            pid=ev.parent_pid,
            uid=ev.parent_process_guid,
            command_line=ev.parent_cmd,
            executable=ev.parent_image,
        )
        if parent:
            process["parent_process"] = parent

    # If we still don't have pid/uid, we can't emit a valid process object
    if "pid" not in process and "uid" not in process:
        return None

    if process:
        actor["process"] = process

    unmapped: Dict[str, Any] = {}
    if ev.process_guid:
        unmapped["process_guid"] = ev.process_guid
    if ev.parent_process_guid:
        unmapped["parent_process_guid"] = ev.parent_process_guid
    if ev.integrity_level:
        unmapped["integrity_level"] = ev.integrity_level
    if ev.current_directory:
        unmapped["current_directory"] = ev.current_directory
    if ev.event_data:
        unmapped["original_event"] = ev.event_data

    # Build OCSF event
    ocsf_event: Dict[str, Any] = {
        "activity_id": PROCESS_ACTIVITY_LAUNCH_ID,
        "category_uid": CATEGORY_UID_SYSTEM,
        "class_uid": PROCESS_ACTIVITY_CLASS_UID,
        "type_uid": type_uid,
        "time": ev.ts,
        "severity_id": DEFAULT_SEVERITY_ID,
        "metadata": {
            "product": DEFAULT_METADATA_PRODUCT,
            "version": DEFAULT_METADATA_VERSION,
        },
        "actor": actor if actor else {"app_name": "unknown"},  # still satisfies "actor has at least one"
        "device": device,
    }

    if unmapped:
        ocsf_event["unmapped"] = unmapped

    return ocsf_event

def map_sysmon_eventid3_to_ocsf(ev: SysmonNormalized) -> Optional[Dict[str, Any]]:
    """
    Maps ONLY Sysmon EventID 3 (Network Connect) -> OCSF network activity Open.
    Returns None if event is not EventID 3.
    """
    if ev.event_id != 3:
        return None

    actor: Dict[str, Any] = {}
    if ev.user:
        actor["user"] = {"name": ev.user}

    device: Dict[str, Any] = {"type_id": DEFAULT_DEVICE_TYPE_ID}
    if ev.host:
        device["hostname"] = ev.host

    network: Dict[str, Any] = {}
    if ev.src_ip or ev.src_port is not None:
        src: Dict[str, Any] = {}
        if ev.src_ip:
            src["ip"] = ev.src_ip
        if ev.src_port is not None:
            src["port"] = ev.src_port
        network["src_endpoint"] = src
    if ev.dst_ip or ev.dst_port is not None:
        dst: Dict[str, Any] = {}
        if ev.dst_ip:
            dst["ip"] = ev.dst_ip
        if ev.dst_port is not None:
            dst["port"] = ev.dst_port
        network["dst_endpoint"] = dst

    if ev.protocol:
        network["protocol"] = ev.protocol

    ocsf_event: Dict[str, Any] = {
        "activity_id": NETWORK_ACTIVITY_OPEN_ID,
        "category_uid": NETWORK_CATEGORY_UID,
        "class_uid": NETWORK_ACTIVITY_CLASS_UID,
        "type_uid": NETWORK_ACTIVITY_OPEN_TYPE_UID,
        "time": ev.ts,
        "severity_id": DEFAULT_SEVERITY_ID,
        "metadata": {
            "product": DEFAULT_METADATA_PRODUCT,
            "version": DEFAULT_METADATA_VERSION,
        },
        "actor": actor if actor else {"app_name": "unknown"},
        "device": device,
    }

    if network:
        ocsf_event["network"] = network

    return ocsf_event


def map_sysmon_eventid5_to_ocsf(ev: SysmonNormalized) -> Optional[Dict[str, Any]]:
    """
    Maps ONLY Sysmon EventID 5 (Process Terminate) -> OCSF process_activity Terminate.
    Returns None if event is not EventID 5.
    """
    if ev.event_id != 5:
        return None

    type_uid = calc_type_uid(PROCESS_ACTIVITY_CLASS_UID, PROCESS_ACTIVITY_TERMINATE_ID)

    actor, device = _build_actor_and_device(ev)
    if "process" not in actor:
        return None

    unmapped: Dict[str, Any] = {}
    if ev.process_guid:
        unmapped["process_guid"] = ev.process_guid
    if ev.parent_process_guid:
        unmapped["parent_process_guid"] = ev.parent_process_guid
    if ev.event_data:
        unmapped["original_event"] = ev.event_data

    ocsf_event: Dict[str, Any] = {
        "activity_id": PROCESS_ACTIVITY_TERMINATE_ID,
        "category_uid": CATEGORY_UID_SYSTEM,
        "class_uid": PROCESS_ACTIVITY_CLASS_UID,
        "type_uid": type_uid,
        "time": ev.ts,
        "severity_id": DEFAULT_SEVERITY_ID,
        "metadata": {
            "product": DEFAULT_METADATA_PRODUCT,
            "version": DEFAULT_METADATA_VERSION,
        },
        "actor": actor,
        "device": device,
    }

    if unmapped:
        ocsf_event["unmapped"] = unmapped

    return ocsf_event


def map_sysmon_eventid7_to_ocsf(ev: SysmonNormalized) -> Optional[Dict[str, Any]]:
    """
    Maps ONLY Sysmon EventID 7 (Image Load) -> OCSF module_activity Load.
    Returns None if event is not EventID 7.
    """
    if ev.event_id != 7:
        return None

    type_uid = MODULE_ACTIVITY_LOAD_ID

    actor, device = _build_actor_and_device(ev)
    if not actor:
        actor = {"app_name": "unknown"}

    image_loaded = _event_data_value(ev.event_data, "ImageLoaded") or ev.image_loaded

    module: Dict[str, Any] = {}
    if image_loaded:
        module["file"] = {
            "path": image_loaded,
            "name": _basename(image_loaded) or image_loaded,
            "type_id": DEFAULT_FILE_TYPE_ID,
        }

    unmapped: Dict[str, Any] = {}
    if ev.event_data:
        unmapped["original_event"] = ev.event_data

    ocsf_event: Dict[str, Any] = {
        "activity_id": MODULE_ACTIVITY_LOAD_ID,
        "category_uid": CATEGORY_UID_SYSTEM,
        "class_uid": MODULE_ACTIVITY_CLASS_UID,
        "type_uid": type_uid,
        "time": ev.ts,
        "severity_id": DEFAULT_SEVERITY_ID,
        "metadata": {
            "product": DEFAULT_METADATA_PRODUCT,
            "version": DEFAULT_METADATA_VERSION,
        },
        "actor": actor,
        "device": device,
    }

    if module:
        ocsf_event["module"] = module
    if unmapped:
        ocsf_event["unmapped"] = unmapped

    return ocsf_event


def map_sysmon_eventid8_to_ocsf(ev: SysmonNormalized) -> Optional[Dict[str, Any]]:
    """
    Maps ONLY Sysmon EventID 8 (CreateRemoteThread) -> OCSF process_activity Inject.
    Returns None if event is not EventID 8.
    """
    if ev.event_id != 8:
        return None

    type_uid = calc_type_uid(PROCESS_ACTIVITY_CLASS_UID, PROCESS_ACTIVITY_INJECT_ID)

    actor, device = _build_actor_and_device(ev)
    if not actor:
        actor = {"app_name": "unknown"}

    target_process = _build_target_process(ev)

    unmapped: Dict[str, Any] = {}
    if ev.start_address:
        unmapped["start_address"] = ev.start_address
    if ev.start_module:
        unmapped["start_module"] = ev.start_module
    if ev.event_data:
        unmapped["original_event"] = ev.event_data

    ocsf_event: Dict[str, Any] = {
        "activity_id": PROCESS_ACTIVITY_INJECT_ID,
        "category_uid": CATEGORY_UID_SYSTEM,
        "class_uid": PROCESS_ACTIVITY_CLASS_UID,
        "type_uid": type_uid,
        "time": ev.ts,
        "severity_id": DEFAULT_SEVERITY_ID,
        "metadata": {
            "product": DEFAULT_METADATA_PRODUCT,
            "version": DEFAULT_METADATA_VERSION,
        },
        "actor": actor,
        "device": device,
        "injection_type": "remote_thread",
    }

    if target_process:
        ocsf_event["process"] = target_process
    if unmapped:
        ocsf_event["unmapped"] = unmapped

    return ocsf_event


def map_sysmon_eventid10_to_ocsf(ev: SysmonNormalized) -> Optional[Dict[str, Any]]:
    """
    Maps ONLY Sysmon EventID 10 (Process Access) -> OCSF process_activity Open.
    Returns None if event is not EventID 10.
    """
    if ev.event_id != 10:
        return None

    type_uid = calc_type_uid(PROCESS_ACTIVITY_CLASS_UID, PROCESS_ACTIVITY_OPEN_ID)

    actor, device = _build_actor_and_device(ev)
    if not actor:
        actor = {"app_name": "unknown"}

    target_process = _build_target_process(ev)

    unmapped: Dict[str, Any] = {}
    if ev.granted_access:
        unmapped["granted_access"] = ev.granted_access
    if ev.event_data:
        unmapped["original_event"] = ev.event_data

    ocsf_event: Dict[str, Any] = {
        "activity_id": PROCESS_ACTIVITY_OPEN_ID,
        "category_uid": CATEGORY_UID_SYSTEM,
        "class_uid": PROCESS_ACTIVITY_CLASS_UID,
        "type_uid": type_uid,
        "time": ev.ts,
        "severity_id": DEFAULT_SEVERITY_ID,
        "metadata": {
            "product": DEFAULT_METADATA_PRODUCT,
            "version": DEFAULT_METADATA_VERSION,
        },
        "actor": actor,
        "device": device,
    }

    if ev.granted_access:
        ocsf_event["actual_permissions"] = ev.granted_access
    if target_process:
        ocsf_event["process"] = target_process
    if unmapped:
        ocsf_event["unmapped"] = unmapped

    return ocsf_event


def map_sysmon_eventid12_to_ocsf(ev: SysmonNormalized) -> Optional[Dict[str, Any]]:
    """
    Maps ONLY Sysmon EventID 12 (Registry Key Create/Delete) -> OCSF registry_key_activity.
    Returns None if event is not EventID 12.
    """
    if ev.event_id != 12:
        return None

    event_type = (ev.event_type or "").lower()
    if event_type == "createkey":
        activity_id = REGISTRY_KEY_ACTIVITY_CREATE_ID
    elif event_type == "deletekey":
        activity_id = REGISTRY_KEY_ACTIVITY_DELETE_ID
    else:
        activity_id = REGISTRY_KEY_ACTIVITY_MODIFY_ID

    type_uid = calc_type_uid(REGISTRY_KEY_ACTIVITY_CLASS_UID, activity_id)

    actor, device = _build_actor_and_device(ev)
    if not actor:
        actor = {"app_name": "unknown"}

    reg_key_path = _event_data_value(ev.event_data, "TargetObject") or ev.target_object
    reg_key: Dict[str, Any] = {}
    if reg_key_path:
        reg_key["path"] = reg_key_path

    unmapped: Dict[str, Any] = {}
    if ev.event_data:
        unmapped["original_event"] = ev.event_data

    ocsf_event: Dict[str, Any] = {
        "activity_id": activity_id,
        "category_uid": CATEGORY_UID_SYSTEM,
        "class_uid": REGISTRY_KEY_ACTIVITY_CLASS_UID,
        "type_uid": type_uid,
        "time": ev.ts,
        "severity_id": DEFAULT_SEVERITY_ID,
        "metadata": {
            "product": DEFAULT_METADATA_PRODUCT,
            "version": DEFAULT_METADATA_VERSION,
        },
        "actor": actor,
        "device": device,
    }

    if reg_key:
        ocsf_event["reg_key"] = reg_key
    if unmapped:
        ocsf_event["unmapped"] = unmapped

    return ocsf_event


def map_sysmon_eventid13_to_ocsf(ev: SysmonNormalized) -> Optional[Dict[str, Any]]:
    """
    Maps ONLY Sysmon EventID 13 (Registry Value Set) -> OCSF registry_value_activity Set.
    Returns None if event is not EventID 13.
    """
    if ev.event_id != 13:
        return None

    type_uid = calc_type_uid(REGISTRY_VALUE_ACTIVITY_CLASS_UID, REGISTRY_VALUE_ACTIVITY_SET_ID)

    actor, device = _build_actor_and_device(ev)
    if not actor:
        actor = {"app_name": "unknown"}

    target_object = _event_data_value(ev.event_data, "TargetObject") or ev.target_object
    reg_path, reg_name = _split_registry_target(target_object)

    reg_value: Dict[str, Any] = {}
    if reg_path:
        reg_value["path"] = reg_path
    if reg_name:
        reg_value["name"] = reg_name
    if ev.details:
        reg_value["data"] = ev.details

    unmapped: Dict[str, Any] = {}
    if ev.event_data:
        unmapped["original_event"] = ev.event_data

    ocsf_event: Dict[str, Any] = {
        "activity_id": REGISTRY_VALUE_ACTIVITY_SET_ID,
        "category_uid": CATEGORY_UID_SYSTEM,
        "class_uid": REGISTRY_VALUE_ACTIVITY_CLASS_UID,
        "type_uid": type_uid,
        "time": ev.ts,
        "severity_id": DEFAULT_SEVERITY_ID,
        "metadata": {
            "product": DEFAULT_METADATA_PRODUCT,
            "version": DEFAULT_METADATA_VERSION,
        },
        "actor": actor,
        "device": device,
    }

    if reg_value:
        ocsf_event["reg_value"] = reg_value
    if unmapped:
        ocsf_event["unmapped"] = unmapped

    return ocsf_event


def map_sysmon_eventid14_to_ocsf(ev: SysmonNormalized) -> Optional[Dict[str, Any]]:
    """
    Maps ONLY Sysmon EventID 14 (Registry Key/Value Rename) -> OCSF registry activity.
    Returns None if event is not EventID 14.
    """
    if ev.event_id != 14:
        return None

    event_type = (ev.event_type or "").lower()
    is_value = event_type == "renamevalue"
    if is_value:
        activity_id = REGISTRY_VALUE_ACTIVITY_MODIFY_ID
        class_uid = REGISTRY_VALUE_ACTIVITY_CLASS_UID
    else:
        activity_id = REGISTRY_KEY_ACTIVITY_RENAME_ID
        class_uid = REGISTRY_KEY_ACTIVITY_CLASS_UID

    type_uid = calc_type_uid(class_uid, activity_id)

    actor, device = _build_actor_and_device(ev)
    if not actor:
        actor = {"app_name": "unknown"}

    target_object = _event_data_value(ev.event_data, "TargetObject") or ev.target_object
    new_name = _event_data_value(ev.event_data, "NewName") or ev.new_name

    unmapped: Dict[str, Any] = {}
    if ev.event_data:
        unmapped["original_event"] = ev.event_data

    ocsf_event: Dict[str, Any] = {
        "activity_id": activity_id,
        "category_uid": CATEGORY_UID_SYSTEM,
        "class_uid": class_uid,
        "type_uid": type_uid,
        "time": ev.ts,
        "severity_id": DEFAULT_SEVERITY_ID,
        "metadata": {
            "product": DEFAULT_METADATA_PRODUCT,
            "version": DEFAULT_METADATA_VERSION,
        },
        "actor": actor,
        "device": device,
    }

    if is_value:
        reg_path, reg_name = _split_registry_target(target_object)
        reg_value: Dict[str, Any] = {}
        if reg_path:
            reg_value["path"] = reg_path
        if new_name:
            _, new_value_name = _split_registry_target(new_name)
            if new_value_name:
                reg_value["name"] = new_value_name
        elif reg_name:
            reg_value["name"] = reg_name
        if reg_name and reg_path:
            ocsf_event["prev_reg_value"] = {"name": reg_name, "path": reg_path}
        if reg_value:
            ocsf_event["reg_value"] = reg_value
    else:
        reg_key: Dict[str, Any] = {}
        if new_name:
            reg_key["path"] = new_name
            if target_object:
                ocsf_event["prev_reg_key"] = {"path": target_object}
        elif target_object:
            reg_key["path"] = target_object
        if reg_key:
            ocsf_event["reg_key"] = reg_key

    if unmapped:
        ocsf_event["unmapped"] = unmapped

    return ocsf_event


def map_sysmon_eventid11_to_ocsf(ev: SysmonNormalized) -> Optional[Dict[str, Any]]:
    """
    Maps ONLY Sysmon EventID 11 (File Create) -> OCSF File System Activity Create.
    Returns None if event is not EventID 11.
    """
    if ev.event_id != 11:
        return None

    type_uid = calc_type_uid(FILE_SYSTEM_ACTIVITY_CLASS_UID, FILE_SYSTEM_ACTIVITY_CREATE_ID)

    target_filename = _event_data_value(ev.event_data, "TargetFilename") or ev.target_filename
    image = _event_data_value(ev.event_data, "Image") or ev.image
    process_id = _event_data_value(ev.event_data, "ProcessId") or ev.pid

    actor: Dict[str, Any] = {}
    process: Dict[str, Any] = {}
    if image:
        process["executable"] = image
    pid = _safe_int(process_id)
    if pid is not None:
        process["pid"] = pid
    if process:
        actor["process"] = process
    if ev.user:
        actor["user"] = {"name": ev.user}

    file_obj: Dict[str, Any] = {}
    if target_filename:
        file_obj["path"] = target_filename
        file_obj["name"] = _basename(target_filename) or target_filename
        file_obj["type_id"] = DEFAULT_FILE_TYPE_ID

    unmapped: Dict[str, Any] = {}
    if ev.process_guid:
        unmapped["process_guid"] = ev.process_guid
    if ev.rule_name:
        unmapped["rule_name"] = ev.rule_name
    if ev.user:
        unmapped["user"] = ev.user
    if ev.creation_utctime:
        unmapped["creation_utctime"] = ev.creation_utctime
    if ev.event_data:
        unmapped["original_event"] = ev.event_data

    ocsf_event: Dict[str, Any] = {
        "activity_id": FILE_SYSTEM_ACTIVITY_CREATE_ID,
        "category_uid": CATEGORY_UID_SYSTEM,
        "class_uid": FILE_SYSTEM_ACTIVITY_CLASS_UID,
        "type_uid": type_uid,
        "time": ev.ts,
        "severity_id": DEFAULT_SEVERITY_ID,
        "metadata": {
            "product": DEFAULT_METADATA_PRODUCT,
            "version": DEFAULT_METADATA_VERSION,
        },
        "actor": actor if actor else {"app_name": "unknown"},
    }

    if file_obj:
        ocsf_event["file"] = file_obj
    if unmapped:
        ocsf_event["unmapped"] = unmapped

    return ocsf_event


def map_sysmon_eventid15_to_ocsf(ev: SysmonNormalized) -> Optional[Dict[str, Any]]:
    """
    Maps ONLY Sysmon EventID 15 (FileCreateStreamHash) -> OCSF File System Activity Create.
    Returns None if event is not EventID 15.
    """
    if ev.event_id != 15:
        return None

    type_uid = calc_type_uid(FILE_SYSTEM_ACTIVITY_CLASS_UID, FILE_SYSTEM_ACTIVITY_CREATE_ID)

    target_filename = _event_data_value(ev.event_data, "TargetFilename") or ev.target_filename
    image = _event_data_value(ev.event_data, "Image") or ev.image
    process_id = _event_data_value(ev.event_data, "ProcessId") or ev.pid
    hashes = ev.hashes or {}

    actor: Dict[str, Any] = {}
    process: Dict[str, Any] = {}
    if image:
        process["executable"] = image
    pid = _safe_int(process_id)
    if pid is not None:
        process["pid"] = pid
    if process:
        actor["process"] = process
    if ev.user:
        actor["user"] = {"name": ev.user}

    file_obj: Dict[str, Any] = {}
    if target_filename:
        file_obj["path"] = target_filename
        file_obj["name"] = _basename(target_filename) or target_filename
        file_obj["type_id"] = DEFAULT_FILE_TYPE_ID
    if hashes:
        file_obj["hash"] = dict(hashes)

    unmapped: Dict[str, Any] = {}
    if ev.process_guid:
        unmapped["process_guid"] = ev.process_guid
    if ev.user:
        unmapped["user"] = ev.user
    if ev.creation_utctime:
        unmapped["creation_utctime"] = ev.creation_utctime
    if ev.event_data:
        unmapped["original_event"] = ev.event_data

    ocsf_event: Dict[str, Any] = {
        "activity_id": FILE_SYSTEM_ACTIVITY_CREATE_ID,
        "category_uid": CATEGORY_UID_SYSTEM,
        "class_uid": FILE_SYSTEM_ACTIVITY_CLASS_UID,
        "type_uid": type_uid,
        "time": ev.ts,
        "severity_id": DEFAULT_SEVERITY_ID,
        "metadata": {
            "product": DEFAULT_METADATA_PRODUCT,
            "version": DEFAULT_METADATA_VERSION,
        },
        "actor": actor if actor else {"app_name": "unknown"},
    }

    if file_obj:
        ocsf_event["file"] = file_obj
    if unmapped:
        ocsf_event["unmapped"] = unmapped

    return ocsf_event


def map_sysmon_eventid22_to_ocsf(ev: SysmonNormalized) -> Optional[Dict[str, Any]]:
    """
    Maps ONLY Sysmon EventID 22 (DNS Query) -> OCSF DNS Activity Query.
    Returns None if event is not EventID 22.
    """
    if ev.event_id != 22:
        return None

    type_uid = calc_type_uid(DNS_ACTIVITY_CLASS_UID, DNS_ACTIVITY_QUERY_ID)

    query_name = _event_data_value(ev.event_data, "QueryName") or ev.query_name
    query_results = _event_data_value(ev.event_data, "QueryResults") or ev.query_results
    process_image = _event_data_value(ev.event_data, "Image") or ev.image
    process_id = _event_data_value(ev.event_data, "ProcessId") or ev.pid

    dns: Dict[str, Any] = {}
    if query_name:
        dns["question"] = {"name": query_name}
    if query_results:
        dns["answers"] = [{"data": query_results}]

    actor: Dict[str, Any] = {}
    process: Dict[str, Any] = {}
    if process_image:
        process["executable"] = process_image
    pid = _safe_int(process_id)
    if pid is not None:
        process["pid"] = pid
    if process:
        actor["process"] = process
    if ev.user:
        actor["user"] = {"name": ev.user}

    unmapped: Dict[str, Any] = {}
    if ev.event_data:
        unmapped["original_event"] = ev.event_data

    ocsf_event: Dict[str, Any] = {
        "activity_id": DNS_ACTIVITY_QUERY_ID,
        "class_uid": DNS_ACTIVITY_CLASS_UID,
        "type_uid": type_uid,
        "time": ev.ts,
        "severity_id": DEFAULT_SEVERITY_ID,
        "metadata": {
            "product": DEFAULT_METADATA_PRODUCT,
            "version": DEFAULT_METADATA_VERSION,
        },
        "actor": actor if actor else {"app_name": "unknown"},
    }

    if dns:
        ocsf_event["dns"] = dns
    if unmapped:
        ocsf_event["unmapped"] = unmapped

    return ocsf_event
