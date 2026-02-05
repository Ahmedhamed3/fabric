from datetime import datetime, timezone
from typing import Any, Dict

from app.plugins.file_artifact.parse import FileArtifactNormalized

FILE_ACTIVITY_CLASS_UID = 1001
FILE_ACTIVITY_OBSERVED_ID = 1


def _to_iso8601_utc(ts: str | None) -> str:
    if not ts:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
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


def map_file_artifact_to_ocsf(ev: FileArtifactNormalized) -> Dict[str, Any]:
    type_uid = FILE_ACTIVITY_CLASS_UID * 100 + FILE_ACTIVITY_OBSERVED_ID

    file_obj: Dict[str, Any] = {}
    if ev.file_path:
        file_obj["path"] = ev.file_path
    if ev.file_name:
        file_obj["name"] = ev.file_name

    hash_obj: Dict[str, Any] = {}
    if ev.sha256:
        hash_obj["sha256"] = ev.sha256
    if ev.sha1:
        hash_obj["sha1"] = ev.sha1
    if ev.md5:
        hash_obj["md5"] = ev.md5
    if hash_obj:
        file_obj["hash"] = hash_obj

    if ev.file_size is not None:
        file_obj["size"] = ev.file_size

    device_obj: Dict[str, Any] = {}
    if ev.device_hostname:
        device_obj["hostname"] = ev.device_hostname

    actor_obj: Dict[str, Any] = {}
    if ev.user_name:
        user_obj: Dict[str, Any] = {"name": ev.user_name}
        if ev.user_domain:
            user_obj["domain"] = ev.user_domain
        actor_obj["user"] = user_obj

    if ev.process_pid is not None or ev.process_executable:
        process_obj: Dict[str, Any] = {}
        if ev.process_pid is not None:
            process_obj["pid"] = ev.process_pid
        if ev.process_executable:
            process_obj["executable"] = ev.process_executable
        actor_obj["process"] = process_obj

    ocsf_event: Dict[str, Any] = {
        "activity_id": FILE_ACTIVITY_OBSERVED_ID,
        "class_uid": FILE_ACTIVITY_CLASS_UID,
        "type_uid": type_uid,
        "time": _to_iso8601_utc(ev.timestamp),
        "metadata": {
            "product": ev.source or "File Artifact",
        },
        "file": file_obj,
        "unmapped": {"original_event": ev.original_event},
    }
    if device_obj:
        ocsf_event["device"] = device_obj
    if actor_obj:
        ocsf_event["actor"] = actor_obj

    return ocsf_event
