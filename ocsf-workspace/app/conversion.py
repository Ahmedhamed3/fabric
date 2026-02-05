import json
from datetime import datetime, timezone
from typing import Iterable, Iterator, Optional

from app.detect import detect_event
from app.formats.reader import PARSE_ERROR_KEY
from app.ocsf.constants import (
    AUTHENTICATION_ACTIVITY_CLASS_UID,
    FILE_SYSTEM_ACTIVITY_CLASS_UID,
    FILE_SYSTEM_ACTIVITY_CREATE_ID,
    FILE_SYSTEM_ACTIVITY_DELETE_ID,
    FILE_SYSTEM_ACTIVITY_MODIFY_ID,
    FILE_SYSTEM_ACTIVITY_READ_ID,
    MODULE_ACTIVITY_CLASS_UID,
    MODULE_ACTIVITY_LOAD_ID,
    PROCESS_ACTIVITY_CLASS_UID,
    PROCESS_ACTIVITY_INJECT_ID,
    PROCESS_ACTIVITY_LAUNCH_ID,
    PROCESS_ACTIVITY_OPEN_ID,
    REGISTRY_KEY_ACTIVITY_CLASS_UID,
    REGISTRY_VALUE_ACTIVITY_CLASS_UID,
    SECURITY_FINDING_CLASS_UID,
    calc_type_uid,
)
from app.ocsf.unknown import map_parse_error_to_ocsf, map_unknown_event_to_ocsf
from app.plugins.azure_ad_signin.pipeline import convert_azure_ad_signin_events_to_ocsf_jsonl
from app.plugins.file_artifact.pipeline import convert_file_artifact_events_to_ocsf_jsonl
from app.plugins.suricata.pipeline import convert_suricata_events_to_ocsf_jsonl
from app.plugins.sysmon.pipeline import convert_sysmon_events_to_ocsf_jsonl
from app.plugins.windows_security.pipeline import convert_windows_security_events_to_ocsf_jsonl
from app.plugins.zeek.pipeline import convert_zeek_dns_events_to_ocsf_jsonl
from app.plugins.zeek_http.pipeline import convert_zeek_http_events_to_ocsf_jsonl
from app.plugins.proxy_http.pipeline import convert_proxy_http_events_to_ocsf_jsonl


SOURCE_PIPELINES = {
    "azure_ad_signin": convert_azure_ad_signin_events_to_ocsf_jsonl,
    "sysmon": convert_sysmon_events_to_ocsf_jsonl,
    "zeek": convert_zeek_dns_events_to_ocsf_jsonl,
    "zeek_http": convert_zeek_http_events_to_ocsf_jsonl,
    "suricata": convert_suricata_events_to_ocsf_jsonl,
    "windows-security": convert_windows_security_events_to_ocsf_jsonl,
    "file-artifact": convert_file_artifact_events_to_ocsf_jsonl,
    "proxy_http": convert_proxy_http_events_to_ocsf_jsonl,
}


def _ensure_unmapped_original(event: dict, mapped: dict) -> dict:
    unmapped = mapped.get("unmapped")
    if not isinstance(unmapped, dict):
        unmapped = {}
        mapped["unmapped"] = unmapped
    if "original_event" not in unmapped:
        unmapped["original_event"] = event
    return mapped


def _current_ingestion_time() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _ensure_unmapped(mapped: dict) -> dict:
    unmapped = mapped.get("unmapped")
    if not isinstance(unmapped, dict):
        unmapped = {}
        mapped["unmapped"] = unmapped
    return unmapped


def _is_valid_iso8601_z(value: object) -> bool:
    if not isinstance(value, str):
        return False
    if not value.endswith("Z"):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return False
    return True


def _ensure_time(event: dict, *, ingestion_time: str) -> None:
    if _is_valid_iso8601_z(event.get("time")):
        return
    event["time"] = ingestion_time
    unmapped = _ensure_unmapped(event)
    unmapped["time_parse_error"] = True


def _extract_original_event_id(original_event: object) -> Optional[int]:
    if not isinstance(original_event, dict):
        return None
    value = original_event.get("EventID")
    if value is None:
        value = original_event.get("event_id")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _derive_evidence_flags(event: dict) -> dict:
    """Derive evidence flags based on normalized OCSF content and source hints."""
    metadata = event.get("metadata") or {}
    product = metadata.get("product")
    class_uid = event.get("class_uid")
    activity_id = event.get("activity_id")
    type_uid = event.get("type_uid")

    actor = event.get("actor") or {}
    actor_process = actor.get("process") or {}
    file_obj = event.get("file") or {}
    file_hash = file_obj.get("hash") or {}
    module_obj = event.get("module") or {}
    module_file = module_obj.get("file") or {}
    dns_obj = event.get("dns") or {}
    http_obj = event.get("http") or {}
    auth_obj = event.get("auth")

    unmapped = event.get("unmapped") or {}
    original_event = unmapped.get("original_event")
    original_event_id = _extract_original_event_id(original_event)

    # Process execution is only asserted for explicit process launch activity.
    if original_event_id is not None:
        process_execution = original_event_id == 1
    else:
        process_execution = (
            class_uid == PROCESS_ACTIVITY_CLASS_UID
            and activity_id == PROCESS_ACTIVITY_LAUNCH_ID
        )

    file_create = (
        class_uid == FILE_SYSTEM_ACTIVITY_CLASS_UID
        and activity_id == FILE_SYSTEM_ACTIVITY_CREATE_ID
    )
    if not file_create and file_obj.get("path") and original_event_id == 11:
        file_create = True

    file_access = (
        class_uid == FILE_SYSTEM_ACTIVITY_CLASS_UID
        and activity_id in {
            FILE_SYSTEM_ACTIVITY_READ_ID,
            FILE_SYSTEM_ACTIVITY_MODIFY_ID,
            FILE_SYSTEM_ACTIVITY_DELETE_ID,
        }
    )
    if not file_access and original_event_id == 4663:
        file_access = True

    file_hash_present = bool(file_hash.get("sha256") or file_hash.get("md5"))

    dns_present = bool(dns_obj.get("question") or dns_obj.get("answers"))
    http_present = bool(http_obj.get("url") or http_obj.get("method"))

    identity_present = bool(auth_obj) or class_uid == AUTHENTICATION_ACTIVITY_CLASS_UID

    alert_present = class_uid == SECURITY_FINDING_CLASS_UID

    module_load = class_uid == MODULE_ACTIVITY_CLASS_UID or bool(module_obj or module_file)
    inject_type_uid = calc_type_uid(PROCESS_ACTIVITY_CLASS_UID, PROCESS_ACTIVITY_INJECT_ID)
    open_type_uid = calc_type_uid(PROCESS_ACTIVITY_CLASS_UID, PROCESS_ACTIVITY_OPEN_ID)
    process_injection = (
        type_uid == inject_type_uid
        or (
            class_uid == PROCESS_ACTIVITY_CLASS_UID
            and activity_id == PROCESS_ACTIVITY_INJECT_ID
        )
        or "injection_type" in event
    )
    process_access = (
        type_uid == open_type_uid
        or (
            class_uid == PROCESS_ACTIVITY_CLASS_UID
            and activity_id == PROCESS_ACTIVITY_OPEN_ID
        )
        or event.get("actual_permissions") is not None
    )
    registry_key = class_uid == REGISTRY_KEY_ACTIVITY_CLASS_UID
    registry_value = class_uid == REGISTRY_VALUE_ACTIVITY_CLASS_UID

    unknown_present = product == "Unknown"
    parse_error_present = product == "ParseError"

    return {
        "process_execution": process_execution,
        "file_create": file_create,
        "file_hash": file_hash_present,
        "file_access": file_access,
        "dns": dns_present,
        "http": http_present,
        "identity": identity_present,
        "alert": alert_present,
        "module_load": module_load,
        "process_injection": process_injection,
        "process_access": process_access,
        "registry_key": registry_key,
        "registry_value": registry_value,
        "unknown": unknown_present,
        "parse_error": parse_error_present,
    }


def _derive_context_flags(event: dict) -> dict:
    """Derive context flags from normalized OCSF fields."""
    actor = event.get("actor") or {}
    actor_user = actor.get("user") or {}
    actor_process = actor.get("process") or {}
    process = event.get("process") or {}
    file_obj = event.get("file") or {}
    module = event.get("module") or {}
    module_file = module.get("file") or {}
    device = event.get("device") or {}

    network = event.get("network") or {}
    network_src = network.get("src_endpoint") or {}
    network_dst = network.get("dst_endpoint") or {}
    src_endpoint = event.get("src_endpoint") or {}
    dst_endpoint = event.get("dst_endpoint") or {}

    def _has_file_reference(file_candidate: object) -> bool:
        if not isinstance(file_candidate, dict):
            return False
        return bool(file_candidate.get("path") or file_candidate.get("name"))

    def _endpoint_has_ip(endpoint: object) -> bool:
        return isinstance(endpoint, dict) and bool(endpoint.get("ip"))

    has_user = bool(actor_user)
    has_process = bool(actor_process) or bool(process)
    has_file = any(
        [
            _has_file_reference(file_obj),
            _has_file_reference(actor_process.get("file")),
            _has_file_reference(process.get("file")),
            _has_file_reference(module_file),
        ]
    )
    endpoint_present = [
        network_src,
        network_dst,
        src_endpoint,
        dst_endpoint,
    ]
    has_ip = any(
        [
            _endpoint_has_ip(network_src),
            _endpoint_has_ip(network_dst),
            _endpoint_has_ip(src_endpoint),
            _endpoint_has_ip(dst_endpoint),
            any(bool(endpoint) for endpoint in endpoint_present if isinstance(endpoint, dict)),
        ]
    )
    has_device = bool(device)

    return {
        "has_user": has_user,
        "has_process": has_process,
        "has_file": has_file,
        "has_ip": has_ip,
        "has_device": has_device,
    }


def _apply_post_processing(event: dict, *, ingestion_time: str) -> dict:
    _ensure_time(event, ingestion_time=ingestion_time)
    event["evidence_flags"] = _derive_evidence_flags(event)
    event["context_flags"] = _derive_context_flags(event)
    return event


def _map_event_with_source(event: dict, *, source_type: str, ingestion_time: str) -> dict:
    if PARSE_ERROR_KEY in event:
        payload = event.get(PARSE_ERROR_KEY) or {}
        raw_line = payload.get("raw_line", "")
        error = payload.get("error", "Parse error")
        mapped = map_parse_error_to_ocsf(
            raw_line=raw_line,
            error_message=error,
            ingestion_time=ingestion_time,
        )
        return _apply_post_processing(mapped, ingestion_time=ingestion_time)

    converter = SOURCE_PIPELINES.get(source_type)
    if converter:
        mapped_lines = list(converter([event]))
        if mapped_lines:
            mapped_line = mapped_lines[0]
            try:
                mapped_event = json.loads(mapped_line)
            except json.JSONDecodeError:
                mapped_event = None
            if isinstance(mapped_event, dict):
                mapped_event = _ensure_unmapped_original(event, mapped_event)
                return _apply_post_processing(mapped_event, ingestion_time=ingestion_time)

    unknown_event = map_unknown_event_to_ocsf(
        event,
        reason=f"No mapper for source {source_type}.",
    )
    return _apply_post_processing(unknown_event, ingestion_time=ingestion_time)


def convert_events_to_ocsf_jsonl(
    events: Iterable[dict],
    *,
    threshold: float = 0.6,
) -> Iterator[str]:
    ingestion_time = _current_ingestion_time()
    for event in events:
        if PARSE_ERROR_KEY in event:
            mapped_event = _map_event_with_source(
                event,
                source_type="unknown",
                ingestion_time=ingestion_time,
            )
            yield json.dumps(mapped_event, ensure_ascii=False)
            continue
        detection = detect_event(event, threshold=threshold)
        source_type = detection["source_type"]
        mapped_event = _map_event_with_source(
            event,
            source_type=source_type,
            ingestion_time=ingestion_time,
        )
        yield json.dumps(mapped_event, ensure_ascii=False)


def convert_events_with_source_to_ocsf_jsonl(
    events: Iterable[dict],
    *,
    source_type: str,
) -> Iterator[str]:
    ingestion_time = _current_ingestion_time()
    for event in events:
        mapped_event = _map_event_with_source(
            event,
            source_type=source_type,
            ingestion_time=ingestion_time,
        )
        yield json.dumps(mapped_event, ensure_ascii=False)
