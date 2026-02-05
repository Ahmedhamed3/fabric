from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Any, Dict, Iterable, Optional

from app.normalizers.elastic_to_ocsf import taxonomy
from app.utils.timeutil import to_utc_iso


@dataclass(frozen=True)
class MappingContext:
    ocsf_version: str


@dataclass(frozen=True)
class FamilyDecision:
    family: str
    reason: str


def map_raw_event(raw_event: Dict[str, Any], context: MappingContext) -> Optional[Dict[str, Any]]:
    source = _extract_source(raw_event)
    decision = _detect_family(raw_event, source)
    missing_fields = _missing_required_fields_for_family(raw_event, source, decision.family)
    if decision.family == "iam":
        if _is_windows_security_group_membership_enumeration(source):
            return _map_windows_security_group_membership_enumeration(raw_event, context, decision, missing_fields)
        if _is_windows_security_privilege_use(source):
            return _map_windows_security_privilege_use(raw_event, context, decision, missing_fields)
        return _map_generic_activity(raw_event, context, decision, missing_fields)
    if decision.family == "auth":
        return _map_authentication_activity(raw_event, context, decision, missing_fields)
    if decision.family == "dns":
        return _map_dns_activity(raw_event, context, decision, missing_fields)
    if decision.family == "process":
        return _map_process_activity(raw_event, context, decision, missing_fields)
    if decision.family == "network":
        return _map_network_activity(raw_event, context, decision, missing_fields)
    if decision.family == "elastic_agent":
        source = _extract_source(raw_event)
        dataset = _elastic_agent_dataset(source)
        if dataset and dataset.lower() == "elastic_agent":
            return _map_elastic_agent_activity(raw_event, context, decision, missing_fields)
        return _map_elastic_agent_error(raw_event, context, decision, missing_fields)
    return _map_generic_activity(raw_event, context, decision, missing_fields)


def mapping_attempted(raw_event: Dict[str, Any]) -> bool:
    return True


def missing_required_fields(raw_event: Dict[str, Any]) -> list[str]:
    source = _extract_source(raw_event)
    decision = _detect_family(raw_event, source)
    return _missing_required_fields_for_family(raw_event, source, decision.family)


def _extract_hit(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    raw = raw_event.get("raw") or {}
    data = raw.get("data")
    return data if isinstance(data, dict) else {}


def _extract_source(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    hit = _extract_hit(raw_event)
    source = hit.get("_source")
    return source if isinstance(source, dict) else {}


def _get_event_block(source: Dict[str, Any]) -> Dict[str, Any]:
    event = source.get("event")
    return event if isinstance(event, dict) else {}


def _get_network_block(source: Dict[str, Any]) -> Dict[str, Any]:
    network = source.get("network")
    return network if isinstance(network, dict) else {}


def _get_user_block(source: Dict[str, Any]) -> Dict[str, Any]:
    user = source.get("user")
    return user if isinstance(user, dict) else {}


def _get_process_block(source: Dict[str, Any]) -> Dict[str, Any]:
    process = source.get("process")
    return process if isinstance(process, dict) else {}


def _get_host_block(source: Dict[str, Any]) -> Dict[str, Any]:
    host = source.get("host")
    return host if isinstance(host, dict) else {}


def _get_winlog_block(source: Dict[str, Any]) -> Dict[str, Any]:
    winlog = source.get("winlog")
    return winlog if isinstance(winlog, dict) else {}


def _extract_winlog_event_id(source: Dict[str, Any]) -> Optional[str]:
    winlog = _get_winlog_block(source)
    event_id = winlog.get("event_id")
    if isinstance(event_id, int):
        return str(event_id)
    return _coerce_str(event_id)


def _get_data_stream_block(source: Dict[str, Any]) -> Dict[str, Any]:
    data_stream = source.get("data_stream")
    return data_stream if isinstance(data_stream, dict) else {}


def _get_dns_block(source: Dict[str, Any]) -> Dict[str, Any]:
    dns = source.get("dns")
    return dns if isinstance(dns, dict) else {}


def _get_authentication_block(source: Dict[str, Any]) -> Dict[str, Any]:
    authentication = source.get("authentication")
    return authentication if isinstance(authentication, dict) else {}


def _get_file_block(source: Dict[str, Any]) -> Dict[str, Any]:
    file_block = source.get("file")
    return file_block if isinstance(file_block, dict) else {}


def _get_registry_block(source: Dict[str, Any]) -> Dict[str, Any]:
    registry = source.get("registry")
    return registry if isinstance(registry, dict) else {}


def _coerce_str(value: Any) -> Optional[str]:
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    return None


def _coerce_pid(value: Any) -> Optional[int]:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        stripped = value.strip().lower()
        if not stripped:
            return None
        if stripped.startswith("0x"):
            try:
                return int(stripped, 16)
            except ValueError:
                return None
        if stripped.isdigit():
            return int(stripped)
    return None


def _path_basename(path: str) -> str:
    if "\\" in path:
        return PureWindowsPath(path).name
    return Path(path).name


def _coerce_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [item for item in (str(part).strip() for part in value) if item]
    if isinstance(value, str):
        stripped = value.strip()
        return [stripped] if stripped else []
    return []


def _contains_any(values: Iterable[str], options: Iterable[str]) -> bool:
    lowered = {value.lower() for value in values}
    return any(option.lower() in lowered for option in options)


"""
Elastic family detection is deterministic and ordered to favor ECS intent over raw field presence:
1) event.kind / event.category / event.type / event.action / event.outcome
2) event.code (numeric Windows/Sysmon style IDs)
3) data_stream.* (dataset/type/namespace)
4) winlog.channel / winlog.provider_name
5) ECS field presence (process/user/source/destination/dns/authentication/file/registry/network)
The chosen family drives routing; missing fields fall back to a generic OCSF base_event while
preserving the selected family and detection reason in unmapped.mapping_attempt.
"""


def _detect_family(raw_event: Dict[str, Any], source: Dict[str, Any]) -> FamilyDecision:
    event = _get_event_block(source)
    kind = _coerce_str(event.get("kind"))
    categories = _coerce_list(event.get("category"))
    types = _coerce_list(event.get("type"))
    action = _coerce_str(event.get("action"))
    outcome = _coerce_str(event.get("outcome"))
    action_text = " ".join(part for part in [action, *types] if part).lower()

    event_family: Optional[FamilyDecision] = None
    if _contains_any(categories, ["authentication"]):
        event_family = FamilyDecision("auth", "event.category=authentication")
    elif _contains_any(categories, ["iam"]):
        event_family = FamilyDecision("iam", "event.category=iam")
    elif "dns" in action_text or _contains_any(types, ["dns"]):
        event_family = FamilyDecision("dns", "event.type/action=dns")
    elif _contains_any(categories, ["network"]):
        event_family = FamilyDecision("network", "event.category=network")
    elif _contains_any(categories, ["process"]):
        event_family = FamilyDecision("process", "event.category=process")
    elif _contains_any(categories, ["file"]):
        event_family = FamilyDecision("file", "event.category=file")
    elif _contains_any(categories, ["registry"]):
        event_family = FamilyDecision("registry", "event.category=registry")
    elif kind:
        event_family = FamilyDecision("generic", f"event.kind={kind}")
    elif outcome:
        event_family = FamilyDecision("generic", f"event.outcome={outcome}")

    event_code = _coerce_str(event.get("code")) or _extract_winlog_event_id(source)
    if event_code and event_code.isdigit():
        if _is_windows_security_privilege_use(source) or _is_windows_security_group_membership_enumeration(source):
            return FamilyDecision("iam", f"event.code={event_code}")
        if event_family is None:
            return FamilyDecision("iam", f"event.code={event_code}")
    elastic_agent_match = _elastic_agent_match(source)
    if elastic_agent_match and (event_family is None or event_family.family == "generic"):
        return FamilyDecision("elastic_agent", elastic_agent_match)
    if event_family is not None:
        return event_family

    data_stream = _get_data_stream_block(source)
    dataset = _coerce_str(data_stream.get("dataset"))
    stream_type = _coerce_str(data_stream.get("type"))
    namespace = _coerce_str(data_stream.get("namespace"))
    if dataset:
        lowered = dataset.lower()
        if "dns" in lowered:
            return FamilyDecision("dns", f"data_stream.dataset={dataset}")
        if "network" in lowered or "flow" in lowered:
            return FamilyDecision("network", f"data_stream.dataset={dataset}")
        if "auth" in lowered or "login" in lowered:
            return FamilyDecision("auth", f"data_stream.dataset={dataset}")
        if "process" in lowered:
            return FamilyDecision("process", f"data_stream.dataset={dataset}")
    if stream_type:
        if stream_type.lower() == "logs" and namespace:
            return FamilyDecision("generic", f"data_stream.type={stream_type}")

    winlog = _get_winlog_block(source)
    channel = _coerce_str(winlog.get("channel"))
    provider = _coerce_str(winlog.get("provider_name"))
    if channel:
        if channel.lower() == "security":
            return FamilyDecision("iam", f"winlog.channel={channel}")
        return FamilyDecision("generic", f"winlog.channel={channel}")
    if provider:
        return FamilyDecision("generic", f"winlog.provider_name={provider}")

    if _get_dns_block(source):
        return FamilyDecision("dns", "ecs.dns")
    if _get_authentication_block(source):
        return FamilyDecision("auth", "ecs.authentication")
    if _get_network_block(source) or _extract_ip(source, "source") or _extract_ip(source, "destination"):
        return FamilyDecision("network", "ecs.network/source/destination")
    if _get_process_block(source):
        return FamilyDecision("process", "ecs.process")
    if _get_user_block(source):
        return FamilyDecision("iam", "ecs.user")
    if _get_file_block(source):
        return FamilyDecision("file", "ecs.file")
    if _get_registry_block(source):
        return FamilyDecision("registry", "ecs.registry")
    return FamilyDecision("generic", "fallback")


def _elastic_agent_match(source: Dict[str, Any]) -> Optional[str]:
    data_stream = _get_data_stream_block(source)
    dataset = _coerce_str(data_stream.get("dataset"))
    if dataset and dataset.lower() == "elastic_agent":
        return f"data_stream.dataset={dataset}"
    if dataset and dataset.lower().startswith("elastic_agent."):
        return f"data_stream.dataset={dataset}"
    service_type = _coerce_str(_extract_nested_value(source, ("service", "type")))
    if service_type and service_type.lower() == "fleet-server":
        return f"service.type={service_type}"
    service_name = _coerce_str(_extract_nested_value(source, ("service", "name")))
    if service_name and service_name.lower() == "fleet-server":
        return f"service.name={service_name}"
    return None


def _elastic_agent_dataset(source: Dict[str, Any]) -> Optional[str]:
    data_stream = _get_data_stream_block(source)
    return _coerce_str(data_stream.get("dataset"))


def _is_windows_security_privilege_use(source: Dict[str, Any]) -> bool:
    event = _get_event_block(source)
    event_code = _coerce_str(event.get("code")) or _extract_winlog_event_id(source)
    if event_code != "4673":
        return False
    winlog = _get_winlog_block(source)
    channel = _coerce_str(winlog.get("channel"))
    return channel == "Security"


def _is_windows_security_group_membership_enumeration(source: Dict[str, Any]) -> bool:
    event = _get_event_block(source)
    event_code = _coerce_str(event.get("code")) or _extract_winlog_event_id(source)
    if event_code != "4798":
        return False
    winlog = _get_winlog_block(source)
    channel = _coerce_str(winlog.get("channel"))
    return channel == "Security"


def _extract_event_time(raw_event: Dict[str, Any], source: Dict[str, Any]) -> Optional[str]:
    for key_path in (
        ("@timestamp",),
        ("event", "created"),
        ("event", "ingested"),
        ("timestamp",),
    ):
        value = _extract_nested_value(source, key_path)
        if isinstance(value, str) and value:
            return to_utc_iso(value) or value
    event = raw_event.get("event") or {}
    time_block = event.get("time") or {}
    observed = time_block.get("observed_utc")
    if isinstance(observed, str) and observed:
        return observed
    return None


def _extract_nested_value(source: Dict[str, Any], path: Iterable[str]) -> Any:
    cursor: Any = source
    for key in path:
        if not isinstance(cursor, dict):
            return None
        cursor = cursor.get(key)
    return cursor


def _extract_event_code(source: Dict[str, Any], hit: Dict[str, Any]) -> Optional[str]:
    event = _get_event_block(source)
    for key in ("code", "action", "id"):
        value = _coerce_str(event.get(key))
        if value:
            return value
    dataset = _coerce_str(event.get("dataset"))
    if dataset:
        return dataset
    data_stream = _get_data_stream_block(source)
    data_stream_dataset = _coerce_str(data_stream.get("dataset"))
    if data_stream_dataset:
        return data_stream_dataset
    return _coerce_str(hit.get("_index"))


def _extract_ip(source: Dict[str, Any], key: str) -> Optional[str]:
    block = source.get(key)
    if not isinstance(block, dict):
        return None
    return _coerce_str(block.get("ip"))


def _extract_port(source: Dict[str, Any], key: str) -> Optional[int]:
    block = source.get(key)
    if not isinstance(block, dict):
        return None
    value = block.get("port")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _extract_hostname(source: Dict[str, Any], key: str) -> Optional[str]:
    block = source.get(key)
    if not isinstance(block, dict):
        return None
    return _coerce_str(block.get("domain")) or _coerce_str(block.get("hostname")) or _coerce_str(block.get("name"))


def _extract_host_name(source: Dict[str, Any]) -> Optional[str]:
    host = _get_host_block(source)
    return _coerce_str(host.get("name")) or _coerce_str(host.get("hostname"))


def _extract_host_ip(source: Dict[str, Any]) -> Optional[str]:
    host = _get_host_block(source)
    return _coerce_str(host.get("ip"))


def _normalize_hostname(hostname: str) -> str:
    return hostname.lower()


def _extract_elastic_agent_app(source: Dict[str, Any]) -> Dict[str, Any]:
    unit_block = source.get("unit")
    component_block = source.get("component")
    agent_block = source.get("agent")
    unit_id = _coerce_str(unit_block.get("id")) if isinstance(unit_block, dict) else None
    component_id = _coerce_str(component_block.get("id")) if isinstance(component_block, dict) else None
    agent_name = _coerce_str(agent_block.get("name")) if isinstance(agent_block, dict) else None
    app_name = unit_id or component_id or agent_name
    if not app_name:
        return {}
    app: Dict[str, Any] = {"name": app_name}
    version = _coerce_str(_extract_nested_value(source, ("elastic_agent", "version")))
    if version:
        app["version"] = version
    return app


def _elastic_agent_lifecycle_activity_id(source: Dict[str, Any]) -> Optional[int]:
    unit_block = source.get("unit")
    component_block = source.get("component")
    new_state = _coerce_str(unit_block.get("state")) if isinstance(unit_block, dict) else None
    old_state = _coerce_str(unit_block.get("old_state")) if isinstance(unit_block, dict) else None
    component_state = _coerce_str(component_block.get("state")) if isinstance(component_block, dict) else None
    message = _coerce_str(source.get("message"))
    return _map_elastic_agent_state_to_activity(new_state, old_state, component_state, message)


def _map_elastic_agent_state_to_activity(
    new_state: Optional[str],
    old_state: Optional[str],
    component_state: Optional[str],
    message: Optional[str],
) -> Optional[int]:
    state = new_state or component_state
    normalized = state.lower() if state else None
    if normalized:
        if normalized in {"restarting", "restart", "restarted"}:
            return taxonomy.APPLICATION_LIFECYCLE_RESTART_ID
        if normalized in {"starting", "start", "started", "running", "healthy", "online"}:
            return taxonomy.APPLICATION_LIFECYCLE_START_ID
        if normalized in {"stopping", "stop", "stopped", "failed", "dead", "exited", "inactive", "crashed"}:
            return taxonomy.APPLICATION_LIFECYCLE_STOP_ID
        if normalized in {"enabling", "enable", "enabled"}:
            return taxonomy.APPLICATION_LIFECYCLE_ENABLE_ID
        if normalized in {"disabling", "disable", "disabled"}:
            return taxonomy.APPLICATION_LIFECYCLE_DISABLE_ID
        if normalized in {"updating", "update", "updated"}:
            return taxonomy.APPLICATION_LIFECYCLE_UPDATE_ID
    if message:
        lowered = message.lower()
        if "restart" in lowered:
            return taxonomy.APPLICATION_LIFECYCLE_RESTART_ID
        if "start" in lowered:
            return taxonomy.APPLICATION_LIFECYCLE_START_ID
        if "stop" in lowered or "failed" in lowered:
            return taxonomy.APPLICATION_LIFECYCLE_STOP_ID
    if old_state and new_state:
        old_normalized = old_state.lower()
        new_normalized = new_state.lower()
        if old_normalized != new_normalized:
            if new_normalized in {"starting", "started", "running"}:
                return taxonomy.APPLICATION_LIFECYCLE_START_ID
            if new_normalized in {"stopping", "stopped", "failed"}:
                return taxonomy.APPLICATION_LIFECYCLE_STOP_ID
    return None


def _extract_user(source: Dict[str, Any]) -> Dict[str, Any]:
    user = _get_user_block(source)
    user_name = _coerce_str(user.get("name")) or _coerce_str(user.get("username")) or _coerce_str(user.get("email"))
    user_id = _coerce_str(user.get("id")) or _coerce_str(user.get("uid"))
    domain = _coerce_str(user.get("domain"))
    payload: Dict[str, Any] = {}
    if user_name:
        payload["name"] = user_name
    if user_id:
        payload["uid"] = user_id
    if domain:
        payload["domain"] = domain
    return payload


def _extract_winlog_event_data(source: Dict[str, Any]) -> Dict[str, Any]:
    winlog = _get_winlog_block(source)
    event_data = winlog.get("event_data")
    return event_data if isinstance(event_data, dict) else {}


def _extract_winlog_subject_user(event_data: Dict[str, Any]) -> Dict[str, Any]:
    name = _coerce_str(event_data.get("SubjectUserName"))
    domain = _coerce_str(event_data.get("SubjectDomainName"))
    uid = _coerce_str(event_data.get("SubjectUserSid"))
    payload: Dict[str, Any] = {}
    if name:
        payload["name"] = name
    if domain:
        payload["domain"] = domain
    if uid:
        payload["uid"] = uid
    return payload


def _extract_winlog_target_user(event_data: Dict[str, Any]) -> Dict[str, Any]:
    name = _coerce_str(event_data.get("TargetUserName")) or _coerce_str(event_data.get("UserName"))
    domain = _coerce_str(event_data.get("TargetDomainName"))
    uid = _coerce_str(event_data.get("TargetUserSid"))
    payload: Dict[str, Any] = {}
    if name:
        payload["name"] = name
    if domain:
        payload["domain"] = domain
    if uid:
        payload["uid"] = uid
    return payload


def _extract_winlog_caller_process(event_data: Dict[str, Any]) -> Dict[str, Any]:
    name = _coerce_str(event_data.get("CallerProcessName"))
    pid = _coerce_pid(event_data.get("CallerProcessId"))
    payload: Dict[str, Any] = {}
    if name:
        payload["name"] = _path_basename(name)
        payload["path"] = name
    if pid is not None:
        payload["pid"] = pid
    return payload


def _split_privileges(value: Optional[str]) -> list[str]:
    if not value:
        return []
    return [part for part in value.replace(",", " ").split() if part]


def _extract_privileges(source: Dict[str, Any]) -> list[str]:
    event_data = _extract_winlog_event_data(source)
    for key in ("PrivilegeList", "Privileges", "Privilege"):
        value = _coerce_str(event_data.get(key))
        if value:
            return _split_privileges(value)
    return []


def _extract_process(source: Dict[str, Any]) -> Dict[str, Any]:
    process = _get_process_block(source)
    pid = _coerce_pid(process.get("pid"))
    entity_id = _coerce_str(process.get("entity_id"))
    path = _coerce_str(process.get("executable"))
    name = _coerce_str(process.get("name"))
    if not name and path:
        name = _path_basename(path)
    cmd_line = _coerce_str(process.get("command_line"))
    payload: Dict[str, Any] = {}
    if pid is not None:
        payload["pid"] = pid
    if entity_id:
        payload["uid"] = entity_id
    if path:
        payload["path"] = path
    if name:
        payload["name"] = name
    if cmd_line:
        payload["cmd_line"] = cmd_line
    parent = process.get("parent")
    if isinstance(parent, dict):
        parent_pid = _coerce_pid(parent.get("pid"))
        parent_entity = _coerce_str(parent.get("entity_id"))
        parent_path = _coerce_str(parent.get("executable"))
        parent_name = _coerce_str(parent.get("name"))
        if not parent_name and parent_path:
            parent_name = _path_basename(parent_path)
        parent_payload: Dict[str, Any] = {}
        if parent_pid is not None:
            parent_payload["pid"] = parent_pid
        if parent_entity:
            parent_payload["uid"] = parent_entity
        if parent_path:
            parent_payload["path"] = parent_path
        if parent_name:
            parent_payload["name"] = parent_name
        if parent_payload:
            payload["parent_process"] = parent_payload
    return payload


def _extract_network_protocol(source: Dict[str, Any]) -> Optional[str]:
    network = _get_network_block(source)
    protocol = _coerce_str(network.get("transport")) or _coerce_str(network.get("protocol"))
    return protocol.lower() if protocol else None


def _extract_source_endpoint(source: Dict[str, Any]) -> Dict[str, Any]:
    endpoint: Dict[str, Any] = {}
    ip = _extract_ip(source, "source")
    port = _extract_port(source, "source")
    hostname = _extract_hostname(source, "source")
    if ip:
        endpoint["ip"] = ip
    if port is not None:
        endpoint["port"] = port
    if hostname:
        endpoint["hostname"] = hostname
    return endpoint


def _extract_destination_endpoint(source: Dict[str, Any]) -> Dict[str, Any]:
    endpoint: Dict[str, Any] = {}
    ip = _extract_ip(source, "destination")
    port = _extract_port(source, "destination")
    hostname = _extract_hostname(source, "destination")
    if ip:
        endpoint["ip"] = ip
    if port is not None:
        endpoint["port"] = port
    if hostname:
        endpoint["hostname"] = hostname
    return endpoint


def _extract_dns_query_name(source: Dict[str, Any]) -> Optional[str]:
    dns = _get_dns_block(source)
    question = dns.get("question")
    if isinstance(question, dict):
        name = _coerce_str(question.get("name"))
        if name:
            return name
    name = _coerce_str(dns.get("question"))
    if name:
        return name
    event_data = _extract_winlog_event_data(source)
    return _coerce_str(event_data.get("QueryName")) or _coerce_str(event_data.get("Query"))


def _extract_dns_answers(source: Dict[str, Any]) -> list[Dict[str, Any]]:
    dns = _get_dns_block(source)
    answers = dns.get("answers")
    payloads: list[Dict[str, Any]] = []
    if isinstance(answers, list):
        for answer in answers:
            if not isinstance(answer, dict):
                continue
            rdata = _coerce_str(answer.get("data")) or _coerce_str(answer.get("ip"))
            if not rdata:
                continue
            entry: Dict[str, Any] = {"rdata": rdata}
            answer_type = _coerce_str(answer.get("type"))
            answer_class = _coerce_str(answer.get("class"))
            ttl = answer.get("ttl")
            if answer_type:
                entry["type"] = answer_type
            if answer_class:
                entry["class"] = answer_class
            if isinstance(ttl, int):
                entry["ttl"] = ttl
            payloads.append(entry)
    return payloads


def _missing_required_authentication_fields(raw_event: Dict[str, Any], source: Dict[str, Any]) -> list[str]:
    missing: list[str] = []
    time_value = _extract_event_time(raw_event, source)
    if not time_value:
        missing.append("time")
    user = _extract_user(source)
    if not user:
        missing.append("user")
    service_name = _coerce_str(_extract_nested_value(source, ("service", "name")))
    dst_endpoint = _extract_destination_endpoint(source)
    if not service_name and not dst_endpoint:
        missing.append("dst_endpoint/service")
    return missing


def _missing_required_privilege_fields(raw_event: Dict[str, Any], source: Dict[str, Any]) -> list[str]:
    missing: list[str] = []
    time_value = _extract_event_time(raw_event, source)
    if not time_value:
        missing.append("time")
    user = _extract_user(source)
    if not (user.get("uid") or user.get("name")):
        missing.append("user")
    privileges = _extract_privileges(source)
    if not privileges:
        missing.append("privileges")
    return missing


def _missing_required_group_membership_fields(raw_event: Dict[str, Any], source: Dict[str, Any]) -> list[str]:
    missing: list[str] = []
    time_value = _extract_event_time(raw_event, source)
    if not time_value:
        missing.append("time")
    event_data = _extract_winlog_event_data(source)
    actor = _extract_user(source) or _extract_winlog_subject_user(event_data)
    if not actor:
        missing.append("actor.user")
    target_user = _extract_winlog_target_user(event_data)
    if not target_user:
        missing.append("target_user")
    entity_name = _coerce_str(event_data.get("GroupName")) or _coerce_str(event_data.get("Group"))
    if not entity_name:
        missing.append("entity.name")
    return missing


def _missing_required_process_fields(raw_event: Dict[str, Any], source: Dict[str, Any]) -> list[str]:
    missing: list[str] = []
    time_value = _extract_event_time(raw_event, source)
    if not time_value:
        missing.append("time")
    process = _extract_process(source)
    if not process or not (process.get("pid") or process.get("uid")):
        missing.append("process.pid/process.uid")
    if not _extract_host_name(source) and not _extract_host_ip(source):
        missing.append("host.name")
    if _process_activity_id(source) is None:
        missing.append("event.action")
    return missing


def _missing_required_network_fields(raw_event: Dict[str, Any], source: Dict[str, Any]) -> list[str]:
    missing: list[str] = []
    time_value = _extract_event_time(raw_event, source)
    if not time_value:
        missing.append("time")
    protocol = _extract_network_protocol(source)
    if not protocol:
        missing.append("network.transport")
    src_ip = _extract_ip(source, "source")
    if not src_ip:
        missing.append("source.ip")
    dst_ip = _extract_ip(source, "destination")
    if not dst_ip:
        missing.append("destination.ip")
    src_port = _extract_port(source, "source")
    if src_port is None:
        missing.append("source.port")
    dst_port = _extract_port(source, "destination")
    if dst_port is None:
        missing.append("destination.port")
    if _network_activity_id(source) is None:
        missing.append("event.action")
    return missing


def _missing_required_dns_fields(raw_event: Dict[str, Any], source: Dict[str, Any]) -> list[str]:
    missing: list[str] = []
    time_value = _extract_event_time(raw_event, source)
    if not time_value:
        missing.append("time")
    query_name = _extract_dns_query_name(source)
    answers = _extract_dns_answers(source)
    if not query_name and not answers:
        missing.append("dns.question.name")
    return missing


def _missing_required_elastic_agent_fields(raw_event: Dict[str, Any], source: Dict[str, Any]) -> list[str]:
    missing: list[str] = []
    time_value = _extract_event_time(raw_event, source)
    if not time_value:
        missing.append("time")
    dataset = _elastic_agent_dataset(source)
    if dataset and dataset.lower() == "elastic_agent":
        app = _extract_elastic_agent_app(source)
        if not app:
            missing.append("unit.id/component.id/agent.name")
        activity_id = _elastic_agent_lifecycle_activity_id(source)
        if activity_id is None:
            missing.append("unit.state/component.state")
    return missing


def _missing_required_fields_for_family(raw_event: Dict[str, Any], source: Dict[str, Any], family: str) -> list[str]:
    if family == "iam":
        if _is_windows_security_group_membership_enumeration(source):
            return _missing_required_group_membership_fields(raw_event, source)
        if _is_windows_security_privilege_use(source):
            return _missing_required_privilege_fields(raw_event, source)
        return []
    if family == "auth":
        return _missing_required_authentication_fields(raw_event, source)
    if family == "dns":
        return _missing_required_dns_fields(raw_event, source)
    if family == "process":
        return _missing_required_process_fields(raw_event, source)
    if family == "network":
        return _missing_required_network_fields(raw_event, source)
    if family == "elastic_agent":
        return _missing_required_elastic_agent_fields(raw_event, source)
    return []


def _map_generic_activity(
    raw_event: Dict[str, Any],
    context: MappingContext,
    decision: FamilyDecision,
    missing_fields: list[str],
    *,
    unmapped_event_data: Optional[Dict[str, Any]] = None,
    mapping_note: Optional[str] = None,
) -> Dict[str, Any]:
    base = _base_event(
        raw_event,
        context,
        category_uid=taxonomy.OTHER_CATEGORY_UID,
        class_uid=taxonomy.BASE_EVENT_CLASS_UID,
        activity_id=0,
        mapping_attempt=_build_mapping_attempt(decision, missing_fields),
        unmapped_event_data=unmapped_event_data,
        mapping_note=mapping_note,
    )
    return base


def _map_authentication_activity(
    raw_event: Dict[str, Any],
    context: MappingContext,
    decision: FamilyDecision,
    missing_fields: list[str],
) -> Optional[Dict[str, Any]]:
    source = _extract_source(raw_event)
    if missing_fields:
        return _map_generic_activity(raw_event, context, decision, missing_fields)
    class_uid = taxonomy.to_class_uid(taxonomy.IAM_CATEGORY_UID, taxonomy.AUTHENTICATION_ACTIVITY_UID)
    activity_id = _authentication_activity_id(source)
    base = _base_event(
        raw_event,
        context,
        category_uid=taxonomy.IAM_CATEGORY_UID,
        class_uid=class_uid,
        activity_id=activity_id,
        mapping_attempt=_build_mapping_attempt(decision, missing_fields),
    )
    user = _extract_user(source)
    if user:
        base["user"] = user
    src_endpoint = _extract_source_endpoint(source)
    if src_endpoint:
        base["src_endpoint"] = src_endpoint
    dst_endpoint = _extract_destination_endpoint(source)
    if dst_endpoint:
        base["dst_endpoint"] = dst_endpoint
    service_name = _coerce_str(_extract_nested_value(source, ("service", "name")))
    if service_name:
        base["service"] = {"name": service_name}
    status = _coerce_str(_extract_nested_value(source, ("event", "outcome")))
    if status:
        base["status"] = status
    return base


def _map_windows_security_privilege_use(
    raw_event: Dict[str, Any],
    context: MappingContext,
    decision: FamilyDecision,
    missing_fields: list[str],
) -> Optional[Dict[str, Any]]:
    source = _extract_source(raw_event)
    if missing_fields:
        return _map_generic_activity(raw_event, context, decision, missing_fields)
    class_uid = taxonomy.to_class_uid(
        taxonomy.IAM_CATEGORY_UID,
        taxonomy.AUTHORIZE_SESSION_ACTIVITY_UID,
    )
    activity_id = taxonomy.AUTHORIZE_SESSION_ASSIGN_PRIVILEGES_ID
    base = _base_event(
        raw_event,
        context,
        category_uid=taxonomy.IAM_CATEGORY_UID,
        class_uid=class_uid,
        activity_id=activity_id,
        mapping_attempt=_build_mapping_attempt(decision, missing_fields),
    )
    user = _extract_user(source)
    if user:
        base["user"] = user
    privileges = _extract_privileges(source)
    if privileges:
        base["privileges"] = privileges
    event_data = _extract_winlog_event_data(source)
    logon_id = _coerce_str(event_data.get("SubjectLogonId")) or _coerce_str(event_data.get("LogonId"))
    if logon_id:
        base["session"] = {"uid": logon_id}
    process = _extract_process(source)
    actor = _build_actor(source, None, process if process else None)
    if actor:
        base["actor"] = actor
    status = _coerce_str(_extract_nested_value(source, ("event", "outcome")))
    if status:
        base["status"] = status
    return base


def _map_windows_security_group_membership_enumeration(
    raw_event: Dict[str, Any],
    context: MappingContext,
    decision: FamilyDecision,
    missing_fields: list[str],
) -> Optional[Dict[str, Any]]:
    source = _extract_source(raw_event)
    if missing_fields:
        return None
    class_uid = taxonomy.to_class_uid(taxonomy.IAM_CATEGORY_UID, taxonomy.ENTITY_MANAGEMENT_ACTIVITY_UID)
    activity_id = taxonomy.ENTITY_MANAGEMENT_READ_ID
    event_data = _extract_winlog_event_data(source)
    actor_user = _extract_user(source) or _extract_winlog_subject_user(event_data)
    actor_process = _extract_winlog_caller_process(event_data)
    if not actor_process:
        actor_process = _extract_process(source)
    mapping_note = (
        "Mapped to iam/entity_management (read) because OCSF taxonomy lacks a specific "
        "group-membership-enumeration activity."
    )
    base = _base_event(
        raw_event,
        context,
        category_uid=taxonomy.IAM_CATEGORY_UID,
        class_uid=class_uid,
        activity_id=activity_id,
        mapping_attempt=_build_mapping_attempt(decision, missing_fields),
        unmapped_event_data=_build_group_membership_unmapped(event_data),
        mapping_note=mapping_note,
    )
    actor: Dict[str, Any] = {}
    if actor_user:
        actor["user"] = actor_user
    if actor_process:
        actor["process"] = actor_process
    if actor:
        base["actor"] = actor
    entity_name = _coerce_str(event_data.get("GroupName")) or _coerce_str(event_data.get("Group"))
    entity = {"name": entity_name} if entity_name else None
    if entity:
        base["entity"] = entity
    status = _coerce_str(_extract_nested_value(source, ("event", "outcome")))
    if status:
        base["status"] = status
    return base


def _map_process_activity(
    raw_event: Dict[str, Any],
    context: MappingContext,
    decision: FamilyDecision,
    missing_fields: list[str],
) -> Optional[Dict[str, Any]]:
    source = _extract_source(raw_event)
    if missing_fields:
        return _map_generic_activity(raw_event, context, decision, missing_fields)
    class_uid = taxonomy.to_class_uid(taxonomy.SYSTEM_CATEGORY_UID, taxonomy.PROCESS_ACTIVITY_UID)
    activity_id = _process_activity_id(source)
    if activity_id is None:
        return _map_generic_activity(raw_event, context, decision, missing_fields)
    base = _base_event(
        raw_event,
        context,
        category_uid=taxonomy.SYSTEM_CATEGORY_UID,
        class_uid=class_uid,
        activity_id=activity_id,
        mapping_attempt=_build_mapping_attempt(decision, missing_fields),
    )
    process = _extract_process(source)
    if process:
        base["process"] = process
    actor = _build_actor(source, process.get("parent_process") if process else None, process)
    if actor:
        base["actor"] = actor
    return base


def _map_network_activity(
    raw_event: Dict[str, Any],
    context: MappingContext,
    decision: FamilyDecision,
    missing_fields: list[str],
) -> Optional[Dict[str, Any]]:
    source = _extract_source(raw_event)
    if missing_fields:
        return _map_generic_activity(raw_event, context, decision, missing_fields)
    class_uid = taxonomy.to_class_uid(taxonomy.NETWORK_CATEGORY_UID, taxonomy.NETWORK_ACTIVITY_UID)
    activity_id = _network_activity_id(source)
    if activity_id is None:
        return _map_generic_activity(raw_event, context, decision, missing_fields)
    base = _base_event(
        raw_event,
        context,
        category_uid=taxonomy.NETWORK_CATEGORY_UID,
        class_uid=class_uid,
        activity_id=activity_id,
        mapping_attempt=_build_mapping_attempt(decision, missing_fields),
    )
    protocol = _extract_network_protocol(source)
    base["connection_info"] = {
        "direction_id": taxonomy.NETWORK_DIRECTION_UNKNOWN_ID,
        "protocol_name": protocol,
    }
    src_endpoint = _extract_source_endpoint(source)
    if src_endpoint:
        base["src_endpoint"] = src_endpoint
    dst_endpoint = _extract_destination_endpoint(source)
    if dst_endpoint:
        base["dst_endpoint"] = dst_endpoint
    return base


def _map_dns_activity(
    raw_event: Dict[str, Any],
    context: MappingContext,
    decision: FamilyDecision,
    missing_fields: list[str],
) -> Optional[Dict[str, Any]]:
    source = _extract_source(raw_event)
    if missing_fields:
        return _map_generic_activity(raw_event, context, decision, missing_fields)
    class_uid = taxonomy.to_class_uid(taxonomy.NETWORK_CATEGORY_UID, taxonomy.DNS_ACTIVITY_UID)
    activity_id = _dns_activity_id(source)
    if activity_id is None:
        return _map_generic_activity(raw_event, context, decision, missing_fields)
    base = _base_event(
        raw_event,
        context,
        category_uid=taxonomy.NETWORK_CATEGORY_UID,
        class_uid=class_uid,
        activity_id=activity_id,
        mapping_attempt=_build_mapping_attempt(decision, missing_fields),
    )
    query_name = _extract_dns_query_name(source)
    if query_name:
        base["query"] = {"hostname": query_name}
    answers = _extract_dns_answers(source)
    if answers:
        base["answers"] = answers
    rcode = _coerce_str(_extract_nested_value(source, ("dns", "response_code")))
    if rcode:
        base["rcode"] = rcode
    src_endpoint = _extract_source_endpoint(source)
    if src_endpoint:
        base["src_endpoint"] = src_endpoint
    dst_endpoint = _extract_destination_endpoint(source)
    if dst_endpoint:
        base["dst_endpoint"] = dst_endpoint
    protocol = _extract_network_protocol(source)
    if protocol:
        base["connection_info"] = {
            "direction_id": taxonomy.NETWORK_DIRECTION_UNKNOWN_ID,
            "protocol_name": protocol,
        }
    return base


def _map_elastic_agent_error(
    raw_event: Dict[str, Any],
    context: MappingContext,
    decision: FamilyDecision,
    missing_fields: list[str],
) -> Optional[Dict[str, Any]]:
    source = _extract_source(raw_event)
    if missing_fields:
        return None
    class_uid = taxonomy.to_class_uid(taxonomy.APPLICATION_CATEGORY_UID, taxonomy.APPLICATION_ERROR_UID)
    activity_id = taxonomy.APPLICATION_ERROR_GENERAL_ID
    base = _base_event(
        raw_event,
        context,
        category_uid=taxonomy.APPLICATION_CATEGORY_UID,
        class_uid=class_uid,
        activity_id=activity_id,
        mapping_attempt=_build_mapping_attempt(decision, missing_fields),
    )
    message = _coerce_str(_extract_nested_value(source, ("error", "message")))
    fallback_message = _coerce_str(source.get("message"))
    if message:
        base["message"] = message
    elif fallback_message:
        base["message"] = fallback_message
    event_code = _elastic_agent_event_code(source)
    if event_code:
        base["metadata"]["event_code"] = event_code
    device = base.get("device")
    if isinstance(device, dict) and "hostname" in device:
        device["hostname"] = _normalize_hostname(device["hostname"])
    elastic_agent_unmapped = _build_elastic_agent_unmapped(source, message, fallback_message)
    if elastic_agent_unmapped:
        base["unmapped"]["elastic_agent"] = elastic_agent_unmapped
    return base


def _map_elastic_agent_activity(
    raw_event: Dict[str, Any],
    context: MappingContext,
    decision: FamilyDecision,
    missing_fields: list[str],
) -> Optional[Dict[str, Any]]:
    source = _extract_source(raw_event)
    if missing_fields:
        return None
    class_uid = taxonomy.to_class_uid(taxonomy.APPLICATION_CATEGORY_UID, taxonomy.APPLICATION_LIFECYCLE_UID)
    activity_id = _elastic_agent_lifecycle_activity_id(source)
    if activity_id is None:
        return None
    base = _base_event(
        raw_event,
        context,
        category_uid=taxonomy.APPLICATION_CATEGORY_UID,
        class_uid=class_uid,
        activity_id=activity_id,
        mapping_attempt=_build_mapping_attempt(decision, missing_fields),
    )
    app = _extract_elastic_agent_app(source)
    if app:
        base["app"] = app
    message = _coerce_str(source.get("message"))
    if message:
        base["message"] = message
    event_code = _elastic_agent_event_code(source)
    if event_code:
        base["metadata"]["event_code"] = event_code
    device = base.get("device")
    if isinstance(device, dict) and "hostname" in device:
        device["hostname"] = _normalize_hostname(device["hostname"])
    elastic_agent_unmapped = _build_elastic_agent_state_unmapped(source)
    if elastic_agent_unmapped:
        base["unmapped"]["elastic_agent"] = elastic_agent_unmapped
    return base


def _authentication_activity_id(source: Dict[str, Any]) -> int:
    action = _event_action_text(source)
    if action and any(term in action for term in ("logoff", "logout")):
        return taxonomy.AUTHENTICATION_LOGOFF_ID
    return taxonomy.AUTHENTICATION_LOGON_ID


def _process_activity_id(source: Dict[str, Any]) -> Optional[int]:
    action = _event_action_text(source)
    if not action:
        return None
    if any(term in action for term in ("terminate", "terminated", "stop", "end", "kill", "exit")):
        return taxonomy.PROCESS_ACTIVITY_TERMINATE_ID
    if any(term in action for term in ("start", "launch", "create", "exec", "spawn", "fork")):
        return taxonomy.PROCESS_ACTIVITY_LAUNCH_ID
    return None


def _network_activity_id(source: Dict[str, Any]) -> Optional[int]:
    action = _event_action_text(source)
    if not action:
        return None
    if any(term in action for term in ("close", "end", "stop", "reset", "terminate")):
        return taxonomy.NETWORK_ACTIVITY_CLOSE_ID
    if "traffic" in action:
        return taxonomy.NETWORK_ACTIVITY_TRAFFIC_ID
    if any(term in action for term in ("open", "start", "connect", "connection", "allow", "accept")):
        return taxonomy.NETWORK_ACTIVITY_OPEN_ID
    return None


def _dns_activity_id(source: Dict[str, Any]) -> Optional[int]:
    action = _event_action_text(source)
    if "response" in action or "answer" in action:
        return taxonomy.DNS_ACTIVITY_RESPONSE_ID
    if "query" in action or "request" in action:
        return taxonomy.DNS_ACTIVITY_QUERY_ID
    query_name = _extract_dns_query_name(source)
    answers = _extract_dns_answers(source)
    if query_name and answers:
        return taxonomy.DNS_ACTIVITY_TRAFFIC_ID
    if query_name:
        return taxonomy.DNS_ACTIVITY_QUERY_ID
    if answers:
        return taxonomy.DNS_ACTIVITY_RESPONSE_ID
    return None


def _event_action_text(source: Dict[str, Any]) -> str:
    event = _get_event_block(source)
    candidates = []
    action = _coerce_str(event.get("action"))
    if action:
        candidates.append(action)
    candidates.extend(_coerce_list(event.get("type")))
    return " ".join(candidates).lower()


def _build_actor(
    source: Dict[str, Any],
    parent_process: Optional[Dict[str, Any]],
    fallback_process: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    actor: Dict[str, Any] = {}
    if parent_process:
        actor["process"] = parent_process
    elif fallback_process:
        actor["process"] = fallback_process
    user = _extract_user(source)
    if user:
        actor["user"] = user
    return actor


def _build_mapping_attempt(decision: FamilyDecision, missing_fields: list[str]) -> Dict[str, Any]:
    payload = {
        "family": decision.family,
        "reason": decision.reason,
    }
    if missing_fields:
        payload["missing_fields"] = missing_fields
    return payload


def _build_group_membership_unmapped(event_data: Dict[str, Any]) -> Dict[str, Any]:
    payload: Dict[str, Any] = {}
    target_user = _extract_winlog_target_user(event_data)
    if target_user:
        payload["target_user"] = target_user
    logon_id = _coerce_str(event_data.get("SubjectLogonId")) or _coerce_str(event_data.get("LogonId"))
    if logon_id:
        payload["logon_id"] = logon_id
    return payload


def _build_elastic_agent_unmapped(
    source: Dict[str, Any],
    error_message: Optional[str],
    original_message: Optional[str],
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {}
    service_name = _coerce_str(_extract_nested_value(source, ("service", "name")))
    service_type = _coerce_str(_extract_nested_value(source, ("service", "type")))
    if service_name or service_type:
        service: Dict[str, Any] = {}
        if service_name:
            service["name"] = service_name
        if service_type:
            service["type"] = service_type
        payload["service"] = service
    component_block = _extract_nested_value(source, ("component",))
    if isinstance(component_block, dict):
        component_payload: Dict[str, Any] = {}
        component_id = _coerce_str(component_block.get("id"))
        component_binary = _coerce_str(component_block.get("binary"))
        if component_id:
            component_payload["id"] = component_id
        if component_binary:
            component_payload["binary"] = component_binary
        if component_payload:
            payload["component"] = component_payload
    if error_message and original_message and error_message != original_message:
        payload["message"] = original_message
    elif not error_message and original_message:
        payload["message"] = original_message
    if error_message and (not original_message or error_message != original_message):
        payload["error_message"] = error_message
    return payload


def _build_elastic_agent_state_unmapped(source: Dict[str, Any]) -> Dict[str, Any]:
    payload: Dict[str, Any] = {}
    unit_block = source.get("unit")
    if isinstance(unit_block, dict):
        unit_payload: Dict[str, Any] = {}
        for key in ("id", "type", "state", "old_state"):
            value = _coerce_str(unit_block.get(key))
            if value:
                unit_payload[key] = value
        if unit_payload:
            payload["unit"] = unit_payload
    component_block = source.get("component")
    if isinstance(component_block, dict):
        component_payload: Dict[str, Any] = {}
        for key in ("id", "state"):
            value = _coerce_str(component_block.get(key))
            if value:
                component_payload[key] = value
        if component_payload:
            payload["component"] = component_payload
    return payload


def _elastic_agent_event_code(source: Dict[str, Any]) -> Optional[str]:
    event_dataset = _coerce_str(_extract_nested_value(source, ("event", "dataset")))
    data_stream_dataset = _elastic_agent_dataset(source)
    return data_stream_dataset or event_dataset


def _base_event(
    raw_event: Dict[str, Any],
    context: MappingContext,
    *,
    category_uid: int,
    class_uid: int,
    activity_id: int,
    mapping_attempt: Optional[Dict[str, Any]] = None,
    unmapped_event_data: Optional[Dict[str, Any]] = None,
    mapping_note: Optional[str] = None,
) -> Dict[str, Any]:
    hit = _extract_hit(raw_event)
    source = _extract_source(raw_event)
    time_value = _extract_event_time(raw_event, source)
    ids = raw_event.get("ids") or {}
    event_code = _extract_event_code(source, hit)
    index_name = hit.get("_index")
    doc_id = hit.get("_id")
    # metadata.uid is assigned after hashing to a stable OCSF event hash.
    metadata = {
        "product": {
            "name": "elastic",
            "vendor_name": "elastic",
        },
        "version": context.ocsf_version,
        "event_code": event_code,
        "original_event_uid": str(doc_id) if doc_id is not None else None,
        "log_name": str(index_name) if index_name is not None else None,
        "log_source": "elastic",
        "log_format": "json",
        "original_time": time_value,
    }
    metadata = {key: value for key, value in metadata.items() if value is not None}
    device: Dict[str, Any] = {"type_id": taxonomy.DEVICE_TYPE_UNKNOWN_ID}
    host_name = _extract_host_name(source)
    host_ip = _extract_host_ip(source)
    if host_name:
        device["hostname"] = host_name
    if host_ip:
        device["ip"] = host_ip
    base = {
        "activity_id": activity_id,
        "category_uid": category_uid,
        "class_uid": class_uid,
        "type_uid": taxonomy.to_type_uid(class_uid, activity_id),
        "time": time_value,
        "severity_id": _map_severity_id(raw_event.get("severity")),
        "metadata": metadata,
    }
    if device.get("hostname") or device.get("ip"):
        base["device"] = device
    base["unmapped"] = _build_unmapped(
        hit,
        source,
        mapping_attempt=mapping_attempt,
        unmapped_event_data=unmapped_event_data,
        mapping_note=mapping_note,
    )
    return base


def _build_unmapped(
    hit: Dict[str, Any],
    source: Dict[str, Any],
    *,
    mapping_attempt: Optional[Dict[str, Any]] = None,
    unmapped_event_data: Optional[Dict[str, Any]] = None,
    mapping_note: Optional[str] = None,
) -> Dict[str, Any]:
    elastic_block: Dict[str, Any] = {
        "_index": hit.get("_index"),
        "_id": hit.get("_id"),
        "_version": hit.get("_version"),
        "_source": source,
    }
    elastic_block = {key: value for key, value in elastic_block.items() if value is not None}
    payload: Dict[str, Any] = {"elastic": elastic_block}
    if mapping_attempt:
        payload["mapping_attempt"] = mapping_attempt
    if unmapped_event_data:
        payload["event_data"] = unmapped_event_data
    if mapping_note:
        payload["mapping_note"] = mapping_note
    return payload


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
