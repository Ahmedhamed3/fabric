from __future__ import annotations

from pathlib import Path

from app.normalizers.elastic_to_ocsf.io_ndjson import class_path_for_event, convert_events
from app.normalizers.elastic_to_ocsf.mapper import MappingContext, map_raw_event
from app.normalizers.elastic_to_ocsf.validator import OcsfSchemaLoader
from app.utils.raw_envelope import build_elastic_raw_event


def build_raw_event(hit: dict) -> dict:
    return build_elastic_raw_event(
        hit,
        now_utc="2024-06-01T12:00:00Z",
        hostname="collector-host",
        timezone_name="UTC+0000",
    )


def build_context() -> tuple[OcsfSchemaLoader, MappingContext]:
    schema_loader = OcsfSchemaLoader(Path("app/ocsf_schema"))
    context = MappingContext(ocsf_version=schema_loader.version)
    return schema_loader, context


def test_elastic_authentication_mapping_schema_valid() -> None:
    hit = {
        "_index": "logs-auth-default",
        "_id": "auth-1",
        "_source": {
            "@timestamp": "2024-06-01T11:59:00Z",
            "event": {
                "category": ["authentication"],
                "action": "user_login",
                "code": "AUTH-100",
                "outcome": "success",
            },
            "user": {"name": "alice", "id": "1001"},
            "source": {"ip": "10.0.0.10", "port": 51515},
            "destination": {"ip": "10.0.0.20", "port": 443},
            "host": {"name": "auth-host"},
        },
    }
    schema_loader, context = build_context()
    raw_event = build_raw_event(hit)

    mapped = map_raw_event(raw_event, context)

    assert mapped is not None
    assert mapped["class_uid"] == 3002
    assert mapped["activity_id"] == 1
    class_path = class_path_for_event(mapped)
    assert class_path == "iam/authentication"
    result = schema_loader.validate_event(mapped, class_path)
    assert result.valid, result.errors


def test_elastic_network_mapping_schema_valid() -> None:
    hit = {
        "_index": "logs-network-default",
        "_id": "net-1",
        "_source": {
            "@timestamp": "2024-06-01T11:58:00Z",
            "event": {
                "category": ["network"],
                "action": "connection",
                "dataset": "network.flow",
            },
            "network": {"transport": "tcp"},
            "source": {"ip": "10.0.0.20", "port": 12345},
            "destination": {"ip": "10.0.0.30", "port": 443},
        },
    }
    schema_loader, context = build_context()
    raw_event = build_raw_event(hit)

    mapped = map_raw_event(raw_event, context)

    assert mapped is not None
    assert mapped["class_uid"] == 4001
    assert mapped["activity_id"] == 1
    class_path = class_path_for_event(mapped)
    assert class_path == "network/network_activity"
    result = schema_loader.validate_event(mapped, class_path)
    assert result.valid, result.errors


def test_elastic_process_mapping_schema_valid() -> None:
    hit = {
        "_index": "logs-process-default",
        "_id": "proc-1",
        "_source": {
            "@timestamp": "2024-06-01T11:57:00Z",
            "event": {"category": ["process"], "action": "start"},
            "process": {
                "pid": 4321,
                "executable": "/usr/bin/bash",
                "entity_id": "proc-123",
            },
            "user": {"name": "bob"},
            "host": {"name": "endpoint-1"},
        },
    }
    schema_loader, context = build_context()
    raw_event = build_raw_event(hit)

    mapped = map_raw_event(raw_event, context)

    assert mapped is not None
    assert mapped["class_uid"] == 1007
    assert mapped["activity_id"] == 1
    class_path = class_path_for_event(mapped)
    assert class_path == "system/process_activity"
    result = schema_loader.validate_event(mapped, class_path)
    assert result.valid, result.errors


def test_elastic_windows_security_4673_mapping_schema_valid() -> None:
    hit = {
        "_index": "logs-windows.security-default",
        "_id": "winsec-4673",
        "_source": {
            "@timestamp": "2024-06-01T11:54:00Z",
            "event": {
                "category": ["authentication"],
                "code": "4673",
            },
            "winlog": {
                "channel": "Security",
                "event_data": {
                    "PrivilegeList": "SeBackupPrivilege SeRestorePrivilege",
                    "SubjectLogonId": "0x3e7",
                },
            },
            "user": {"name": "svc-backup", "id": "S-1-5-21-1000"},
            "process": {
                "pid": 4242,
                "name": "backup.exe",
                "executable": "C:\\Windows\\System32\\backup.exe",
            },
            "host": {"name": "win-host-01"},
        },
    }
    schema_loader, context = build_context()
    raw_event = build_raw_event(hit)

    mapped = map_raw_event(raw_event, context)

    assert mapped is not None
    assert mapped["class_uid"] == 3003
    assert mapped["category_uid"] == 3
    assert mapped["activity_id"] == 1
    assert mapped["type_uid"] == 300301
    class_path = class_path_for_event(mapped)
    assert class_path == "iam/authorize_session"
    assert "dst_endpoint" not in mapped
    assert mapped["actor"]["process"]["pid"] == 4242
    assert mapped["actor"]["process"]["name"] == "backup.exe"
    assert mapped["actor"]["process"]["path"] == "C:\\Windows\\System32\\backup.exe"
    assert mapped["unmapped"]["elastic"]["_source"] == hit["_source"]
    assert "elastic_source" not in mapped["unmapped"]
    result = schema_loader.validate_event(mapped, class_path)
    assert result.valid, result.errors


def test_elastic_windows_security_4798_hex_pid_mapping_schema_valid() -> None:
    hit = {
        "_index": "logs-windows.security-default",
        "_id": "winsec-4798-hex",
        "_source": {
            "@timestamp": "2024-06-01T11:53:00Z",
            "event": {
                "category": ["iam"],
                "code": "4798",
                "outcome": "success",
            },
            "user": {"name": "ecs-admin", "domain": "CORP", "id": "S-1-5-21-2000"},
            "winlog": {
                "channel": "Security",
                "event_data": {
                    "SubjectUserName": "admin",
                    "SubjectDomainName": "CORP",
                    "SubjectUserSid": "S-1-5-21-2000",
                    "CallerProcessName": "C:\\Windows\\System32\\net.exe",
                    "CallerProcessId": "0x25e0",
                    "TargetUserName": "bob",
                    "TargetDomainName": "CORP",
                    "TargetUserSid": "S-1-5-21-3000",
                    "GroupName": "Administrators",
                    "SubjectLogonId": "0x3e7",
                },
            },
            "host": {"name": "win-host-02"},
        },
    }
    schema_loader, context = build_context()
    raw_event = build_raw_event(hit)

    mapped = map_raw_event(raw_event, context)

    assert mapped is not None
    assert mapped["class_uid"] == 3004
    assert mapped["activity_id"] == 2
    class_path = class_path_for_event(mapped)
    assert class_path == "iam/entity_management"
    assert "dst_endpoint" not in mapped
    assert mapped["actor"]["user"]["name"] == "ecs-admin"
    assert mapped["actor"]["process"]["pid"] == 9696
    assert mapped["actor"]["process"]["name"] == "net.exe"
    assert mapped["actor"]["process"]["path"] == "C:\\Windows\\System32\\net.exe"
    assert mapped["entity"]["name"] == "Administrators"
    assert "mapping_note" in mapped["unmapped"]
    assert mapped["unmapped"]["event_data"]["target_user"]["name"] == "bob"
    assert mapped["unmapped"]["event_data"]["target_user"]["domain"] == "CORP"
    assert mapped["unmapped"]["event_data"]["target_user"]["uid"] == "S-1-5-21-3000"
    assert mapped["unmapped"]["event_data"]["logon_id"] == "0x3e7"
    result = schema_loader.validate_event(mapped, class_path)
    assert result.valid, result.errors


def test_elastic_windows_security_4798_decimal_pid_mapping_schema_valid() -> None:
    hit = {
        "_index": "logs-windows.security-default",
        "_id": "winsec-4798-decimal",
        "_source": {
            "@timestamp": "2024-06-01T11:53:30Z",
            "event": {
                "category": ["iam"],
                "outcome": "success",
            },
            "winlog": {
                "channel": "Security",
                "event_id": 4798,
                "event_data": {
                    "SubjectUserName": "admin",
                    "SubjectDomainName": "CORP",
                    "SubjectUserSid": "S-1-5-21-2000",
                    "CallerProcessName": "C:\\Windows\\System32\\net1.exe",
                    "CallerProcessId": "4321",
                    "TargetUserName": "bob",
                    "TargetDomainName": "CORP",
                    "TargetUserSid": "S-1-5-21-3000",
                    "GroupName": "Administrators",
                },
            },
            "host": {"name": "win-host-02"},
        },
    }
    schema_loader, context = build_context()
    raw_event = build_raw_event(hit)

    mapped = map_raw_event(raw_event, context)

    assert mapped is not None
    assert mapped["class_uid"] == 3004
    assert mapped["activity_id"] == 2
    class_path = class_path_for_event(mapped)
    assert class_path == "iam/entity_management"
    assert mapped["actor"]["user"]["name"] == "admin"
    assert mapped["actor"]["process"]["pid"] == 4321
    assert mapped["actor"]["process"]["name"] == "net1.exe"
    assert mapped["entity"]["name"] == "Administrators"
    result = schema_loader.validate_event(mapped, class_path)
    assert result.valid, result.errors


def test_elastic_windows_security_4798_missing_fields_reported() -> None:
    hit = {
        "_index": "logs-windows.security-default",
        "_id": "winsec-4798-missing",
        "_source": {
            "event": {
                "category": ["iam"],
                "code": "4798",
            },
            "user": {"name": "admin", "domain": "CORP", "id": "S-1-5-21-2000"},
            "winlog": {
                "channel": "Security",
                "event_data": {
                    "GroupName": "Administrators",
                },
            },
        },
    }
    schema_loader, _ = build_context()
    raw_event = build_raw_event(hit)
    raw_event["event"]["time"] = {}

    results = list(convert_events([raw_event], schema_loader=schema_loader, strict=False))

    assert results
    mapped, report = results[0]
    assert mapped is None
    assert report["status"] == "unmapped"
    assert "time" in report.get("missing_fields", [])
    assert "target_user" in report.get("missing_fields", [])


def test_elastic_windows_security_4798_mapping_is_deterministic() -> None:
    schema_loader, context = build_context()
    hit = {
        "_index": "logs-windows.security-default",
        "_id": "winsec-4798-dedupe",
        "_source": {
            "@timestamp": "2024-06-01T11:53:45Z",
            "event": {
                "category": ["iam"],
                "code": "4798",
                "outcome": "success",
            },
            "winlog": {
                "channel": "Security",
                "event_data": {
                    "SubjectUserName": "admin",
                    "SubjectDomainName": "CORP",
                    "SubjectUserSid": "S-1-5-21-2000",
                    "CallerProcessName": "C:\\Windows\\System32\\net.exe",
                    "CallerProcessId": "0x25e0",
                    "TargetUserName": "bob",
                    "TargetDomainName": "CORP",
                    "GroupName": "Administrators",
                },
            },
            "host": {"name": "win-host-02"},
        },
    }
    raw_event = build_raw_event(hit)

    first = map_raw_event(raw_event, context)
    second = map_raw_event(raw_event, context)

    assert first is not None
    assert second is not None
    assert first == second
    class_path = class_path_for_event(first)
    result = schema_loader.validate_event(first, class_path)
    assert result.valid, result.errors


def test_elastic_dns_mapping_schema_valid() -> None:
    hit = {
        "_index": "logs-dns-default",
        "_id": "dns-1",
        "_source": {
            "@timestamp": "2024-06-01T11:52:00Z",
            "event": {"category": ["network"], "action": "dns_query"},
            "network": {"transport": "udp"},
            "source": {"ip": "10.0.0.40", "port": 5353},
            "destination": {"ip": "10.0.0.53", "port": 53},
            "dns": {
                "question": {"name": "example.com"},
                "answers": [
                    {"data": "93.184.216.34", "type": "A", "ttl": 60},
                ],
                "response_code": "NOERROR",
            },
        },
    }
    schema_loader, context = build_context()
    raw_event = build_raw_event(hit)

    mapped = map_raw_event(raw_event, context)

    assert mapped is not None
    assert mapped["class_uid"] == 4003
    assert mapped["activity_id"] == 1
    class_path = class_path_for_event(mapped)
    assert class_path == "network/dns_activity"
    assert mapped["query"]["hostname"] == "example.com"
    assert mapped["answers"][0]["rdata"] == "93.184.216.34"
    result = schema_loader.validate_event(mapped, class_path)
    assert result.valid, result.errors


def test_elastic_generic_mapping_schema_valid() -> None:
    hit = {
        "_index": "logs-generic-default",
        "_id": "generic-1",
        "_source": {
            "@timestamp": "2024-06-01T11:56:00Z",
            "message": "Unclassified event",
        },
    }
    schema_loader, context = build_context()
    raw_event = build_raw_event(hit)

    mapped = map_raw_event(raw_event, context)

    assert mapped is not None
    assert mapped["class_uid"] == 0
    assert mapped["category_uid"] == 0
    class_path = class_path_for_event(mapped)
    assert class_path == "base_event"
    result = schema_loader.validate_event(mapped, class_path)
    assert result.valid, result.errors


def test_elastic_agent_dataset_mapping_schema_valid() -> None:
    hit = {
        "_index": "logs-elastic_agent-default",
        "_id": "elastic-agent-1",
        "_source": {
            "@timestamp": "2024-06-01T11:50:00Z",
            "data_stream": {"dataset": "elastic_agent"},
            "log": {"level": "info"},
            "message": "Unit state changed fleet-server (FAILED->STARTING): Starting",
            "unit": {
                "id": "fleet-server",
                "type": "service",
                "old_state": "FAILED",
                "state": "STARTING",
            },
            "component": {"id": "fleet-server", "state": "STARTING"},
            "agent": {"name": "elastic-agent-01"},
            "elastic_agent": {"version": "8.13.0"},
            "host": {"name": "Desktop-4URHEAC"},
        },
    }
    schema_loader, context = build_context()
    raw_event = build_raw_event(hit)

    mapped = map_raw_event(raw_event, context)

    assert mapped is not None
    assert mapped["category_uid"] == 6
    assert mapped["class_uid"] == 6002
    assert mapped["activity_id"] == 3
    assert mapped["type_uid"] != 0
    assert mapped["severity_id"] == 2
    assert mapped["app"]["name"] == "fleet-server"
    assert mapped["app"]["version"] == "8.13.0"
    assert mapped["device"]["hostname"] == "desktop-4urheac"
    assert mapped["metadata"]["event_code"] == "elastic_agent"
    assert mapped["unmapped"]["elastic_agent"]["unit"]["state"] == "STARTING"
    assert mapped["unmapped"]["elastic_agent"]["component"]["id"] == "fleet-server"
    class_path = class_path_for_event(mapped)
    assert class_path == "application/application_lifecycle"
    result = schema_loader.validate_event(mapped, class_path)
    assert result.valid, result.errors


def test_elastic_agent_dataset_mapping_is_deterministic() -> None:
    schema_loader, context = build_context()
    hit = {
        "_index": "logs-elastic_agent-default",
        "_id": "elastic-agent-dedupe",
        "_source": {
            "@timestamp": "2024-06-01T11:45:00Z",
            "data_stream": {"dataset": "elastic_agent"},
            "log": {"level": "info"},
            "message": "Unit state changed fleet-server (STOPPED->STARTING): Starting",
            "unit": {"id": "fleet-server", "state": "STARTING", "old_state": "STOPPED"},
            "host": {"name": "Desktop-4URHEAC"},
        },
    }
    raw_event = build_raw_event(hit)

    first = map_raw_event(raw_event, context)
    second = map_raw_event(raw_event, context)

    assert first is not None
    assert second is not None
    assert first["metadata"]["original_event_uid"] == second["metadata"]["original_event_uid"]
    results = list(convert_events([raw_event, raw_event], schema_loader=schema_loader, strict=False))
    assert results[0][1]["record_id"] == results[1][1]["record_id"]


def test_elastic_agent_fleet_server_error_mapping_schema_valid() -> None:
    hit = {
        "_index": "logs-elastic_agent.fleet_server-default",
        "_id": "fleet-err-1",
        "_source": {
            "@timestamp": "2024-06-01T11:50:00Z",
            "data_stream": {"dataset": "elastic_agent.fleet_server"},
            "service": {"name": "fleet-server", "type": "fleet-server"},
            "component": {"binary": "fleet-server", "id": "fleet-server"},
            "log": {"level": "error"},
            "message": "Fleet Server failed",
            "error": {"message": "Access is denied."},
            "host": {"name": "desktop-4urheac"},
        },
    }
    schema_loader, context = build_context()
    raw_event = build_raw_event(hit)

    mapped = map_raw_event(raw_event, context)

    assert mapped is not None
    assert mapped["category_uid"] == 6
    assert mapped["class_uid"] == 6008
    assert mapped["activity_id"] == 1
    assert mapped["type_uid"] != 0
    assert mapped["severity_id"] == 4
    assert mapped["message"] == "Access is denied."
    assert mapped["device"]["hostname"] == "desktop-4urheac"
    assert mapped["metadata"]["event_code"] == "elastic_agent.fleet_server"
    class_path = class_path_for_event(mapped)
    assert class_path == "application/application_error"
    result = schema_loader.validate_event(mapped, class_path)
    assert result.valid, result.errors


def test_elastic_agent_fleet_server_mapping_is_deterministic() -> None:
    schema_loader, context = build_context()
    hit = {
        "_index": "logs-elastic_agent.fleet_server-default",
        "_id": "fleet-err-dedupe",
        "_source": {
            "@timestamp": "2024-06-01T11:49:00Z",
            "data_stream": {"dataset": "elastic_agent.fleet_server"},
            "service": {"name": "fleet-server", "type": "fleet-server"},
            "log": {"level": "error"},
            "message": "Fleet Server failed",
            "error": {"message": "Access is denied."},
            "host": {"name": "desktop-4urheac"},
        },
    }
    raw_event = build_raw_event(hit)

    first = map_raw_event(raw_event, context)
    second = map_raw_event(raw_event, context)

    assert first is not None
    assert first == second
    class_path = class_path_for_event(first)
    result = schema_loader.validate_event(first, class_path)
    assert result.valid, result.errors


def test_elastic_agent_missing_required_fields_reported() -> None:
    hit = {
        "_index": "logs-elastic_agent-default",
        "_id": "agent-missing",
        "_source": {
            "data_stream": {"dataset": "elastic_agent"},
            "log": {"level": "info"},
            "message": "Unit state changed",
        },
    }
    schema_loader, _ = build_context()
    raw_event = build_raw_event(hit)
    raw_event["event"] = {}

    results = list(convert_events([raw_event], schema_loader=schema_loader, strict=False))

    assert results
    mapped, report = results[0]
    assert mapped is None
    assert report["status"] == "unmapped"
    assert "time" in report.get("missing_fields", [])
    assert "unit.id/component.id/agent.name" in report.get("missing_fields", [])
    assert "unit.state/component.state" in report.get("missing_fields", [])


def test_elastic_authentication_missing_required_fields_reported() -> None:
    hit = {
        "_index": "logs-auth-default",
        "_id": "auth-missing",
        "_source": {
            "@timestamp": "2024-06-01T11:55:00Z",
            "event": {"category": ["authentication"], "action": "user_login"},
            "host": {"name": "auth-host"},
        },
    }
    schema_loader, _ = build_context()
    raw_event = build_raw_event(hit)

    results = list(
        convert_events([raw_event], schema_loader=schema_loader, strict=False)
    )

    assert results
    mapped, report = results[0]
    assert mapped is not None
    assert mapped["class_uid"] == 0
    assert report["status"] == "valid"
    assert "user" in report.get("missing_fields", [])
    assert "dst_endpoint/service" in report.get("missing_fields", [])


def test_elastic_missing_required_fields_for_each_family() -> None:
    schema_loader, context = build_context()
    samples = [
        {
            "_id": "auth-missing",
            "_source": {"event": {"category": ["authentication"], "action": "login"}},
            "expected_missing": "user",
        },
        {
            "_id": "proc-missing",
            "_source": {"event": {"category": ["process"], "action": "start"}, "host": {"name": "host-a"}},
            "expected_missing": "process.pid/process.uid",
        },
        {
            "_id": "net-missing",
            "_source": {
                "event": {"category": ["network"], "action": "connection"},
                "network": {"transport": "tcp"},
                "source": {"ip": "10.0.0.1", "port": 1234},
            },
            "expected_missing": "destination.ip",
        },
        {
            "_id": "dns-missing",
            "_source": {"event": {"category": ["network"], "action": "dns_query"}},
            "expected_missing": "dns.question.name",
        },
        {
            "_id": "iam-missing",
            "_source": {
                "event": {"code": "4673"},
                "winlog": {"channel": "Security", "event_data": {}},
            },
            "expected_missing": "privileges",
        },
    ]

    for sample in samples:
        hit = {"_index": "logs-test", "_id": sample["_id"], "_source": sample["_source"]}
        raw_event = build_raw_event(hit)
        mapped = map_raw_event(raw_event, context)
        assert mapped is not None
        assert mapped["class_uid"] == 0
        report = list(convert_events([raw_event], schema_loader=schema_loader, strict=False))[0][1]
        assert sample["expected_missing"] in report.get("missing_fields", [])


def test_elastic_mapping_is_deterministic() -> None:
    schema_loader, context = build_context()
    hit = {
        "_index": "logs-network-default",
        "_id": "net-deterministic",
        "_source": {
            "@timestamp": "2024-06-01T11:40:00Z",
            "event": {"category": ["network"], "action": "connection"},
            "network": {"transport": "tcp"},
            "source": {"ip": "10.0.0.20", "port": 12345},
            "destination": {"ip": "10.0.0.30", "port": 443},
        },
    }
    raw_event = build_raw_event(hit)

    first = map_raw_event(raw_event, context)
    second = map_raw_event(raw_event, context)

    assert first == second
    class_path = class_path_for_event(first)
    result = schema_loader.validate_event(first, class_path)
    assert result.valid, result.errors
