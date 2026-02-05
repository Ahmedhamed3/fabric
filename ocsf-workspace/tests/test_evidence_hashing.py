from __future__ import annotations

from pathlib import Path

from app.normalizers.elastic_to_ocsf.mapper import MappingContext as ElasticMappingContext
from app.normalizers.elastic_to_ocsf.mapper import map_raw_event as map_elastic_raw_event
from app.normalizers.sysmon_to_ocsf.mapper import MappingContext as SysmonMappingContext
from app.normalizers.sysmon_to_ocsf.mapper import map_raw_event as map_sysmon_raw_event
from app.normalizers.windows_security_to_ocsf.mapper import MappingContext as SecurityMappingContext
from app.normalizers.windows_security_to_ocsf.mapper import map_raw_event as map_security_raw_event
from app.normalizers.sysmon_to_ocsf.validator import OcsfSchemaLoader
from app.utils.evidence_hashing import (
    apply_evidence_hashing,
    canonicalize_json,
    hash_sha256_hex,
)
from app.utils.raw_envelope import build_elastic_raw_event, build_security_raw_event


SYS_MON_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" />
    <EventID>1</EventID>
    <Level>4</Level>
    <TimeCreated SystemTime="2024-01-02T03:04:05.678Z" />
    <EventRecordID>123</EventRecordID>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>HOST-A</Computer>
  </System>
  <EventData>
    <Data Name="UtcTime">2024-01-02 03:04:05.678</Data>
    <Data Name="ProcessId">1234</Data>
    <Data Name="ProcessGuid">{11111111-1111-1111-1111-111111111111}</Data>
    <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
    <Data Name="CommandLine">cmd.exe /c whoami</Data>
  </EventData>
</Event>"""


def _schema_loader() -> OcsfSchemaLoader:
    return OcsfSchemaLoader(Path("app/ocsf_schema"))


def _build_sysmon_raw_event() -> dict:
    return {
        "envelope_version": "1.0",
        "source": {
            "type": "sysmon",
            "vendor": "microsoft",
            "product": "sysmon",
            "channel": "Microsoft-Windows-Sysmon/Operational",
        },
        "event": {
            "time": {
                "observed_utc": "2024-01-02T03:04:06.000Z",
                "created_utc": "2024-01-02T03:04:05.678Z",
            }
        },
        "ids": {
            "record_id": 123,
            "event_id": 1,
            "activity_id": None,
            "correlation_id": None,
            "dedupe_hash": "sha256:sysmon-test",
        },
        "host": {"hostname": "HOST-A", "os": "windows", "timezone": "UTC+0000"},
        "severity": "information",
        "tags": ["live", "sysmon"],
        "raw": {"format": "xml", "data": SYS_MON_XML, "rendered_message": None, "xml": SYS_MON_XML},
    }


def _build_security_raw_event() -> dict:
    raw_record = {
        "record_id": 200,
        "time_created_utc": "2024-01-01T12:00:00Z",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "event_id": 4624,
        "level": 4,
        "computer": "WIN-TEST",
        "event_data": {
            "SubjectUserSid": "S-1-5-18",
            "SubjectUserName": "SYSTEM",
            "SubjectDomainName": "NT AUTHORITY",
            "TargetUserSid": "S-1-5-21-111",
            "TargetUserName": "alice",
            "TargetDomainName": "CONTOSO",
            "LogonType": "3",
            "IpAddress": "10.0.0.5",
        },
        "raw_xml": None,
    }
    return build_security_raw_event(
        raw_record,
        observed_utc="2024-01-01T12:00:00Z",
        hostname="collector-host",
        timezone_name="UTC+0000",
    )


def _build_elastic_raw_event() -> dict:
    hit = {
        "_index": "logs-test-0001",
        "_id": "doc-1",
        "_source": {
            "@timestamp": "2024-01-01T00:00:00Z",
            "event": {
                "kind": "event",
                "category": ["process"],
                "action": "start",
            },
            "process": {
                "pid": 4321,
                "executable": "C:\\\\Windows\\\\System32\\\\cmd.exe",
                "command_line": "cmd.exe /c whoami",
            },
            "host": {"name": "elastic-host"},
        },
    }
    return build_elastic_raw_event(
        hit,
        now_utc="2024-01-01T00:00:01Z",
        hostname="collector-host",
        timezone_name="UTC+0000",
    )


def test_canonicalization_is_deterministic() -> None:
    payload = {"b": 1, "a": ["z", {"c": 2, "d": 3}]}
    first = canonicalize_json(payload)
    second = canonicalize_json(payload)
    assert first == second
    assert hash_sha256_hex(first) == hash_sha256_hex(second)


def test_canonicalization_key_order_is_stable() -> None:
    payload_a = {"b": 1, "a": {"y": 2, "x": 3}}
    payload_b = {"a": {"x": 3, "y": 2}, "b": 1}
    assert canonicalize_json(payload_a) == canonicalize_json(payload_b)


def test_hash_changes_on_single_bit_change() -> None:
    payload_a = {"message": "alpha"}
    payload_b = {"message": "alphb"}
    hash_a = hash_sha256_hex(canonicalize_json(payload_a))
    hash_b = hash_sha256_hex(canonicalize_json(payload_b))
    assert hash_a != hash_b


def test_evidence_hashing_regression_sysmon_windows_elastic() -> None:
    schema_loader = _schema_loader()
    sysmon_context = SysmonMappingContext(ocsf_version=schema_loader.version)
    security_context = SecurityMappingContext(ocsf_version=schema_loader.version)
    elastic_context = ElasticMappingContext(ocsf_version=schema_loader.version)

    sysmon_raw = _build_sysmon_raw_event()
    security_raw = _build_security_raw_event()
    elastic_raw = _build_elastic_raw_event()

    sysmon_ocsf = map_sysmon_raw_event(sysmon_raw, sysmon_context)
    security_ocsf = map_security_raw_event(security_raw, security_context)
    elastic_ocsf = map_elastic_raw_event(elastic_raw, elastic_context)

    assert sysmon_ocsf is not None
    assert security_ocsf is not None
    assert elastic_ocsf is not None

    sysmon_result = apply_evidence_hashing(
        sysmon_raw,
        sysmon_ocsf,
        ocsf_schema="system/process_activity",
        ocsf_version=schema_loader.version,
        hashed_utc="2024-01-01T00:00:00Z",
    )
    security_result = apply_evidence_hashing(
        security_raw,
        security_ocsf,
        ocsf_schema="iam/authentication",
        ocsf_version=schema_loader.version,
        hashed_utc="2024-01-01T00:00:00Z",
    )
    elastic_result = apply_evidence_hashing(
        elastic_raw,
        elastic_ocsf,
        ocsf_schema="system/process_activity",
        ocsf_version=schema_loader.version,
        hashed_utc="2024-01-01T00:00:00Z",
    )

    assert sysmon_result.ocsf_event["metadata"]["original_event_uid"] == "123"
    assert security_result.ocsf_event["metadata"]["original_event_uid"] == "200"
    assert elastic_result.ocsf_event["metadata"]["original_event_uid"] == "doc-1"

    assert sysmon_result.ocsf_event["metadata"]["uid"].startswith("sha256:")
    assert security_result.ocsf_event["metadata"]["uid"].startswith("sha256:")
    assert elastic_result.ocsf_event["metadata"]["uid"].startswith("sha256:")
    assert sysmon_result.ocsf_event["metadata"]["uid"] == f"sha256:{sysmon_result.evidence_commit['ocsf']['hash_sha256']}"
    assert security_result.ocsf_event["metadata"]["uid"] == f"sha256:{security_result.evidence_commit['ocsf']['hash_sha256']}"
    assert elastic_result.ocsf_event["metadata"]["uid"] == f"sha256:{elastic_result.evidence_commit['ocsf']['hash_sha256']}"

    assert sysmon_result.raw_envelope["derived"]["ocsf_event_hash"] == sysmon_result.evidence_commit["ocsf"]["hash_sha256"]
    assert security_result.raw_envelope["derived"]["ocsf_event_hash"] == security_result.evidence_commit["ocsf"]["hash_sha256"]
    assert elastic_result.raw_envelope["derived"]["ocsf_event_hash"] == elastic_result.evidence_commit["ocsf"]["hash_sha256"]

    assert sysmon_result.ocsf_event["forensics"]["raw_envelope_hash"] == sysmon_result.evidence_commit["raw"]["envelope"]["hash_sha256"]
    assert security_result.ocsf_event["forensics"]["raw_envelope_hash"] == security_result.evidence_commit["raw"]["envelope"]["hash_sha256"]
    assert elastic_result.ocsf_event["forensics"]["raw_envelope_hash"] == elastic_result.evidence_commit["raw"]["envelope"]["hash_sha256"]

    assert sysmon_result.evidence_commit["raw"]["envelope"]["hash_sha256"] == "c3414f3357e7773e81679d237a014918caf1422c11cb4eab576fa7f2dd138451"
    assert sysmon_result.evidence_commit["raw"]["payload"]["hash_sha256"] == "148c9c0ff64e499bbce35e3b5d422f9a772c97f17630f81861b4a081438e929d"
    assert sysmon_result.evidence_commit["ocsf"]["hash_sha256"] == "d3534eca890931f5656232dc5be7c679320bd1307afac14095c6ca05a7b9dd0d"
    assert security_result.evidence_commit["raw"]["envelope"]["hash_sha256"] == "144bf615f3a1c7821c0cc87ad75924d063e6f582341ced1d596ab691f3ba0643"
    assert security_result.evidence_commit["raw"]["payload"]["hash_sha256"] == "216b4c66436f2a476d6235a0faca54c27d7039681eaae5f13aca903116a03a60"
    assert security_result.evidence_commit["ocsf"]["hash_sha256"] == "9429e1c01a216e6778a89f4e142fafa1283e80777975caaec021229bfe79f709"
    assert elastic_result.evidence_commit["raw"]["envelope"]["hash_sha256"] == "59111eb407eab5f6b7463b2b01674f5b599e9d91690ebe46538fba3751bb643b"
    assert elastic_result.evidence_commit["raw"]["payload"]["hash_sha256"] == "8743d406ab512cbcfc123ea427f9167c4f0df9a58d954a5c8814f9a11247a664"
    assert elastic_result.evidence_commit["ocsf"]["hash_sha256"] == "ec648c64e5fa713695b19617083cf30b12da0e340565f4bac9e9ecd33529ea45"


def test_envelope_and_payload_hashes_are_deterministic() -> None:
    raw_event = _build_sysmon_raw_event()
    schema_loader = _schema_loader()
    context = SysmonMappingContext(ocsf_version=schema_loader.version)
    ocsf_event = map_sysmon_raw_event(raw_event, context)
    assert ocsf_event is not None

    first = apply_evidence_hashing(
        raw_event,
        ocsf_event,
        ocsf_schema="system/process_activity",
        ocsf_version=schema_loader.version,
        hashed_utc="2024-01-01T00:00:00Z",
    )
    second = apply_evidence_hashing(
        raw_event,
        ocsf_event,
        ocsf_schema="system/process_activity",
        ocsf_version=schema_loader.version,
        hashed_utc="2024-01-01T00:00:00Z",
    )

    assert first.evidence_commit["raw"]["envelope"]["hash_sha256"] == second.evidence_commit["raw"]["envelope"]["hash_sha256"]
    assert first.evidence_commit["raw"]["payload"]["hash_sha256"] == second.evidence_commit["raw"]["payload"]["hash_sha256"]


def test_envelope_hash_ignores_key_order() -> None:
    raw_event = _build_sysmon_raw_event()
    reordered = dict(reversed(list(raw_event.items())))
    schema_loader = _schema_loader()
    context = SysmonMappingContext(ocsf_version=schema_loader.version)
    ocsf_event = map_sysmon_raw_event(raw_event, context)
    assert ocsf_event is not None

    original = apply_evidence_hashing(
        raw_event,
        ocsf_event,
        ocsf_schema="system/process_activity",
        ocsf_version=schema_loader.version,
        hashed_utc="2024-01-01T00:00:00Z",
    )
    updated = apply_evidence_hashing(
        reordered,
        ocsf_event,
        ocsf_schema="system/process_activity",
        ocsf_version=schema_loader.version,
        hashed_utc="2024-01-01T00:00:00Z",
    )

    assert original.evidence_commit["raw"]["envelope"]["hash_sha256"] == updated.evidence_commit["raw"]["envelope"]["hash_sha256"]


def test_payload_change_updates_payload_and_envelope_hashes() -> None:
    raw_event = _build_sysmon_raw_event()
    schema_loader = _schema_loader()
    context = SysmonMappingContext(ocsf_version=schema_loader.version)
    ocsf_event = map_sysmon_raw_event(raw_event, context)
    assert ocsf_event is not None

    original = apply_evidence_hashing(
        raw_event,
        ocsf_event,
        ocsf_schema="system/process_activity",
        ocsf_version=schema_loader.version,
        hashed_utc="2024-01-01T00:00:00Z",
    )
    updated_raw = _build_sysmon_raw_event()
    updated_raw["raw"]["data"] = SYS_MON_XML.replace("cmd.exe /c whoami", "cmd.exe /c hostname")
    updated_raw["raw"]["xml"] = updated_raw["raw"]["data"]
    updated = apply_evidence_hashing(
        updated_raw,
        ocsf_event,
        ocsf_schema="system/process_activity",
        ocsf_version=schema_loader.version,
        hashed_utc="2024-01-01T00:00:00Z",
    )

    assert original.evidence_commit["raw"]["payload"]["hash_sha256"] != updated.evidence_commit["raw"]["payload"]["hash_sha256"]
    assert original.evidence_commit["raw"]["envelope"]["hash_sha256"] != updated.evidence_commit["raw"]["envelope"]["hash_sha256"]


def test_evidence_id_strategy_is_consistent() -> None:
    raw_event = _build_sysmon_raw_event()
    schema_loader = _schema_loader()
    context = SysmonMappingContext(ocsf_version=schema_loader.version)
    ocsf_event = map_sysmon_raw_event(raw_event, context)
    assert ocsf_event is not None

    first = apply_evidence_hashing(
        raw_event,
        ocsf_event,
        ocsf_schema="system/process_activity",
        ocsf_version=schema_loader.version,
        hashed_utc="2024-01-01T00:00:00Z",
    )
    second = apply_evidence_hashing(
        raw_event,
        ocsf_event,
        ocsf_schema="system/process_activity",
        ocsf_version=schema_loader.version,
        hashed_utc="2024-01-01T00:00:00Z",
    )
    evidence_id = first.evidence_commit["evidence_id"]
    if evidence_id.startswith("uuidv7:"):
        assert evidence_id != second.evidence_commit["evidence_id"]
    else:
        assert evidence_id == second.evidence_commit["evidence_id"]
