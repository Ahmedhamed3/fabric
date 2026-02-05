from __future__ import annotations

from pathlib import Path

from app.normalizers.sysmon_to_ocsf.io_ndjson import class_path_for_event, convert_events
from app.normalizers.sysmon_to_ocsf.mapper import MappingContext, map_raw_event
from app.normalizers.sysmon_to_ocsf.validator import OcsfSchemaLoader


SYSmon_EID1_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
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
    <Data Name="ParentProcessId">2222</Data>
    <Data Name="ParentProcessGuid">{22222222-2222-2222-2222-222222222222}</Data>
    <Data Name="ParentImage">C:\\Windows\\explorer.exe</Data>
    <Data Name="ParentCommandLine">explorer.exe</Data>
    <Data Name="User">CONTOSO\\jdoe</Data>
  </EventData>
</Event>"""

SYSmon_EID3_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" />
    <EventID>3</EventID>
    <Level>4</Level>
    <TimeCreated SystemTime="2024-01-02T03:05:05.678Z" />
    <EventRecordID>124</EventRecordID>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>HOST-A</Computer>
  </System>
  <EventData>
    <Data Name="UtcTime">2024-01-02 03:05:05.678</Data>
    <Data Name="ProcessId">4321</Data>
    <Data Name="ProcessGuid">{33333333-3333-3333-3333-333333333333}</Data>
    <Data Name="Image">C:\\Windows\\System32\\svchost.exe</Data>
    <Data Name="User">CONTOSO\\svc</Data>
    <Data Name="SourceIp">10.0.0.10</Data>
    <Data Name="SourcePort">50000</Data>
    <Data Name="DestinationIp">10.0.0.20</Data>
    <Data Name="DestinationPort">443</Data>
    <Data Name="Protocol">tcp</Data>
    <Data Name="Initiated">true</Data>
  </EventData>
</Event>"""

SYSmon_EID11_XML = Path("samples/sysmon_eventid11.xml").read_text(encoding="utf-8")

SYSmon_EID5_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" />
    <EventID>5</EventID>
    <Level>4</Level>
    <TimeCreated SystemTime="2024-01-02T03:07:05.678Z" />
    <EventRecordID>126</EventRecordID>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>HOST-A</Computer>
  </System>
  <EventData>
    <Data Name="UtcTime">2024-01-02 03:07:05.678</Data>
    <Data Name="ProcessId">7777</Data>
    <Data Name="ProcessGuid">{55555555-5555-5555-5555-555555555555}</Data>
    <Data Name="Image">C:\\Windows\\System32\\werfault.exe</Data>
  </EventData>
</Event>"""

SYSmon_EID22_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" />
    <EventID>22</EventID>
    <Level>4</Level>
    <TimeCreated SystemTime="2024-01-02T03:08:05.678Z" />
    <EventRecordID>127</EventRecordID>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>HOST-A</Computer>
  </System>
  <EventData>
    <Data Name="UtcTime">2024-01-02 03:08:05.678</Data>
    <Data Name="ProcessId">2468</Data>
    <Data Name="ProcessGuid">{66666666-6666-6666-6666-666666666666}</Data>
    <Data Name="Image">C:\\Windows\\System32\\svchost.exe</Data>
    <Data Name="User">CONTOSO\\svc</Data>
    <Data Name="QueryName">example.com</Data>
    <Data Name="QueryResults">93.184.216.34;2606:2800:220:1:248:1893:25c8:1946</Data>
    <Data Name="QueryStatus">0x0</Data>
  </EventData>
</Event>"""

SYSmon_EID22_JSON_EVENT_DATA = {
    "UtcTime": "2024-01-02 03:08:05.678",
    "ProcessId": "2468",
    "ProcessGuid": "{66666666-6666-6666-6666-666666666666}",
    "Image": "C:\\Windows\\System32\\svchost.exe",
    "User": "CONTOSO\\svc",
    "QueryName": "example.com",
    "QueryResults": "93.184.216.34",
    "QueryStatus": "0",
}


def build_raw_event(xml: str, event_id: int, record_id: int, dedupe_hash: str) -> dict:
    return {
        "envelope_version": "1.0",
        "source": {
            "type": "sysmon",
            "vendor": "microsoft",
            "product": "sysmon",
            "channel": "Microsoft-Windows-Sysmon/Operational",
        },
        "event": {"time": {"observed_utc": "2024-01-02T03:04:06.000Z", "created_utc": "2024-01-02T03:04:05.678Z"}},
        "ids": {
            "record_id": record_id,
            "event_id": event_id,
            "activity_id": None,
            "correlation_id": None,
            "dedupe_hash": dedupe_hash,
        },
        "host": {"hostname": "HOST-A", "os": "windows", "timezone": "UTC+0000"},
        "severity": "information",
        "tags": ["live", "sysmon"],
        "raw": {"format": "xml", "data": xml, "rendered_message": None, "xml": xml},
    }


def test_sysmon_mapping_is_schema_valid() -> None:
    schema_loader = OcsfSchemaLoader(Path("app/ocsf_schema"))
    context = MappingContext(ocsf_version=schema_loader.version)
    raw_events = [
        build_raw_event(SYSmon_EID1_XML, 1, 123, "sha256:one"),
        build_raw_event(SYSmon_EID3_XML, 3, 124, "sha256:two"),
        build_raw_event(SYSmon_EID11_XML, 11, 125, "sha256:three"),
        build_raw_event(SYSmon_EID5_XML, 5, 126, "sha256:four"),
    ]
    for raw_event in raw_events:
        mapped = map_raw_event(raw_event, context)
        assert mapped is not None
        class_path = class_path_for_event(mapped)
        assert class_path is not None
        result = schema_loader.validate_event(mapped, class_path)
        assert result.valid, result.errors


def test_sysmon_mapping_is_deterministic() -> None:
    schema_loader = OcsfSchemaLoader(Path("app/ocsf_schema"))
    context = MappingContext(ocsf_version=schema_loader.version)
    raw_event = build_raw_event(SYSmon_EID11_XML, 11, 125, "sha256:three")
    mapped_first = map_raw_event(raw_event, context)
    mapped_second = map_raw_event(raw_event, context)
    assert mapped_first == mapped_second
    assert mapped_first is not None
    assert mapped_first["metadata"]["original_event_uid"] == "125"
    hashes = {entry["algorithm_id"]: entry["value"] for entry in mapped_first["file"]["hashes"]}
    assert hashes[3].startswith("c")
    assert hashes[1].startswith("d")


def test_sysmon_event5_mapping_schema_valid() -> None:
    schema_loader = OcsfSchemaLoader(Path("app/ocsf_schema"))
    context = MappingContext(ocsf_version=schema_loader.version)
    raw_event = build_raw_event(SYSmon_EID5_XML, 5, 126, "sha256:four")
    mapped = map_raw_event(raw_event, context)
    assert mapped is not None
    assert mapped["class_uid"] == 1007
    assert mapped["activity_id"] == 2
    class_path = class_path_for_event(mapped)
    assert class_path is not None
    result = schema_loader.validate_event(mapped, class_path)
    assert result.valid, result.errors


def test_sysmon_event22_mapping_schema_valid_xml() -> None:
    schema_loader = OcsfSchemaLoader(Path("app/ocsf_schema"))
    context = MappingContext(ocsf_version=schema_loader.version)
    raw_event = build_raw_event(SYSmon_EID22_XML, 22, 127, "sha256:nine")
    mapped = map_raw_event(raw_event, context)
    assert mapped is not None
    assert mapped["class_uid"] == 4003
    assert mapped["activity_id"] == 1
    class_path = class_path_for_event(mapped)
    assert class_path is not None
    result = schema_loader.validate_event(mapped, class_path)
    assert result.valid, result.errors


def test_sysmon_event22_mapping_schema_valid_json() -> None:
    schema_loader = OcsfSchemaLoader(Path("app/ocsf_schema"))
    context = MappingContext(ocsf_version=schema_loader.version)
    raw_event = build_raw_event("", 22, 128, "sha256:ten")
    raw_event["parsed"] = {"event_data": SYSmon_EID22_JSON_EVENT_DATA}
    mapped = map_raw_event(raw_event, context)
    assert mapped is not None
    assert mapped["query"]["hostname"] == "example.com"
    class_path = class_path_for_event(mapped)
    assert class_path is not None
    result = schema_loader.validate_event(mapped, class_path)
    assert result.valid, result.errors


def test_sysmon_event5_missing_process_id_unmapped() -> None:
    schema_loader = OcsfSchemaLoader(Path("app/ocsf_schema"))
    context = MappingContext(ocsf_version=schema_loader.version)
    xml_payload = SYSmon_EID5_XML.replace(
        '<Data Name="ProcessId">7777</Data>',
        "",
    )
    raw_event = build_raw_event(xml_payload, 5, 127, "sha256:five")
    mapped = map_raw_event(raw_event, context)
    assert mapped is None


def test_sysmon_event5_missing_image_unmapped() -> None:
    schema_loader = OcsfSchemaLoader(Path("app/ocsf_schema"))
    context = MappingContext(ocsf_version=schema_loader.version)
    xml_payload = SYSmon_EID5_XML.replace(
        '<Data Name="Image">C:\\Windows\\System32\\werfault.exe</Data>',
        "",
    )
    raw_event = build_raw_event(xml_payload, 5, 128, "sha256:six")
    mapped = map_raw_event(raw_event, context)
    assert mapped is None


def test_sysmon_event5_mapping_is_deterministic() -> None:
    schema_loader = OcsfSchemaLoader(Path("app/ocsf_schema"))
    context = MappingContext(ocsf_version=schema_loader.version)
    raw_event = build_raw_event(SYSmon_EID5_XML, 5, 126, "sha256:four")
    mapped_first = map_raw_event(raw_event, context)
    mapped_second = map_raw_event(raw_event, context)
    assert mapped_first == mapped_second


def test_sysmon_event3_mapping_report_valid() -> None:
    schema_loader = OcsfSchemaLoader(Path("app/ocsf_schema"))
    raw_event = build_raw_event(SYSmon_EID3_XML, 3, 124, "sha256:two")
    results = list(convert_events([raw_event], schema_loader=schema_loader, strict=False))
    assert len(results) == 1
    mapped, report = results[0]
    assert mapped is not None
    assert report["supported"] is True
    assert report["mapped"] is True
    assert report["schema_valid"] is True
    assert report["status"] == "valid"
    assert mapped["actor"]["user"]["name"] == "svc"
    assert mapped["actor"]["process"]["pid"] == 4321
    assert mapped["actor"]["process"]["path"] == "C:\\Windows\\System32\\svchost.exe"
    assert mapped["connection_info"]["protocol_name"] == "tcp"
    assert mapped["src_endpoint"]["ip"] == "10.0.0.10"
    assert mapped["src_endpoint"]["port"] == 50000
    assert mapped["dst_endpoint"]["ip"] == "10.0.0.20"
    assert mapped["dst_endpoint"]["port"] == 443


def test_sysmon_event22_mapping_report_valid() -> None:
    schema_loader = OcsfSchemaLoader(Path("app/ocsf_schema"))
    raw_event = build_raw_event(SYSmon_EID22_XML, 22, 127, "sha256:nine")
    results = list(convert_events([raw_event], schema_loader=schema_loader, strict=False))
    assert len(results) == 1
    mapped, report = results[0]
    assert mapped is not None
    assert report["supported"] is True
    assert report["mapped"] is True
    assert report["schema_valid"] is True
    assert report["status"] == "valid"
    assert mapped["query"]["hostname"] == "example.com"
    assert mapped["actor"]["process"]["pid"] == 2468


def test_sysmon_event3_missing_fields_unmapped() -> None:
    schema_loader = OcsfSchemaLoader(Path("app/ocsf_schema"))
    xml_payload = SYSmon_EID3_XML.replace(
        '<Data Name="DestinationIp">10.0.0.20</Data>',
        "",
    )
    raw_event = build_raw_event(xml_payload, 3, 129, "sha256:seven")
    results = list(convert_events([raw_event], schema_loader=schema_loader, strict=False))
    mapped, report = results[0]
    assert mapped is None
    assert report["supported"] is True
    assert report["mapped"] is False
    assert report["status"] == "unmapped"
    assert "DestinationIp" in report["missing_fields"]


def test_sysmon_event22_missing_query_name_unmapped() -> None:
    schema_loader = OcsfSchemaLoader(Path("app/ocsf_schema"))
    xml_payload = SYSmon_EID22_XML.replace(
        '<Data Name="QueryName">example.com</Data>',
        "",
    )
    raw_event = build_raw_event(xml_payload, 22, 131, "sha256:eleven")
    results = list(convert_events([raw_event], schema_loader=schema_loader, strict=False))
    mapped, report = results[0]
    assert mapped is None
    assert report["supported"] is True
    assert report["mapped"] is False
    assert report["status"] == "unmapped"
    assert "QueryName" in report["missing_fields"]


def test_sysmon_event22_missing_time_unmapped() -> None:
    schema_loader = OcsfSchemaLoader(Path("app/ocsf_schema"))
    xml_payload = SYSmon_EID22_XML.replace(
        '<Data Name="UtcTime">2024-01-02 03:08:05.678</Data>',
        "",
    ).replace(
        '<TimeCreated SystemTime="2024-01-02T03:08:05.678Z" />',
        "",
    )
    raw_event = build_raw_event(xml_payload, 22, 132, "sha256:twelve")
    raw_event["event"]["time"] = {}
    results = list(convert_events([raw_event], schema_loader=schema_loader, strict=False))
    mapped, report = results[0]
    assert mapped is None
    assert report["supported"] is True
    assert report["mapped"] is False
    assert report["status"] == "unmapped"
    assert "UtcTime" in report["missing_fields"]


def test_sysmon_event22_missing_process_unmapped() -> None:
    schema_loader = OcsfSchemaLoader(Path("app/ocsf_schema"))
    xml_payload = SYSmon_EID22_XML.replace(
        '<Data Name="ProcessId">2468</Data>',
        "",
    ).replace(
        '<Data Name="Image">C:\\Windows\\System32\\svchost.exe</Data>',
        "",
    )
    raw_event = build_raw_event(xml_payload, 22, 133, "sha256:thirteen")
    results = list(convert_events([raw_event], schema_loader=schema_loader, strict=False))
    mapped, report = results[0]
    assert mapped is None
    assert report["supported"] is True
    assert report["mapped"] is False
    assert report["status"] == "unmapped"
    assert "ProcessId" in report["missing_fields"]
    assert "Image" in report["missing_fields"]


def test_sysmon_event11_missing_fields_unmapped() -> None:
    schema_loader = OcsfSchemaLoader(Path("app/ocsf_schema"))
    xml_payload = SYSmon_EID11_XML.replace(
        '<Data Name="TargetFilename">C:\\Temp\\notes.txt</Data>',
        "",
    )
    raw_event = build_raw_event(xml_payload, 11, 130, "sha256:eight")
    results = list(convert_events([raw_event], schema_loader=schema_loader, strict=False))
    mapped, report = results[0]
    assert mapped is None
    assert report["supported"] is True
    assert report["mapped"] is False
    assert report["status"] == "unmapped"
    assert "TargetFilename" in report["missing_fields"]


def test_sysmon_event3_mapping_is_deterministic() -> None:
    schema_loader = OcsfSchemaLoader(Path("app/ocsf_schema"))
    context = MappingContext(ocsf_version=schema_loader.version)
    raw_event = build_raw_event(SYSmon_EID3_XML, 3, 124, "sha256:two")
    mapped_first = map_raw_event(raw_event, context)
    mapped_second = map_raw_event(raw_event, context)
    assert mapped_first == mapped_second


def test_sysmon_event22_mapping_is_deterministic() -> None:
    schema_loader = OcsfSchemaLoader(Path("app/ocsf_schema"))
    context = MappingContext(ocsf_version=schema_loader.version)
    raw_event = build_raw_event(SYSmon_EID22_XML, 22, 127, "sha256:nine")
    mapped_first = map_raw_event(raw_event, context)
    mapped_second = map_raw_event(raw_event, context)
    assert mapped_first == mapped_second


def test_validator_reports_errors() -> None:
    schema_loader = OcsfSchemaLoader(Path("app/ocsf_schema"))
    context = MappingContext(ocsf_version=schema_loader.version)
    raw_event = build_raw_event(SYSmon_EID3_XML, 3, 124, "sha256:two")
    mapped = map_raw_event(raw_event, context)
    assert mapped is not None
    mapped.pop("metadata", None)
    class_path = class_path_for_event(mapped)
    assert class_path is not None
    result = schema_loader.validate_event(mapped, class_path)
    assert not result.valid
    assert any("metadata" in error for error in result.errors)
