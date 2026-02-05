from __future__ import annotations

from app.connectors.sysmon import parse_event_xml
from app.utils.raw_envelope import (
    build_elastic_raw_event,
    build_security_raw_event,
    validate_raw_event_v1,
)


def test_validator_accepts_sysmon_security_elastic() -> None:
    sysmon_xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-Sysmon" Guid="{11111111-1111-1111-1111-111111111111}" />
        <EventID>1</EventID>
        <Level>4</Level>
        <TimeCreated SystemTime="2024-01-02T03:04:05.678Z" />
        <EventRecordID>123</EventRecordID>
        <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
        <Computer>EXAMPLE</Computer>
      </System>
      <EventData>
        <Data Name="RuleName">-</Data>
      </EventData>
    </Event>"""
    sysmon_event = parse_event_xml(sysmon_xml, "EXAMPLE")
    assert sysmon_event is not None
    assert validate_raw_event_v1(sysmon_event) == []

    security_raw = {
        "record_id": 2048,
        "time_created_utc": "2024-02-03T04:05:06.789Z",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "event_id": 4625,
        "level": 4,
        "computer": "HOST-A",
        "event_data": {"SubjectUserName": "alice"},
        "raw_xml": "<Event>minimal</Event>",
    }
    security_event = build_security_raw_event(
        security_raw,
        observed_utc=security_raw["time_created_utc"],
        hostname="HOST-A",
        timezone_name="UTC+0000",
    )
    assert validate_raw_event_v1(security_event) == []

    elastic_hit = {
        "_index": "logs-test-default",
        "_id": "abc123",
        "_source": {
            "@timestamp": "2024-04-01T12:34:56.789Z",
            "message": "Hello elastic",
            "event": {"id": "evt-1", "code": "A1", "severity": 7},
            "log": {"level": "error"},
            "host": {"name": "host-a", "os": {"name": "Linux"}},
        },
    }
    elastic_event = build_elastic_raw_event(
        elastic_hit,
        now_utc="2024-04-01T12:35:00Z",
        hostname="collector-host",
        timezone_name="UTC+0000",
    )
    assert validate_raw_event_v1(elastic_event) == []
