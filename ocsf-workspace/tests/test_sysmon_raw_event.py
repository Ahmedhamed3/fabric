from __future__ import annotations

import re

from app.connectors.sysmon import build_dedupe_hash, parse_event_xml


SAMPLE_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
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


def test_raw_event_envelope_shape() -> None:
    envelope = parse_event_xml(SAMPLE_XML, "EXAMPLE")
    assert envelope is not None
    assert envelope["envelope_version"] == "1.0"
    assert envelope["source"]["type"] == "sysmon"
    assert envelope["source"]["collector"]["instance_id"] == "EXAMPLE:sysmon"
    event = envelope["event"]
    assert envelope["ids"]["record_id"] == 123
    assert envelope["ids"]["event_id"] == 1
    assert event["time"]["created_utc"] == "2024-01-02T03:04:05.678Z"
    assert envelope["severity"] == "information"
    assert envelope["host"]["hostname"] == "EXAMPLE"
    assert envelope["host"]["os"] == "windows"
    assert re.match(r"^UTC[+-]\d{4}$", envelope["host"]["timezone"])
    assert envelope["raw"]["format"] == "xml"
    assert envelope["raw"]["data"] == SAMPLE_XML
    assert envelope["raw"]["xml"] == SAMPLE_XML


def test_dedupe_hash_is_deterministic() -> None:
    created_utc = "2024-01-02T03:04:05.678Z"
    hash_value = build_dedupe_hash("EXAMPLE", 123, 1, created_utc)
    assert (
        hash_value
        == "sha256:ee29a3127270e1471e2bae6a6d7a4d321cbffc4af988544c64aac088ce1b0acf"
    )
