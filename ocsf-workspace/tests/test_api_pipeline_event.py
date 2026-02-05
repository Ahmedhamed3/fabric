from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

import app.main as main


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


def build_raw_event(xml: str, event_id: int, record_id: int, dedupe_hash: str) -> dict:
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


def test_pipeline_event_sysmon_eid1(tmp_path: Path, monkeypatch) -> None:
    raw_event = build_raw_event(SYSmon_EID1_XML, 1, 123, "sha256:test")
    events_path = tmp_path / "events.ndjson"
    events_path.write_text(json.dumps(raw_event) + "\n", encoding="utf-8")
    monkeypatch.setattr(main, "_latest_sysmon_raw_path", lambda: events_path)

    client = TestClient(main.app)
    response = client.get("/api/pipeline/event", params={"source": "sysmon", "key": "123"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["ocsf"] is not None
    assert payload["report"]["schema_valid"] is True


def test_pipeline_ui_returns_html() -> None:
    client = TestClient(main.app)

    response = client.get("/ui/pipeline")

    assert response.status_code == 200
    assert "Pipeline Viewer" in response.text
