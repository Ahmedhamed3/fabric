from __future__ import annotations

from pathlib import Path

from app.connectors import sysmon
from app.connectors.sysmon import SysmonConnector, parse_event_xml
from app.utils.checkpoint import Checkpoint
from app.utils.pathing import build_output_paths
from app.utils import ndjson_writer


def test_sysmon_fsync_before_checkpoint(tmp_path: Path, monkeypatch) -> None:
    connector = SysmonConnector()
    connector._output_paths = build_output_paths(tmp_path, connector.hostname)
    monkeypatch.setattr(sysmon, "CHECKPOINT_PATH", str(tmp_path / "checkpoint.json"))

    xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
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
    event = parse_event_xml(xml, "EXAMPLE")
    assert event is not None

    state = {"fsync_called": False, "checkpoint_called": False}

    def fake_fsync(_: int) -> None:
        state["fsync_called"] = True

    def fake_save_checkpoint(_: str, __: Checkpoint) -> None:
        assert state["fsync_called"] is True
        state["checkpoint_called"] = True

    monkeypatch.setattr(ndjson_writer.os, "fsync", fake_fsync)
    monkeypatch.setattr(sysmon, "save_checkpoint", fake_save_checkpoint)

    connector._write_events([event], Checkpoint())

    assert state["checkpoint_called"] is True
