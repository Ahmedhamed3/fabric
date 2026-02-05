from __future__ import annotations

import argparse
import socket
import subprocess
import sys
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from xml.etree import ElementTree

from app.utils.checkpoint import Checkpoint, load_checkpoint, save_checkpoint
from app.utils.http_status import HttpStatusServer, StatusState, tail_ndjson
from app.utils.ndjson_writer import append_ndjson
from app.utils.pathing import build_output_paths
from app.utils.raw_envelope import build_security_raw_event, local_timezone_name
from app.utils.timeutil import to_utc_iso, utc_now_iso

CHANNEL = "Security"
DEFAULT_POLL_SECONDS = 5
DEFAULT_MAX_EVENTS = 500
DEFAULT_TAIL_SIZE = 200
CHECKPOINT_PATH = "state/security_checkpoint.json"
BASE_OUTPUT_DIR = "out/raw/endpoint/windows_security"


try:
    import win32evtlog  # type: ignore

    HAS_PYWIN32 = True
except ImportError:
    win32evtlog = None
    HAS_PYWIN32 = False


@dataclass
class ConnectorConfig:
    poll_seconds: int
    max_events: int
    http_port: int | None


class SecurityConnector:
    def __init__(self, tail_size: int = DEFAULT_TAIL_SIZE) -> None:
        self.hostname = socket.gethostname()
        self.channel = CHANNEL
        self.tail_buffer: deque[dict] = deque(maxlen=tail_size)
        self.mode = "pywin32" if HAS_PYWIN32 else "powershell"
        self._output_paths = build_output_paths(BASE_OUTPUT_DIR, self.hostname)
        self.timezone_name = local_timezone_name()

    def read_new_events(self, last_record_id: int, max_events: int) -> list[dict]:
        if HAS_PYWIN32:
            return self._read_new_events_pywin32(last_record_id, max_events)
        return self._read_new_events_powershell(last_record_id, max_events)

    def _read_new_events_pywin32(self, last_record_id: int, max_events: int) -> list[dict]:
        query = f"*[System[(EventRecordID>{last_record_id})]]"
        flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection
        try:
            handle = win32evtlog.EvtQuery(self.channel, flags, query)
        except Exception as exc:  # noqa: BLE001
            self._raise_access_denied(exc)
            raise
        events: list[dict] = []
        while len(events) < max_events:
            batch = win32evtlog.EvtNext(handle, min(64, max_events - len(events)))
            if not batch:
                break
            for event in batch:
                xml = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                parsed = parse_event_xml(xml)
                if parsed:
                    observed_utc = parsed.get("time_created_utc") or utc_now_iso()
                    events.append(
                        build_security_raw_event(
                            parsed, observed_utc, self.hostname, self.timezone_name
                        )
                    )
        return events

    def _read_new_events_powershell(self, last_record_id: int, max_events: int) -> list[dict]:
        filter_xpath = f"*[System[(EventRecordID>{last_record_id})]]"
        command = (
            "Get-WinEvent -LogName '{channel}' -FilterXPath '{xpath}' "
            "-MaxEvents {max_events} | Sort-Object RecordId | "
            "ForEach-Object {{ $_.ToXml() }}"
        ).format(channel=self.channel, xpath=filter_xpath, max_events=max_events)
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            message = result.stderr.strip() or "PowerShell error"
            self._raise_access_denied(message)
            raise RuntimeError(message)
        events: list[dict] = []
        for xml in result.stdout.splitlines():
            xml = xml.strip()
            if not xml:
                continue
            parsed = parse_event_xml(xml)
            if parsed:
                observed_utc = parsed.get("time_created_utc") or utc_now_iso()
                events.append(
                    build_security_raw_event(
                        parsed, observed_utc, self.hostname, self.timezone_name
                    )
                )
        return events

    def _raise_access_denied(self, error: object) -> None:
        message = str(error)
        if "access is denied" in message.lower():
            raise RuntimeError(
                "Access denied reading Security event log. "
                "Run with elevated privileges or grant access."
            )

    def run_forever(self, poll_seconds: int, max_events: int, http_port: int | None) -> None:
        checkpoint = load_checkpoint(CHECKPOINT_PATH)
        status_state = StatusState(
            hostname=self.hostname,
            channel=self.channel,
            mode=self.mode,
            last_record_id=checkpoint.last_record_id,
        )
        http_server = None
        if http_port is not None:
            http_server = HttpStatusServer(
                host="127.0.0.1",
                port=http_port,
                status_state=status_state,
                tail_buffer=self.tail_buffer,
                tail_reader=lambda limit: tail_ndjson(
                    self._output_paths.daily_events_path(), limit
                ),
            )
            http_server.start()
            log(f"HTTP status server listening on 127.0.0.1:{http_port}")
        backoff = 1
        try:
            while True:
                try:
                    events = self.read_new_events(checkpoint.last_record_id, max_events)
                    if events:
                        output_path = self._output_paths.daily_events_path()
                        written = append_ndjson(output_path, events)
                        for event in events:
                            self.tail_buffer.append(event)
                        checkpoint.last_record_id = max(
                            event["ids"]["record_id"] for event in events
                        )
                        save_checkpoint(CHECKPOINT_PATH, checkpoint)
                        status_state.update(
                            last_record_id=checkpoint.last_record_id,
                            events_written_total=status_state.events_written_total + written,
                            last_batch_count=written,
                            last_event_time_utc=events[-1]["event"]["time"]["created_utc"],
                            last_error=None,
                        )
                        log(
                            f"Wrote {written} events (record_id={checkpoint.last_record_id})"
                        )
                    else:
                        status_state.update(last_batch_count=0, last_error=None)
                        log("No new events")
                    backoff = 1
                    time.sleep(poll_seconds)
                except Exception as exc:  # noqa: BLE001
                    status_state.update(last_error=str(exc))
                    log(f"Error reading events: {exc}")
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 60)
        finally:
            if http_server:
                http_server.stop()


def parse_event_xml(xml: str) -> dict[str, Any] | None:
    try:
        root = ElementTree.fromstring(xml)
    except ElementTree.ParseError:
        return None
    namespace = ""
    if "}" in root.tag:
        namespace = root.tag.split("}")[0].strip("{")
    ns = {"e": namespace} if namespace else {}
    system = root.find("e:System", ns) if ns else root.find("System")
    if system is None:
        return None
    record_id_text = (
        system.findtext("e:EventRecordID", namespaces=ns)
        if ns
        else system.findtext("EventRecordID")
    )
    if not record_id_text:
        return None
    record_id = int(record_id_text)
    time_created = None
    time_node = system.find("e:TimeCreated", ns) if ns else system.find("TimeCreated")
    if time_node is not None:
        time_created = to_utc_iso(time_node.attrib.get("SystemTime"))
    provider = None
    provider_node = system.find("e:Provider", ns) if ns else system.find("Provider")
    if provider_node is not None:
        provider = provider_node.attrib.get("Name")
    activity_id = None
    correlation_id = None
    correlation_node = system.find("e:Correlation", ns) if ns else system.find("Correlation")
    if correlation_node is not None:
        activity_id = correlation_node.attrib.get("ActivityID")
        correlation_id = correlation_node.attrib.get("RelatedActivityID")
    channel = (
        system.findtext("e:Channel", namespaces=ns)
        if ns
        else system.findtext("Channel")
    )
    event_id = (
        system.findtext("e:EventID", namespaces=ns)
        if ns
        else system.findtext("EventID")
    )
    level = (
        system.findtext("e:Level", namespaces=ns)
        if ns
        else system.findtext("Level")
    )
    computer = (
        system.findtext("e:Computer", namespaces=ns)
        if ns
        else system.findtext("Computer")
    )
    event_data_node = root.find("e:EventData", ns) if ns else root.find("EventData")
    event_data = parse_event_data(event_data_node, ns)
    return {
        "record_id": record_id,
        "time_created_utc": time_created,
        "provider": provider,
        "activity_id": activity_id,
        "correlation_id": correlation_id,
        "channel": channel,
        "event_id": int(event_id) if event_id else None,
        "level": int(level) if level else None,
        "computer": computer,
        "event_data": event_data,
        "raw_xml": xml,
    }


def parse_event_data(
    node: ElementTree.Element | None, ns: dict[str, str] | None = None
) -> dict[str, Any]:
    if node is None:
        return {}
    data: dict[str, Any] = {}
    index = 0
    ns = ns or {}
    tag = "e:Data" if ns else "Data"
    for child in node.findall(tag, ns):
        index += 1
        name = child.attrib.get("Name") or f"param{index}"
        value = child.text or ""
        if name in data:
            existing = data[name]
            if isinstance(existing, list):
                existing.append(value)
            else:
                data[name] = [existing, value]
        else:
            data[name] = value
    return data


def log(message: str) -> None:
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    print(f"[{timestamp}] {message}", flush=True)


def parse_args(argv: list[str]) -> ConnectorConfig:
    parser = argparse.ArgumentParser(description="Security connector")
    parser.add_argument("--poll-seconds", type=int, default=DEFAULT_POLL_SECONDS)
    parser.add_argument("--max-events", type=int, default=DEFAULT_MAX_EVENTS)
    parser.add_argument("--http-port", type=int, default=None)
    args = parser.parse_args(argv)
    return ConnectorConfig(
        poll_seconds=args.poll_seconds,
        max_events=args.max_events,
        http_port=args.http_port,
    )


def main(argv: list[str] | None = None) -> None:
    config = parse_args(argv or sys.argv[1:])
    connector = SecurityConnector()
    connector.run_forever(
        poll_seconds=config.poll_seconds,
        max_events=config.max_events,
        http_port=config.http_port,
    )


if __name__ == "__main__":
    main()
