from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from app.normalizers.windows_security_to_ocsf.io_ndjson import class_path_for_event
from app.normalizers.windows_security_to_ocsf.mapper import (
    MappingContext,
    map_raw_event,
    mapping_attempted,
)
from app.utils.checkpoint import Checkpoint, load_checkpoint, save_checkpoint
from app.utils.debug_artifacts import debug_artifacts_enabled, mirror_path
from app.utils.debug_pipeline import debug_pipeline_enabled, read_ndjson, resolve_debug_input, write_ndjson
from app.utils.evidence_emission import emit_evidence_metadata_for_event, ensure_evidence_api_url
from app.utils.http_status import HttpStatusServer, StatusState, tail_ndjson
from app.utils.ndjson_writer import append_ndjson
from app.utils.ocsf_schema_loader import get_ocsf_schema_loader
from app.utils.pathing import build_output_paths
from app.utils.raw_envelope import build_security_raw_event, local_timezone_name
from app.utils.timeutil import to_utc_iso, utc_now_iso

CHANNEL = "Security"
DEFAULT_POLL_SECONDS = 5
DEFAULT_MAX_EVENTS = 500
DEFAULT_TAIL_SIZE = 200
CHECKPOINT_PATH = "state/security_checkpoint.json"
BASE_OUTPUT_DIR = "out/raw/endpoint/windows_security"
DEBUG_INPUT_ENV = "OCSF_DEBUG_SECURITY_INPUT"
DEBUG_INPUT_DEFAULT = "samples/windows_security.ndjson"


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
        self._debug_mode = debug_pipeline_enabled()
        self.mode = "debug-file" if self._debug_mode else ("pywin32" if HAS_PYWIN32 else "powershell")
        self._output_paths = build_output_paths(BASE_OUTPUT_DIR, self.hostname)
        self._debug_envelope_paths = None
        if not self._debug_mode and debug_artifacts_enabled():
            self._debug_envelope_paths = build_output_paths(
                "out/envelope/endpoint/windows_security", self.hostname
            )
        self.timezone_name = local_timezone_name()

    def read_new_events(self, last_record_id: int, max_events: int) -> list[dict]:
        if self._debug_mode:
            return self._read_debug_events(max_events)
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
        ensure_evidence_api_url()
        if self._debug_mode:
            self._run_debug_pipeline(poll_seconds, http_port)
            return
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
                        for event in events:
                            self._emit_evidence_metadata(event)
                        written = append_ndjson(output_path, events)
                        if self._debug_envelope_paths:
                            append_ndjson(
                                self._debug_envelope_paths.daily_events_path(), events
                            )
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

    def _emit_evidence_metadata(self, raw_event: dict) -> None:
        try:
            schema_loader = get_ocsf_schema_loader()
            context = MappingContext(ocsf_version=schema_loader.version)
            ocsf_event = map_raw_event(raw_event, context)
            if ocsf_event is None:
                return
            class_path = class_path_for_event(ocsf_event)
            emit_evidence_metadata_for_event(
                raw_event,
                ocsf_event,
                ocsf_schema=class_path,
                ocsf_version=context.ocsf_version,
                log=log,
            )
        except Exception as exc:  # noqa: BLE001
            log(f"[EVIDENCE-META] failed to build metadata: {exc}")

    def _run_debug_pipeline(self, poll_seconds: int, http_port: int | None) -> None:
        status_state = StatusState(
            hostname=self.hostname,
            channel=self.channel,
            mode=self.mode,
            last_record_id=0,
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
        try:
            raw_events = self._load_debug_raw_events()
            if raw_events:
                raw_path = self._output_paths.daily_events_path()
                write_ndjson(raw_path, raw_events)
                envelope_events = self._build_debug_envelopes(raw_events)
                if envelope_events:
                    envelope_path = mirror_path(
                        raw_path, BASE_OUTPUT_DIR, "out/envelope/endpoint/windows_security"
                    )
                    write_ndjson(envelope_path, envelope_events)
                    self._write_debug_ocsf_outputs(envelope_events, raw_path)
                status_state.update(
                    last_record_id=len(raw_events),
                    events_written_total=len(raw_events),
                    last_batch_count=len(raw_events),
                    last_event_time_utc=_debug_event_time(raw_events[-1]),
                    last_error=None,
                )
                for event in envelope_events[-DEFAULT_TAIL_SIZE:]:
                    self.tail_buffer.append(event)
            else:
                status_state.update(last_batch_count=0, last_error="No debug input events.")
                log("No debug input events found.")
            while True:
                time.sleep(poll_seconds)
        finally:
            if http_server:
                http_server.stop()

    def _read_debug_events(self, max_events: int) -> list[dict]:
        events = self._load_debug_raw_events()
        if max_events <= 0:
            return events
        return events[:max_events]

    def _load_debug_raw_events(self) -> list[dict]:
        input_path = resolve_debug_input(DEBUG_INPUT_ENV, DEBUG_INPUT_DEFAULT)
        return read_ndjson(input_path)

    def _build_debug_envelopes(self, raw_events: list[dict]) -> list[dict]:
        envelopes: list[dict] = []
        for index, raw_event in enumerate(raw_events, start=1):
            envelope = build_debug_security_envelope(
                raw_event, self.hostname, self.timezone_name, index
            )
            if mapping_attempted(envelope):
                envelopes.append(envelope)
        return envelopes

    def _write_debug_ocsf_outputs(self, envelope_events: list[dict], raw_path: Path) -> None:
        from app.normalizers.windows_security_to_ocsf.io_ndjson import convert_events, write_ndjson as write_ocsf
        from app.normalizers.windows_security_to_ocsf.validator import OcsfSchemaLoader

        schema_loader = OcsfSchemaLoader(Path("app/ocsf_schema"))
        outputs = []
        reports = []
        for ocsf_event, report in convert_events(
            envelope_events, schema_loader=schema_loader, strict=False
        ):
            if ocsf_event is not None:
                outputs.append(ocsf_event)
            if report.get("supported"):
                reports.append(report)
        ocsf_path = mirror_path(
            raw_path, BASE_OUTPUT_DIR, "out/ocsf/endpoint/windows_security"
        )
        report_path = ocsf_path.with_suffix(".report.ndjson")
        write_ocsf(ocsf_path, outputs)
        write_ocsf(report_path, reports)
        validation_reports = [report for report in reports if report.get("validation_ran")]
        if validation_reports:
            validation_path = mirror_path(
                report_path, "out/ocsf", "out/validation"
            )
            write_ocsf(validation_path, validation_reports)


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


def build_debug_security_envelope(
    raw_record: dict[str, Any],
    hostname: str,
    timezone_name: str,
    record_id: int,
) -> dict[str, Any]:
    event_id = raw_record.get("EventID") or raw_record.get("event_id")
    event_id_value = int(event_id) if isinstance(event_id, (int, str)) and str(event_id).isdigit() else None
    time_created = raw_record.get("TimeCreated") or raw_record.get("time_created")
    if isinstance(time_created, dict):
        time_created = time_created.get("SystemTime") or time_created.get("system_time")
    created_utc = to_utc_iso(time_created) or utc_now_iso()
    record = {
        "record_id": raw_record.get("RecordId")
        or raw_record.get("record_id")
        or record_id,
        "event_id": event_id_value,
        "time_created_utc": created_utc,
        "provider": raw_record.get("Provider") or raw_record.get("provider"),
        "channel": raw_record.get("Channel") or raw_record.get("channel") or CHANNEL,
        "level": raw_record.get("Level") or raw_record.get("level"),
        "computer": raw_record.get("Computer") or raw_record.get("computer") or hostname,
        "activity_id": raw_record.get("ActivityId") or raw_record.get("activity_id"),
        "correlation_id": raw_record.get("CorrelationId") or raw_record.get("correlation_id"),
        "rendered_message": raw_record.get("Message") or raw_record.get("rendered_message"),
        "raw_xml": raw_record.get("raw_xml") or raw_record.get("xml"),
        "EventData": raw_record.get("EventData") or raw_record.get("event_data") or {},
    }
    envelope = build_security_raw_event(record, created_utc, hostname, timezone_name)
    envelope["parsed"] = {"event_data": record.get("EventData") or {}}
    return envelope


def _debug_event_time(raw_event: dict[str, Any]) -> str:
    time_created = raw_event.get("TimeCreated")
    if isinstance(time_created, dict):
        time_created = time_created.get("SystemTime") or time_created.get("system_time")
    return to_utc_iso(time_created) or utc_now_iso()


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
    if os.name != "nt" and not debug_pipeline_enabled():
        log("[CONNECTOR] Windows-only connector skipped (non-Windows OS)")
        return
    config = parse_args(argv or sys.argv[1:])
    connector = SecurityConnector()
    connector.run_forever(
        poll_seconds=config.poll_seconds,
        max_events=config.max_events,
        http_port=config.http_port,
    )


if __name__ == "__main__":
    main()
