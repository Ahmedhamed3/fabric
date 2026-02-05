from __future__ import annotations

import argparse
import hashlib
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

from app.utils.checkpoint import Checkpoint, load_checkpoint, save_checkpoint
from app.utils.dedupe_cache import DedupeCache, load_dedupe_cache, save_dedupe_cache
from app.utils.http_status import HttpStatusServer, StatusState, tail_ndjson
from app.utils.ndjson_writer import append_ndjson
from app.utils.pathing import build_output_paths
from app.utils.timeutil import to_utc_iso, utc_now_iso

CHANNEL = "Microsoft-Windows-Sysmon/Operational"
DEFAULT_POLL_SECONDS = 5
DEFAULT_MAX_EVENTS = 500
DEFAULT_TAIL_SIZE = 200
CHECKPOINT_PATH = "state/sysmon_checkpoint.json"
BASE_OUTPUT_DIR = "out/raw/endpoint/windows_sysmon"


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


class SysmonConnector:
    def __init__(self, tail_size: int = DEFAULT_TAIL_SIZE) -> None:
        self.hostname = socket.gethostname()
        self.channel = CHANNEL
        self.tail_buffer: deque[dict] = deque(maxlen=tail_size)
        self.mode = "pywin32" if HAS_PYWIN32 else "powershell"
        self._output_paths = build_output_paths(BASE_OUTPUT_DIR, self.hostname)
        self._dedupe_cache_path: Path | None = None
        self._dedupe_cache: DedupeCache | None = None

    def read_new_events(self, last_record_id: int, max_events: int) -> list[dict]:
        if HAS_PYWIN32:
            return self._read_new_events_pywin32(last_record_id, max_events)
        return self._read_new_events_powershell(last_record_id, max_events)

    def _read_new_events_pywin32(self, last_record_id: int, max_events: int) -> list[dict]:
        query = f"*[System[(EventRecordID>{last_record_id})]]"
        flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection
        handle = win32evtlog.EvtQuery(self.channel, flags, query)
        events: list[dict] = []
        while len(events) < max_events:
            batch = win32evtlog.EvtNext(handle, min(64, max_events - len(events)))
            if not batch:
                break
            for event in batch:
                xml = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                parsed = parse_event_xml(xml, self.hostname)
                if parsed:
                    events.append(parsed)
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
            raise RuntimeError(result.stderr.strip() or "PowerShell error")
        events: list[dict] = []
        for xml in result.stdout.splitlines():
            xml = xml.strip()
            if not xml:
                continue
            parsed = parse_event_xml(xml, self.hostname)
            if parsed:
                events.append(parsed)
        return events

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
                        written, last_event_time_utc = self._write_events(
                            events, checkpoint
                        )
                        status_state.update(
                            last_record_id=checkpoint.last_record_id,
                            events_written_total=status_state.events_written_total + written,
                            last_batch_count=written,
                            last_event_time_utc=last_event_time_utc,
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

    def _write_events(self, events: list[dict], checkpoint: Checkpoint) -> tuple[int, str]:
        output_path = self._output_paths.daily_events_path()
        cache = self._ensure_dedupe_cache(output_path)
        deduped_events = self._apply_dedupe(events, cache)
        written = append_ndjson(output_path, deduped_events)
        self._persist_dedupe_cache(cache)
        for event in deduped_events:
            self.tail_buffer.append(event)
        checkpoint.last_record_id = max(event["ids"]["record_id"] for event in events)
        save_checkpoint(CHECKPOINT_PATH, checkpoint)
        return written, events[-1]["event"]["time"]["created_utc"]

    def _ensure_dedupe_cache(self, output_path: Path) -> DedupeCache:
        dedupe_path = output_path.with_suffix(".dedupe.json")
        if self._dedupe_cache_path != dedupe_path:
            self._dedupe_cache_path = dedupe_path
            self._dedupe_cache = load_dedupe_cache(dedupe_path, warn=log)
        if self._dedupe_cache is None:
            self._dedupe_cache = DedupeCache.empty(10_000)
        return self._dedupe_cache

    def _persist_dedupe_cache(self, cache: DedupeCache) -> None:
        if not self._dedupe_cache_path:
            return
        try:
            save_dedupe_cache(self._dedupe_cache_path, cache)
        except OSError as exc:
            log(f"Failed to save dedupe cache {self._dedupe_cache_path}: {exc}")

    def _apply_dedupe(self, events: list[dict], cache: DedupeCache) -> list[dict]:
        deduped: list[dict] = []
        for event in events:
            dedupe_hash = event.get("ids", {}).get("dedupe_hash")
            if not dedupe_hash:
                deduped.append(event)
                continue
            if dedupe_hash in cache:
                continue
            cache.add(dedupe_hash)
            deduped.append(event)
        return deduped


def parse_event_xml(xml: str, hostname: str) -> dict[str, Any] | None:
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
    record_id_text = system.findtext("e:EventRecordID", namespaces=ns) if ns else system.findtext("EventRecordID")
    if not record_id_text:
        return None
    record_id = int(record_id_text)
    time_created = None
    time_node = system.find("e:TimeCreated", ns) if ns else system.find("TimeCreated")
    if time_node is not None:
        time_created = to_utc_iso(time_node.attrib.get("SystemTime"))
    if not time_created:
        return None
    event_id_text = system.findtext("e:EventID", namespaces=ns) if ns else system.findtext("EventID")
    if not event_id_text:
        return None
    event_id = int(event_id_text)
    level_text = system.findtext("e:Level", namespaces=ns) if ns else system.findtext("Level")
    level = int(level_text) if level_text else None
    severity = map_severity(level)
    timezone_name = local_timezone_name()
    dedupe_hash = build_dedupe_hash(hostname, record_id, event_id, time_created)
    return {
        "envelope_version": "1.0",
        "source": {
            "type": "sysmon",
            "vendor": "microsoft",
            "product": "sysmon",
            "channel": CHANNEL,
            "collector": {
                "name": "sysmon-connector",
                "instance_id": f"{hostname}:sysmon",
                "host": hostname,
            },
        },
        "event": {
            "time": {
                "observed_utc": utc_now_iso(),
                "created_utc": time_created,
            }
        },
        "ids": {
            "record_id": record_id,
            "event_id": event_id,
            "activity_id": None,
            "correlation_id": None,
            "dedupe_hash": dedupe_hash,
        },
        "host": {
            "hostname": hostname,
            "os": "windows",
            "timezone": timezone_name,
        },
        "severity": severity,
        "tags": ["live", "sysmon"],
        "raw": {
            "format": "xml",
            "data": xml,
            "rendered_message": None,
            "xml": xml,
        },
    }


def map_severity(level: int | None) -> str:
    if level == 4:
        return "information"
    if level == 3:
        return "warning"
    if level == 2:
        return "error"
    if level == 1:
        return "critical"
    return "unknown"


def local_timezone_name() -> str:
    offset = datetime.now().astimezone().strftime("%z") or "+0000"
    return f"UTC{offset}"


def build_dedupe_hash(
    hostname: str, record_id: int, event_id: int, created_utc: str
) -> str:
    payload = f"{hostname}|{CHANNEL}|{record_id}|{event_id}|{created_utc}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def log(message: str) -> None:
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    print(f"[{timestamp}] {message}", flush=True)


def parse_args(argv: list[str]) -> ConnectorConfig:
    parser = argparse.ArgumentParser(description="Sysmon connector")
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
    connector = SysmonConnector()
    connector.run_forever(
        poll_seconds=config.poll_seconds,
        max_events=config.max_events,
        http_port=config.http_port,
    )


if __name__ == "__main__":
    main()
