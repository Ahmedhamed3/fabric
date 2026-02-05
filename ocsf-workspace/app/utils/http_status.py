from __future__ import annotations

import json
import threading
from collections import deque
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Deque, Iterable
from urllib.parse import parse_qs, urlparse

from .timeutil import utc_now_iso


@dataclass
class StatusState:
    hostname: str
    channel: str
    mode: str
    last_record_id: int = 0
    events_written_total: int = 0
    last_batch_count: int = 0
    last_event_time_utc: str | None = None
    last_error: str | None = None
    updated_at_utc: str = field(default_factory=utc_now_iso)

    def as_health(self) -> dict:
        return {
            "ok": True,
            "hostname": self.hostname,
            "channel": self.channel,
            "mode": self.mode,
        }

    def as_status(self) -> dict:
        return {
            "last_record_id": self.last_record_id,
            "events_written_total": self.events_written_total,
            "last_batch_count": self.last_batch_count,
            "last_event_time_utc": self.last_event_time_utc,
            "last_error": self.last_error,
            "updated_at_utc": self.updated_at_utc,
        }

    def update(self, **kwargs: object) -> None:
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        self.updated_at_utc = utc_now_iso()


TailReader = Callable[[int], Iterable[dict]]


def tail_ndjson(path: str | Path, limit: int) -> list[dict]:
    path = Path(path)
    if not path.exists():
        return []
    lines: Deque[str] = deque(maxlen=limit)
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            lines.append(line)
    records: list[dict] = []
    for line in lines:
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


class HttpStatusServer:
    def __init__(
        self,
        host: str,
        port: int,
        status_state: StatusState,
        tail_buffer: Deque[dict],
        tail_reader: TailReader | None = None,
    ) -> None:
        self._host = host
        self._port = port
        self._status_state = status_state
        self._tail_buffer = tail_buffer
        self._tail_reader = tail_reader
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        handler = self._build_handler()
        self._server = ThreadingHTTPServer((self._host, self._port), handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        if self._thread:
            self._thread.join(timeout=2)

    def _build_handler(self) -> type[BaseHTTPRequestHandler]:
        status_state = self._status_state
        tail_buffer = self._tail_buffer
        tail_reader = self._tail_reader

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - external interface
                parsed = urlparse(self.path)
                if parsed.path == "/health":
                    self._send_json(status_state.as_health())
                    return
                if parsed.path == "/status":
                    self._send_json(status_state.as_status())
                    return
                if parsed.path == "/tail":
                    params = parse_qs(parsed.query)
                    limit = params.get("limit", ["20"])[0]
                    try:
                        limit_value = max(1, min(1000, int(limit)))
                    except ValueError:
                        limit_value = 20
                    data = list(tail_buffer)[-limit_value:]
                    if not data and tail_reader:
                        data = list(tail_reader(limit_value))
                    self._send_json(data)
                    return
                self.send_response(HTTPStatus.NOT_FOUND)
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                return

            def _send_json(self, payload: object) -> None:
                body = json.dumps(payload).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        return Handler
