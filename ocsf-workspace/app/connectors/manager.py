from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Deque, Iterable

from app.utils.timeutil import utc_now_iso


@dataclass(frozen=True)
class ConnectorSpec:
    name: str
    module: str
    port: int


CONNECTOR_REGISTRY: list[ConnectorSpec] = [
    ConnectorSpec(name="sysmon", module="app.connectors.sysmon", port=8787),
    ConnectorSpec(name="security", module="app.connectors.security", port=8788),
    ConnectorSpec(name="elastic", module="app.connectors.elastic", port=8789),
]

CONNECTOR_DEFAULT_ARGS: list[str] = ["--poll-seconds", "5", "--max-events", "500"]


class ConnectorManager:
    def __init__(
        self,
        registry: Iterable[ConnectorSpec] | None = None,
        default_args: Iterable[str] | None = None,
    ) -> None:
        self._registry = list(registry or CONNECTOR_REGISTRY)
        self._default_args = list(default_args or CONNECTOR_DEFAULT_ARGS)
        self._started: dict[str, subprocess.Popen[str]] = {}
        self._last_health_check: dict[str, str] = {}
        self._last_health_ok: dict[str, bool] = {}
        self._last_start_time: dict[str, str] = {}
        self._last_exit_code: dict[str, int | None] = {}
        self._last_error: dict[str, str | None] = {}
        self._logs: dict[str, Deque[str]] = {}
        self._stderr_lines: dict[str, Deque[str]] = {}
        self._repo_root = Path.cwd()
        self._lock = threading.Lock()

    def startup(self) -> None:
        for spec in self._registry:
            if self._check_health(spec):
                continue
            self._start_connector(spec)

    def shutdown(self) -> None:
        for name, proc in list(self._started.items()):
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        self._started.clear()

    def status(self) -> list[dict[str, object]]:
        statuses: list[dict[str, object]] = []
        for spec in self._registry:
            is_healthy = self._check_health(spec)
            proc = self._started.get(spec.name)
            is_running = proc is not None and proc.poll() is None
            pid = proc.pid if is_running else None
            statuses.append(
                {
                    "name": spec.name,
                    "port": spec.port,
                    "running": is_running,
                    "pid": pid,
                    "last_health_ok": self._last_health_ok.get(spec.name, is_healthy),
                    "last_health_time_utc": self._last_health_check.get(spec.name),
                    "last_health_check_utc": self._last_health_check.get(spec.name),
                    "last_start_time_utc": self._last_start_time.get(spec.name),
                    "last_exit_code": self._last_exit_code.get(spec.name),
                    "last_error": self._last_error.get(spec.name),
                }
            )
        return statuses

    def logs(self, name: str, limit: int = 100) -> list[str]:
        safe_limit = max(1, min(limit, 200))
        buffer = self._logs.get(name)
        if not buffer:
            return []
        return list(buffer)[-safe_limit:]

    def connector_names(self) -> list[str]:
        return [spec.name for spec in self._registry]

    def _check_health(self, spec: ConnectorSpec) -> bool:
        url = f"http://127.0.0.1:{spec.port}/health"
        health_time = utc_now_iso()
        self._last_health_check[spec.name] = health_time
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                is_healthy = 200 <= response.status < 300
                self._last_health_ok[spec.name] = is_healthy
                return is_healthy
        except (urllib.error.URLError, TimeoutError):
            self._last_health_ok[spec.name] = False
            return False

    def _start_connector(self, spec: ConnectorSpec) -> None:
        process: subprocess.Popen[str] | None = None
        with self._lock:
            existing = self._started.get(spec.name)
            if existing and existing.poll() is None:
                return
            if existing and existing.poll() is not None:
                self._started.pop(spec.name, None)
            command = [
                sys.executable,
                "-m",
                spec.module,
                *self._default_args,
                "--http-port",
                str(spec.port),
            ]
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                cwd=self._repo_root,
                env=os.environ.copy(),
            )
            self._started[spec.name] = process
            self._last_start_time[spec.name] = utc_now_iso()
            self._last_exit_code[spec.name] = None
            self._last_error[spec.name] = None
            self._logs.setdefault(spec.name, deque(maxlen=200))
            self._stderr_lines.setdefault(spec.name, deque(maxlen=20))
            self._attach_logger(spec.name, process)
            self._attach_exit_watcher(spec.name, process)
        if process:
            self._wait_for_health(spec, process)

    def _attach_logger(self, name: str, process: subprocess.Popen[str]) -> None:
        def _log_stream(stream: Iterable[str] | None, stream_name: str) -> None:
            if stream is None:
                return
            for line in stream:
                self._record_log_line(name, line, stream_name)

        if process.stdout:
            threading.Thread(
                target=_log_stream, args=(process.stdout, "stdout"), daemon=True
            ).start()
        if process.stderr:
            threading.Thread(
                target=_log_stream, args=(process.stderr, "stderr"), daemon=True
            ).start()

    def _attach_exit_watcher(self, name: str, process: subprocess.Popen[str]) -> None:
        def _watch() -> None:
            exit_code = process.wait()
            self._record_exit(name, exit_code)

        threading.Thread(target=_watch, daemon=True).start()

    def _record_log_line(self, name: str, line: str, stream_name: str) -> None:
        cleaned = line.rstrip()
        timestamp = utc_now_iso()
        entry = f"{timestamp} [{name}] {cleaned}"
        with self._lock:
            self._logs.setdefault(name, deque(maxlen=200)).append(entry)
            if stream_name == "stderr":
                self._stderr_lines.setdefault(name, deque(maxlen=20)).append(cleaned)
                if name == "security" and self._is_access_denied(cleaned):
                    self._last_error[name] = (
                        "Security connector requires running the webapp as Administrator."
                    )
        print(entry)

    def _record_exit(self, name: str, exit_code: int) -> None:
        with self._lock:
            self._last_exit_code[name] = exit_code
            if self._last_error.get(name):
                return
            stderr_lines = list(self._stderr_lines.get(name, deque()))
            if stderr_lines:
                details = " | ".join(stderr_lines[-3:])
                self._last_error[name] = (
                    f"Connector exited with code {exit_code}. "
                    f"Last stderr: {details}"
                )
            else:
                self._last_error[name] = (
                    f"Connector exited with code {exit_code}."
                )

    def _wait_for_health(
        self, spec: ConnectorSpec, process: subprocess.Popen[str]
    ) -> None:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if process.poll() is not None:
                self._record_exit(spec.name, process.poll() or 0)
                return
            if self._check_health(spec):
                return
            time.sleep(0.5)
        with self._lock:
            if not self._last_error.get(spec.name):
                self._last_error[spec.name] = "Health check did not become ready."

    @staticmethod
    def _is_access_denied(line: str) -> bool:
        lowered = line.lower()
        return "access is denied" in lowered or "access denied" in lowered
