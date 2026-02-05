import json
import os
from dataclasses import dataclass
from typing import Any, Iterable, Iterator, Optional


@dataclass
class FileArtifactNormalized:
    timestamp: Optional[str]
    file_path: Optional[str]
    file_name: Optional[str]
    sha256: Optional[str]
    sha1: Optional[str]
    md5: Optional[str]
    file_size: Optional[int]
    source: Optional[str]
    device_hostname: Optional[str]
    user_name: Optional[str]
    user_domain: Optional[str]
    process_pid: Optional[int]
    process_executable: Optional[str]
    original_event: dict[str, Any]


def _normalize_keys(record: dict[str, Any]) -> dict[str, Any]:
    return {str(key).lower(): value for key, value in record.items()}


def _as_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    return str(value)


def _as_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except Exception:
        return None


def _extract_fields(record: dict[str, Any]) -> FileArtifactNormalized:
    normalized = _normalize_keys(record)

    timestamp = _as_str(
        normalized.get("timestamp")
        or normalized.get("time")
        or normalized.get("ts")
        or normalized.get("event_time")
    )
    file_path = _as_str(normalized.get("file_path") or normalized.get("path"))
    file_name = _as_str(normalized.get("file_name") or normalized.get("name"))
    if not file_name and file_path:
        file_name = os.path.basename(file_path)

    sha256 = _as_str(normalized.get("sha256"))
    sha1 = _as_str(normalized.get("sha1"))
    md5 = _as_str(normalized.get("md5"))

    file_size = _as_int(normalized.get("file_size") or normalized.get("size"))
    source = _as_str(
        normalized.get("source")
        or normalized.get("tool")
        or normalized.get("product")
    )
    device_hostname = _as_str(
        normalized.get("hostname") or normalized.get("device_hostname")
    )
    user_name = _as_str(normalized.get("username") or normalized.get("user_name"))
    user_domain = _as_str(normalized.get("user_domain") or normalized.get("domain"))
    process_pid = _as_int(normalized.get("process_pid"))
    process_executable = _as_str(
        normalized.get("process_executable") or normalized.get("process_image")
    )

    return FileArtifactNormalized(
        timestamp=timestamp,
        file_path=file_path,
        file_name=file_name,
        sha256=sha256,
        sha1=sha1,
        md5=md5,
        file_size=file_size,
        source=source,
        device_hostname=device_hostname,
        user_name=user_name,
        user_domain=user_domain,
        process_pid=process_pid,
        process_executable=process_executable,
        original_event=dict(record),
    )


def normalize_file_artifact_record(record: dict[str, Any]) -> FileArtifactNormalized:
    return _extract_fields(record)


def iter_file_artifact_events_from_records(
    records: Iterable[dict[str, Any]],
) -> Iterator[FileArtifactNormalized]:
    for record in records:
        if isinstance(record, dict):
            yield _extract_fields(record)


def iter_file_artifact_events(file_path: str) -> Iterator[FileArtifactNormalized]:
    """
    Supports JSON array, JSON object, or JSONL.
    """
    with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as handle:
        first = handle.readline().strip()

    if not first:
        return

    if first.startswith("["):
        with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as handle:
            data = json.load(handle)
        yield from iter_file_artifact_events_from_records(data)
        return

    if first.startswith("{"):
        try:
            with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as handle:
                data = json.load(handle)
            if isinstance(data, dict):
                if "records" in data and isinstance(data["records"], list):
                    yield from iter_file_artifact_events_from_records(data["records"])
                    return
                if "events" in data and isinstance(data["events"], list):
                    yield from iter_file_artifact_events_from_records(data["events"])
                    return
                yield normalize_file_artifact_record(data)
                return
            if isinstance(data, list):
                yield from iter_file_artifact_events_from_records(data)
                return
        except Exception:
            pass

    with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as handle:
        for line in handle:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                record = json.loads(line)
            except Exception:
                continue
            if isinstance(record, dict):
                yield _extract_fields(record)
