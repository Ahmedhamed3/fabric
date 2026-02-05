from pathlib import Path

import pytest

from app.detect import auto_detect_source
import json


def _load_events(sample_path: Path) -> list[dict]:
    text = sample_path.read_text(encoding="utf-8-sig")
    stripped = text.lstrip()
    if not stripped:
        return []
    if stripped.startswith("[") or stripped.startswith("{"):
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            payload = None
        if payload is not None:
            if isinstance(payload, list):
                return payload
            if isinstance(payload, dict):
                for key in ("Events", "events", "records"):
                    value = payload.get(key)
                    if isinstance(value, list):
                        return value
                return [payload]
            return []
    events = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        events.append(json.loads(line))
    return events


SAMPLES = [
    ("azure_ad_signin", "azure_ad_signin_success.ndjson"),
    ("azure_ad_signin", "azure_ad_signin.single.json"),
    ("sysmon", "sysmon.ndjson"),
    ("sysmon", "sysmon.json"),
    ("suricata", "suricata.ndjson"),
    ("suricata", "suricata.json"),
    ("zeek", "zeek_dns.ndjson"),
    ("zeek", "zeek_dns.json"),
    ("zeek_http", "zeek_http.ndjson"),
    ("windows-security", "windows_security.ndjson"),
    ("windows-security", "windows_security.json"),
    ("windows-security", "windows_security_4663.ndjson"),
    ("windows-security", "windows_security_4663.json"),
    ("file-artifact", "file_artifact.ndjson"),
    ("file-artifact", "file_artifact.json"),
    ("proxy_http", "proxy_http.ndjson"),
]


@pytest.mark.parametrize("expected_source, sample_name", SAMPLES)
def test_auto_detect_source(expected_source: str, sample_name: str):
    sample_path = Path("samples") / sample_name
    events = _load_events(sample_path)
    detection = auto_detect_source(events[:10])

    assert detection["source_type"] == expected_source
    assert detection["confidence"] >= 0.6
