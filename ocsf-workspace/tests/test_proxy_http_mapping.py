import json
from pathlib import Path

from app.detect import auto_detect_source
from app.ocsf.constants import HTTP_ACTIVITY_CLASS_UID, HTTP_ACTIVITY_REQUEST_ID, calc_type_uid
from app.plugins.proxy_http.map_to_ocsf import map_proxy_http_to_ocsf
from app.plugins.proxy_http.parse import ProxyHttpNormalized
from app.plugins.proxy_http.pipeline import convert_proxy_http_events_to_ocsf_jsonl


def _load_ndjson(sample_path: Path) -> list[dict]:
    events = []
    for line in sample_path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line:
            continue
        events.append(json.loads(line))
    return events


def test_detect_proxy_http_samples():
    sample_path = Path("samples") / "proxy_http.ndjson"
    events = _load_ndjson(sample_path)
    detection = auto_detect_source(events[:10])

    assert detection["source_type"] == "proxy_http"
    assert detection["confidence"] >= 0.6


def test_map_proxy_http_to_ocsf_fields():
    original_event = {
        "time": "2025-01-26T20:35:10Z",
        "client_ip": "192.168.1.20",
        "method": "POST",
        "url": "https://evil.com/upload",
        "status": 302,
        "bytes_out": 1024,
        "bytes_in": 20480,
        "user_agent": "curl/7.81.0",
    }
    ev = ProxyHttpNormalized(
        time=original_event["time"],
        client_ip=original_event["client_ip"],
        dst_ip=None,
        dst_host=None,
        method=original_event["method"],
        url=original_event["url"],
        status=original_event["status"],
        bytes_in=original_event["bytes_in"],
        bytes_out=original_event["bytes_out"],
        user_agent=original_event["user_agent"],
        original_event=original_event,
    )

    out = map_proxy_http_to_ocsf(ev)

    assert out["class_uid"] == HTTP_ACTIVITY_CLASS_UID
    assert out["activity_id"] == HTTP_ACTIVITY_REQUEST_ID
    assert out["type_uid"] == calc_type_uid(HTTP_ACTIVITY_CLASS_UID, HTTP_ACTIVITY_REQUEST_ID)
    assert out["http"]["method"] == "POST"
    assert out["http"]["url"] == "https://evil.com/upload"
    assert out["http"]["status_code"] == 302
    assert out["http"]["user_agent"] == "curl/7.81.0"
    assert out["http"]["bytes_out"] == 1024
    assert out["http"]["bytes_in"] == 20480
    assert out["network"]["src_endpoint"]["ip"] == "192.168.1.20"
    assert out["unmapped"]["original_event"] == original_event


def test_convert_proxy_http_missing_optional_fields():
    events = [
        {
            "time": "2025-01-26T20:36:10Z",
            "client_ip": "192.168.1.21",
            "method": "GET",
            "url": "http://updates.example.net/agent.msi",
        }
    ]

    lines = list(convert_proxy_http_events_to_ocsf_jsonl(events))
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert parsed["http"]["method"] == "GET"
    assert parsed["http"]["url"] == "http://updates.example.net/agent.msi"
    assert parsed["unmapped"]["original_event"] == events[0]
