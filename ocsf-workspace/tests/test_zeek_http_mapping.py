import json
from pathlib import Path

from app.detect import auto_detect_source
from app.ocsf.constants import HTTP_ACTIVITY_CLASS_UID, HTTP_ACTIVITY_REQUEST_ID, calc_type_uid
from app.plugins.zeek_http.map_to_ocsf import map_zeek_http_to_ocsf
from app.plugins.zeek_http.parse import ZeekHttpNormalized
from app.plugins.zeek_http.pipeline import convert_zeek_http_events_to_ocsf_jsonl


def _load_ndjson(sample_path: Path) -> list[dict]:
    events = []
    for line in sample_path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line:
            continue
        events.append(json.loads(line))
    return events


def test_detect_zeek_http_samples():
    sample_path = Path("samples") / "zeek_http.ndjson"
    events = _load_ndjson(sample_path)
    detection = auto_detect_source(events[:10])

    assert detection["source_type"] == "zeek_http"
    assert detection["confidence"] >= 0.6


def test_map_zeek_http_to_ocsf_fields():
    original_event = {
        "ts": 1675000000.123,
        "id.orig_h": "192.168.1.10",
        "id.resp_h": "93.184.216.34",
        "method": "GET",
        "host": "example.com",
        "uri": "/malware.exe",
        "status_code": 200,
        "user_agent": "Mozilla/5.0",
        "request_body_len": 0,
        "response_body_len": 123456,
    }
    ev = ZeekHttpNormalized(
        ts=original_event["ts"],
        method=original_event["method"],
        host=original_event["host"],
        uri=original_event["uri"],
        status_code=original_event["status_code"],
        user_agent=original_event["user_agent"],
        request_body_len=original_event["request_body_len"],
        response_body_len=original_event["response_body_len"],
        id_orig_h=original_event["id.orig_h"],
        id_resp_h=original_event["id.resp_h"],
        id_orig_p=None,
        id_resp_p=None,
        original_event=original_event,
    )

    out = map_zeek_http_to_ocsf(ev)

    assert out["class_uid"] == HTTP_ACTIVITY_CLASS_UID
    assert out["activity_id"] == HTTP_ACTIVITY_REQUEST_ID
    assert out["type_uid"] == calc_type_uid(HTTP_ACTIVITY_CLASS_UID, HTTP_ACTIVITY_REQUEST_ID)
    assert out["http"]["method"] == "GET"
    assert out["http"]["url"] == "http://example.com/malware.exe"
    assert out["http"]["status_code"] == 200
    assert out["http"]["user_agent"] == "Mozilla/5.0"
    assert out["http"]["bytes_out"] == 0
    assert out["http"]["bytes_in"] == 123456
    assert out["network"]["src_endpoint"]["ip"] == "192.168.1.10"
    assert out["network"]["dst_endpoint"]["ip"] == "93.184.216.34"
    assert out["unmapped"]["original_event"] == original_event


def test_convert_zeek_http_missing_optional_fields():
    events = [
        {
            "ts": 1675000000.123,
            "id.orig_h": "192.168.1.10",
            "id.resp_h": "93.184.216.34",
            "method": "GET",
            "host": "example.com",
            "uri": "/",
        }
    ]

    lines = list(convert_zeek_http_events_to_ocsf_jsonl(events))
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert parsed["http"]["method"] == "GET"
    assert parsed["http"]["url"] == "http://example.com/"
    assert parsed["unmapped"]["original_event"] == events[0]
