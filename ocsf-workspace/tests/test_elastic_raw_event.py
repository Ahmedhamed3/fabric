from __future__ import annotations

import json

from app.utils.raw_envelope import build_elastic_raw_event


def test_elastic_raw_event_envelope_minimal() -> None:
    hit = {
        "_index": "logs-test-default",
        "_id": "abc123",
        "_source": {
            "@timestamp": "2024-04-01T12:34:56.789Z",
            "message": "Hello elastic",
            "event": {"id": "evt-1", "code": "A1", "severity": 7},
            "log": {"level": "error"},
            "host": {"name": "host-a", "os": {"name": "Linux"}},
        },
        "fields": {"@timestamp": ["2024-04-01T12:34:56.789Z"]},
        "sort": [1711974896],
    }
    now_utc = "2024-04-01T12:35:00Z"
    envelope = build_elastic_raw_event(
        hit,
        now_utc=now_utc,
        hostname="collector-host",
        timezone_name="UTC+0000",
    )

    assert envelope["envelope_version"] == "1.0"
    assert envelope["source"]["type"] == "elastic"
    assert envelope["raw"]["format"] == "json"
    assert envelope["raw"]["data"]["_index"] == hit["_index"]
    assert envelope["raw"]["data"]["_id"] == hit["_id"]
    assert envelope["raw"]["data"]["_source"] == hit["_source"]
    assert envelope["event"]["time"]["observed_utc"] == hit["_source"]["@timestamp"]
    json.dumps(envelope)

    envelope_repeat = build_elastic_raw_event(
        hit,
        now_utc=now_utc,
        hostname="collector-host",
        timezone_name="UTC+0000",
    )
    assert envelope["ids"]["dedupe_hash"] == envelope_repeat["ids"]["dedupe_hash"]


def test_elastic_raw_event_observed_fallback() -> None:
    hit = {
        "_index": "logs-test-default",
        "_id": "def456",
        "_source": {
            "message": "No timestamp",
            "event": {"severity": 2},
        },
    }
    now_utc = "2024-05-01T00:00:00Z"
    envelope = build_elastic_raw_event(
        hit,
        now_utc=now_utc,
        hostname="collector-host",
        timezone_name="UTC+0000",
    )

    assert envelope["event"]["time"]["observed_utc"] == now_utc
