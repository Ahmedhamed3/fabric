from __future__ import annotations

import json

from app.utils.raw_envelope import build_security_raw_event, compute_dedupe_hash


def test_security_raw_event_envelope_minimal() -> None:
    raw_record = {
        "record_id": 2048,
        "time_created_utc": "2024-02-03T04:05:06.789Z",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "event_id": 4625,
        "level": 4,
        "computer": "HOST-A",
        "event_data": {"SubjectUserName": "alice"},
        "raw_xml": "<Event>minimal</Event>",
    }
    observed_utc = raw_record["time_created_utc"]
    envelope = build_security_raw_event(raw_record, observed_utc, "HOST-A", "UTC+0000")

    assert envelope["envelope_version"] == "1.0"
    assert envelope["source"]["type"] == "security"
    assert envelope["source"]["collector"]["name"] == "security-connector"
    assert envelope["ids"]["record_id"] == 2048
    assert envelope["ids"]["event_id"] == 4625
    assert envelope["event"]["time"]["observed_utc"] == observed_utc
    assert envelope["event"]["time"]["created_utc"] == raw_record["time_created_utc"]
    assert envelope["severity"] == "low"
    assert envelope["raw"]["data"] == raw_record
    assert envelope["raw"]["xml"] == raw_record["raw_xml"]
    json.dumps(envelope)


def test_security_raw_event_envelope_rich_and_dedupe() -> None:
    raw_record = {
        "record_id": 4096,
        "time_created_utc": "2024-03-04T10:11:12.000Z",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "event_id": 4673,
        "level": 2,
        "computer": "HOST-B",
        "event_data": {
            "SubjectUserName": "bob",
            "Service": "rpcss",
        },
        "raw_xml": "<Event>rich</Event>",
    }
    observed_utc = raw_record["time_created_utc"]
    envelope = build_security_raw_event(raw_record, observed_utc, "HOST-B", "UTC+0200")

    expected_hash = compute_dedupe_hash(
        "security",
        "HOST-B",
        4096,
        4673,
        observed_utc,
        raw_record["provider"],
        raw_record["computer"],
        raw_record["channel"],
    )
    assert envelope["ids"]["dedupe_hash"] == expected_hash
    assert (
        compute_dedupe_hash(
            "security",
            "HOST-B",
            4096,
            4673,
            observed_utc,
            raw_record["provider"],
            raw_record["computer"],
            raw_record["channel"],
        )
        == expected_hash
    )
