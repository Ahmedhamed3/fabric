import json
from pathlib import Path

from app.conversion import convert_events_to_ocsf_jsonl
from app.formats.reader import iter_events_from_upload


def _load_sysmon_events(sample_path: str) -> list[dict]:
    raw_events = list(iter_events_from_upload(Path(sample_path).read_bytes()))
    return [json.loads(line) for line in convert_events_to_ocsf_jsonl(raw_events)]


def test_sysmon_flags_for_event_ids_7_8_10_12_13_14():
    events = _load_sysmon_events("samples/sysmon_7_8_10_12_13_14.ndjson")
    by_event_id = {
        event["unmapped"]["original_event"]["EventID"]: event for event in events
    }

    event7 = by_event_id[7]
    assert event7["context_flags"]["has_file"] is True
    assert event7["evidence_flags"]["module_load"] is True
    assert event7["evidence_flags"]["process_execution"] is False

    event8 = by_event_id[8]
    assert event8["context_flags"]["has_process"] is True
    assert event8["evidence_flags"]["process_injection"] is True
    assert event8["evidence_flags"]["process_execution"] is False

    event10 = by_event_id[10]
    assert event10["context_flags"]["has_process"] is True
    assert event10["evidence_flags"]["process_access"] is True
    assert event10["evidence_flags"]["process_execution"] is False

    event12 = by_event_id[12]
    assert event12["evidence_flags"]["registry_key"] is True

    event13 = by_event_id[13]
    assert event13["evidence_flags"]["registry_value"] is True

    event14 = by_event_id[14]
    assert event14["evidence_flags"]["registry_value"] is True

    for event in events:
        assert event["context_flags"]["has_device"] is True
        assert event["unmapped"]["original_event"]
