import json
from pathlib import Path

from app.conversion import convert_events_to_ocsf_jsonl
from app.formats.reader import iter_events_from_upload


def test_a9_input_output_invariant():
    sample_path = Path("samples/a9_mixed_with_errors.ndjson")
    events = list(iter_events_from_upload(sample_path.read_bytes()))

    lines = list(convert_events_to_ocsf_jsonl(events))
    assert len(lines) == 4

    parsed = [json.loads(line) for line in lines]
    parse_errors = [event for event in parsed if event["evidence_flags"]["parse_error"]]
    assert parse_errors
    assert parse_errors[0]["unmapped"]["original_line"] == "{\"bad_json\": true,"

    unknowns = [event for event in parsed if event["evidence_flags"]["unknown"]]
    assert unknowns
    assert unknowns[0]["unmapped"]["original_event"] == {
        "foo": "bar",
        "timestamp": "2024-01-01T00:00:00Z",
    }

    for event in parsed:
        assert event["time"].endswith("Z")
