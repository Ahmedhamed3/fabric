import json
from pathlib import Path

from app.utils.ndjson_writer import append_ndjson


def test_append_ndjson(tmp_path: Path) -> None:
    path = tmp_path / "events.ndjson"
    records = [
        {"record_id": 1, "message": "a"},
        {"record_id": 2, "message": "b"},
    ]
    count = append_ndjson(path, records)
    assert count == 2
    lines = path.read_text().splitlines()
    assert [json.loads(line) for line in lines] == records
