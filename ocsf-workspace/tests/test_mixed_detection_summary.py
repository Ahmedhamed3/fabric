from pathlib import Path

from app.detect import summarize_event_detection
import json


def _load_ndjson(sample_path: Path) -> list[dict]:
    text = sample_path.read_text(encoding="utf-8-sig")
    events = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        events.append(json.loads(line))
    return events


def test_mixed_source_detection_summary():
    sample_path = Path("samples/mixed_sources.ndjson")
    events = _load_ndjson(sample_path)
    detection = summarize_event_detection(events)

    assert detection["source_type"] == "mixed"
    breakdown = detection["breakdown"]
    assert len(breakdown) > 1
    total = sum(item["count"] for item in breakdown)
    assert total == len(events)
    top_ratio = max(item["ratio"] for item in breakdown)
    assert top_ratio < 0.85
