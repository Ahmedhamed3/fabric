import json
from pathlib import Path

from app.conversion import convert_events_to_ocsf_jsonl


def _has_ip_match(event: dict, ip_address: str) -> bool:
    network = event.get("network", {})
    if isinstance(network, dict):
        dst = network.get("dst_endpoint", {})
        if isinstance(dst, dict) and dst.get("ip") == ip_address:
            return True

    dns = event.get("dns", {})
    if isinstance(dns, dict):
        answers = dns.get("answers", [])
        if isinstance(answers, list):
            for answer in answers:
                if isinstance(answer, dict) and answer.get("data") == ip_address:
                    return True
                if answer == ip_address:
                    return True

    unmapped = event.get("unmapped", {})
    if isinstance(unmapped, dict):
        original = unmapped.get("original_event")
        if isinstance(original, dict) and original.get("id.resp_h") == ip_address:
            return True

    return False


def test_mixed_source_conversion_per_event():
    sample_path = Path("samples/mixed_sources.ndjson")
    events = [
        json.loads(line)
        for line in sample_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    lines = list(convert_events_to_ocsf_jsonl(events))

    assert len(lines) == len(events)

    outputs = [json.loads(line) for line in lines]

    assert any(_has_ip_match(event, "93.184.216.34") for event in outputs)
    assert any(event.get("class_uid") == 7 for event in outputs)
    assert any(event.get("class_uid") == 4002 for event in outputs)
    assert any(event.get("class_uid") == 1006 for event in outputs)
