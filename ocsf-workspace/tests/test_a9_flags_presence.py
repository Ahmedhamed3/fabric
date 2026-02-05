import json
from pathlib import Path

from app.conversion import convert_events_with_source_to_ocsf_jsonl
from app.formats.reader import iter_events_from_upload


def _load_first_event(sample_path: str, source_type: str) -> dict:
    events = list(iter_events_from_upload(Path(sample_path).read_bytes()))
    line = next(convert_events_with_source_to_ocsf_jsonl(events, source_type=source_type))
    return json.loads(line)


def test_a9_sysmon_process_flags():
    event = _load_first_event("samples/sysmon_eventid1.json", "sysmon")
    assert event["evidence_flags"]["process_execution"] is True
    assert event["context_flags"]["has_process"] is True
    assert event["context_flags"]["has_user"] is True


def test_a9_zeek_dns_flags():
    event = _load_first_event("samples/zeek_dns.ndjson", "zeek")
    assert event["evidence_flags"]["dns"] is True
    assert event["context_flags"]["has_ip"] is True


def test_a9_zeek_http_flags():
    event = _load_first_event("samples/zeek_http.ndjson", "zeek_http")
    assert event["evidence_flags"]["http"] is True
    assert event["context_flags"]["has_ip"] is True


def test_a9_azure_ad_signin_flags():
    event = _load_first_event("samples/azure_ad_signin_success.ndjson", "azure_ad_signin")
    assert event["evidence_flags"]["identity"] is True
    assert event["context_flags"]["has_user"] is True
    assert event["context_flags"]["has_ip"] is True


def test_a9_suricata_flags():
    event = _load_first_event("samples/suricata.ndjson", "suricata")
    assert event["evidence_flags"]["alert"] is True
    assert event["context_flags"]["has_ip"] is True
