import json
import tempfile

from app.ocsf.constants import calc_type_uid
from app.plugins.zeek.map_to_ocsf import map_zeek_dns_to_ocsf
from app.plugins.zeek.parse import ZeekDNSNormalized
from app.plugins.zeek.pipeline import convert_zeek_dns_file_to_ocsf_jsonl


def test_map_zeek_dns_to_ocsf_fields():
    original_event = {
        "ts": 1704067200.0,
        "uid": "C1",
        "id.orig_h": "10.0.0.5",
        "id.resp_h": "8.8.8.8",
        "proto": "udp",
        "query": "example.com",
        "answers": ["93.184.216.34"],
        "rcode": 0,
        "rcode_name": "NOERROR",
    }
    ev = ZeekDNSNormalized(
        ts=original_event["ts"],
        uid=original_event["uid"],
        id_orig_h=original_event["id.orig_h"],
        id_resp_h=original_event["id.resp_h"],
        proto=original_event["proto"],
        query=original_event["query"],
        answers=original_event["answers"],
        rcode=original_event["rcode"],
        rcode_name=original_event["rcode_name"],
        original_event=original_event,
    )

    out = map_zeek_dns_to_ocsf(ev)

    assert out["class_uid"] == 1006
    assert out["activity_id"] == 1
    assert out["type_uid"] == calc_type_uid(1006, 1)
    assert out["dns"]["question"]["name"] == "example.com"
    assert out["dns"]["answers"] == [{"data": "93.184.216.34"}]
    assert out["src_endpoint"]["ip"] == "10.0.0.5"
    assert out["dst_endpoint"]["ip"] == "8.8.8.8"


def test_convert_zeek_dns_multiple_lines_to_ndjson():
    lines = [
        {
            "ts": 1704067200.0,
            "uid": "C1",
            "id.orig_h": "10.0.0.5",
            "id.resp_h": "8.8.8.8",
            "proto": "udp",
            "query": "example.com",
            "answers": ["93.184.216.34"],
            "rcode": 0,
            "rcode_name": "NOERROR",
        },
        {
            "ts": 1704067201.0,
            "uid": "C2",
            "id.orig_h": "10.0.0.6",
            "id.resp_h": "1.1.1.1",
            "proto": "udp",
            "query": "example.org",
            "answers": ["93.184.216.35"],
            "rcode": 0,
            "rcode_name": "NOERROR",
        },
    ]

    with tempfile.NamedTemporaryFile(mode="w+", suffix=".log", delete=False) as tmp:
        for line in lines:
            tmp.write(json.dumps(line))
            tmp.write("\n")
        tmp.flush()
        tmp_path = tmp.name

    output_lines = list(convert_zeek_dns_file_to_ocsf_jsonl(tmp_path))
    assert len(output_lines) == 2

    parsed = [json.loads(line) for line in output_lines]
    assert parsed[0]["dns"]["question"]["name"] == "example.com"
    assert parsed[1]["dns"]["question"]["name"] == "example.org"
