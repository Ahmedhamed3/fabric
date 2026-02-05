import json
import tempfile

from app.ocsf.constants import (
    SECURITY_FINDING_ACTIVITY_ALERT_ID,
    SECURITY_FINDING_CLASS_UID,
    calc_type_uid,
)
from app.plugins.suricata.pipeline import convert_suricata_file_to_ocsf_jsonl


def test_convert_suricata_alerts_to_ocsf_ndjson():
    lines = [
        {
            "timestamp": "2024-02-01T12:34:56.789012+0000",
            "event_type": "alert",
            "src_ip": "192.168.1.10",
            "src_port": 12345,
            "dest_ip": "10.0.0.5",
            "dest_port": 80,
            "proto": "tcp",
            "flow_id": 1234567890,
            "alert": {
                "signature": "ET POLICY Example Alert",
                "category": "Attempted Information Leak",
                "severity": 2,
            },
        },
        {
            "timestamp": "2024-02-01T12:35:00.000000+0000",
            "event_type": "alert",
            "src_ip": "192.168.1.11",
            "src_port": 44321,
            "dest_ip": "10.0.0.8",
            "dest_port": 443,
            "proto": "tcp",
            "alert": {
                "signature": "ET SCAN Suspicious Scan",
                "category": "Attempted Recon",
                "severity": 1,
            },
        },
    ]

    with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as tmp:
        for line in lines:
            tmp.write(json.dumps(line))
            tmp.write("\n")
        tmp.flush()
        tmp_path = tmp.name

    output_lines = list(convert_suricata_file_to_ocsf_jsonl(tmp_path))
    assert len(output_lines) == 2

    parsed = [json.loads(line) for line in output_lines]

    expected_type_uid = calc_type_uid(
        SECURITY_FINDING_CLASS_UID, SECURITY_FINDING_ACTIVITY_ALERT_ID
    )
    assert parsed[0]["class_uid"] == SECURITY_FINDING_CLASS_UID
    assert parsed[0]["activity_id"] == SECURITY_FINDING_ACTIVITY_ALERT_ID
    assert parsed[0]["type_uid"] == expected_type_uid
    assert parsed[0]["finding"]["title"] == "ET POLICY Example Alert"
    assert parsed[0]["src_endpoint"]["ip"] == "192.168.1.10"
    assert parsed[0]["src_endpoint"]["port"] == 12345
    assert parsed[0]["dst_endpoint"]["ip"] == "10.0.0.5"
    assert parsed[0]["dst_endpoint"]["port"] == 80
    assert "original_event" in parsed[0]["unmapped"]
