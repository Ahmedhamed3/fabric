import json
import tempfile

from app.ocsf.constants import AUTHENTICATION_ACTIVITY_CLASS_UID, calc_type_uid
from app.plugins.windows_security.pipeline import convert_windows_security_file_to_ocsf_jsonl


def test_windows_security_4624_success_mapping():
    event = {
        "EventID": 4624,
        "TimeCreated": "2024-05-01T12:34:56.789Z",
        "EventData": {
            "TargetUserName": "alice",
            "TargetDomainName": "CONTOSO",
            "LogonType": "3",
            "IpAddress": "10.10.10.5",
            "WorkstationName": "WS-01",
        },
    }

    with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as tmp:
        tmp.write(json.dumps(event))
        tmp.write("\n")
        tmp.flush()
        tmp_path = tmp.name

    output_lines = list(convert_windows_security_file_to_ocsf_jsonl(tmp_path))
    assert len(output_lines) == 1

    parsed = json.loads(output_lines[0])
    expected_type_uid = calc_type_uid(AUTHENTICATION_ACTIVITY_CLASS_UID, 1)
    assert parsed["class_uid"] == AUTHENTICATION_ACTIVITY_CLASS_UID
    assert parsed["activity_id"] == 1
    assert parsed["type_uid"] == expected_type_uid
    assert parsed["metadata"]["product"] == "Windows Security"
    assert parsed["actor"]["user"]["name"] == "alice"
    assert parsed["actor"]["user"]["domain"] == "CONTOSO"
    assert parsed["src_endpoint"]["ip"] == "10.10.10.5"
    assert parsed["dst_endpoint"]["hostname"] == "WS-01"
    assert parsed["auth"]["result"] == "success"
    assert parsed["auth"]["logon_type"] == 3
    assert "original_event" in parsed["unmapped"]


def test_windows_security_4625_failure_mapping():
    event = {
        "EventID": 4625,
        "TimeCreated": "2024-05-01T12:35:56.789Z",
        "EventData": {
            "TargetUserName": "bob",
            "TargetDomainName": "CONTOSO",
            "LogonType": 2,
            "IpAddress": "10.10.10.8",
            "WorkstationName": "WS-02",
            "Status": "0xC000006D",
            "FailureReason": "Unknown user name or bad password.",
        },
    }

    with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as tmp:
        tmp.write(json.dumps(event))
        tmp.write("\n")
        tmp.flush()
        tmp_path = tmp.name

    output_lines = list(convert_windows_security_file_to_ocsf_jsonl(tmp_path))
    assert len(output_lines) == 1

    parsed = json.loads(output_lines[0])
    expected_type_uid = calc_type_uid(AUTHENTICATION_ACTIVITY_CLASS_UID, 2)
    assert parsed["class_uid"] == AUTHENTICATION_ACTIVITY_CLASS_UID
    assert parsed["activity_id"] == 2
    assert parsed["type_uid"] == expected_type_uid
    assert parsed["auth"]["result"] == "failure"
    assert parsed["auth"]["failure_reason"] == "Unknown user name or bad password."
    assert parsed["src_endpoint"]["ip"] == "10.10.10.8"


def test_windows_security_mixed_events_file():
    lines = [
        {
            "EventID": 4624,
            "TimeCreated": "2024-05-01T12:34:56.789Z",
            "EventData": {"TargetUserName": "alice", "LogonType": "3"},
        },
        {
            "EventID": 9999,
            "TimeCreated": "2024-05-01T12:36:56.789Z",
            "EventData": {"TargetUserName": "skip"},
        },
        {
            "EventID": 4625,
            "TimeCreated": "2024-05-01T12:37:56.789Z",
            "EventData": {"TargetUserName": "bob", "FailureReason": "Bad password"},
        },
    ]

    with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as tmp:
        for line in lines:
            tmp.write(json.dumps(line))
            tmp.write("\n")
        tmp.flush()
        tmp_path = tmp.name

    output_lines = list(convert_windows_security_file_to_ocsf_jsonl(tmp_path))
    assert len(output_lines) == 2

    parsed = [json.loads(line) for line in output_lines]
    assert {entry["activity_id"] for entry in parsed} == {1, 2}
